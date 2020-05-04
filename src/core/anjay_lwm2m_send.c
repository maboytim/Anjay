/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <anjay_init.h>

#ifdef ANJAY_WITH_LWM2M11

#    include <inttypes.h>

#    include <avsystem/commons/avs_stream_membuf.h>
#    include <avsystem/commons/avs_utils.h>

#    include <avsystem/coap/async_client.h>
#    include <avsystem/coap/code.h>

#    include <anjay/lwm2m_send.h>

#    include "anjay_access_utils.h"
#    include "anjay_core.h"
#    include "anjay_io_core.h"
#    include "anjay_servers_utils.h"
#    include "coap/anjay_content_format.h"
#    include "dm/anjay_query.h"
#    include "io/anjay_batch_builder.h"

VISIBILITY_SOURCE_BEGIN

#    define send_log(...) _anjay_log(anjay_send, __VA_ARGS__)

#    ifdef ANJAY_WITH_SEND

// Path for LwM2M Send requests defined by spec
#        define ANJAY_SEND_URI_PATH "dp"

static inline anjay_batch_builder_t *
cast_to_builder(anjay_send_batch_builder_t *builder) {
    return (anjay_batch_builder_t *) builder;
}

static inline anjay_send_batch_builder_t *
cast_to_send_builder(anjay_batch_builder_t *builder) {
    return (anjay_send_batch_builder_t *) builder;
}

static inline anjay_batch_t *cast_to_batch(anjay_send_batch_t *batch) {
    return (anjay_batch_t *) batch;
}

static inline anjay_send_batch_t *cast_to_send_batch(anjay_batch_t *batch) {
    return (anjay_send_batch_t *) batch;
}

static inline const anjay_batch_t *
cast_to_const_batch(const anjay_send_batch_t *batch) {
    return (const anjay_batch_t *) batch;
}

static inline const anjay_send_batch_t *
cast_to_const_send_batch(const anjay_batch_t *batch) {
    return (const anjay_send_batch_t *) batch;
}

typedef struct {
    avs_stream_t *memstream;
    anjay_output_ctx_t *out_ctx;
    size_t expected_offset;
    avs_time_real_t serialization_time;
    const anjay_batch_data_output_state_t *output_state;
} send_serialization_status_t;

typedef struct {
    anjay_t *anjay;
    anjay_send_finished_handler_t *finished_handler;
    void *finished_handler_data;
    anjay_ssid_t target_ssid;
    anjay_batch_t *payload_batch;
    send_serialization_status_t serialization_status;
} send_entry_t;

static void delete_send_entry(send_entry_t **entry) {
    _anjay_batch_release(&(*entry)->payload_batch);
    _anjay_output_ctx_destroy(&(*entry)->serialization_status.out_ctx);
    avs_stream_cleanup(&(*entry)->serialization_status.memstream);
    avs_free(*entry);
    *entry = NULL;
}

static avs_error_t setup_send_options(avs_coap_options_t *options,
                                      const anjay_url_t *server_uri,
                                      uint16_t content_format) {
    avs_error_t err;
    (void) (avs_is_err((err = _anjay_coap_add_string_options(
                                options, server_uri->uri_path,
                                AVS_COAP_OPTION_URI_PATH)))
            || avs_is_err((err = avs_coap_options_add_string(
                                   options, AVS_COAP_OPTION_URI_PATH,
                                   ANJAY_SEND_URI_PATH)))
            || avs_is_err((err = avs_coap_options_set_content_format(
                                   options, content_format)))
            || avs_is_err((err = _anjay_coap_add_string_options(
                                   options, server_uri->uri_query,
                                   AVS_COAP_OPTION_URI_QUERY))));
    return err;
}

static int request_payload_writer(size_t payload_offset,
                                  void *payload_buf,
                                  size_t payload_buf_size,
                                  size_t *out_payload_chunk_size,
                                  void *entry_) {
    send_entry_t *entry = (send_entry_t *) entry_;
    if (payload_offset != entry->serialization_status.expected_offset) {
        send_log(DEBUG,
                 _("Server requested unexpected chunk of payload (expected "
                   "offset ") "%zu" _(", got ") "%zu" _(")"),
                 entry->serialization_status.expected_offset, payload_offset);
        return -1;
    }

    char *write_ptr = (char *) payload_buf;
    const char *end_ptr = write_ptr + payload_buf_size;
    while (true) {
        size_t bytes_read;
        if (avs_is_err(avs_stream_read(entry->serialization_status.memstream,
                                       &bytes_read, NULL, write_ptr,
                                       (size_t) (end_ptr - write_ptr)))) {
            return -1;
        }
        write_ptr += bytes_read;

        // NOTE: (output_state == NULL && out_ctx != NULL) means start of
        // iteration; out_ctx is cleaned up at the end of iteration, so
        // (output_state == NULL && out_ctx == NULL) means end of iteration
        if (write_ptr >= end_ptr || !entry->serialization_status.out_ctx) {
            break;
        }
        int result = _anjay_batch_data_output_entry(
                entry->anjay, entry->payload_batch, entry->target_ssid,
                entry->serialization_status.serialization_time,
                &entry->serialization_status.output_state,
                entry->serialization_status.out_ctx);
        if (!result && !entry->serialization_status.output_state) {
            result = _anjay_output_ctx_destroy_and_process_result(
                    &entry->serialization_status.out_ctx, result);
        }
        if (result) {
            return result;
        }
    }
    *out_payload_chunk_size = (size_t) (write_ptr - (char *) payload_buf);
    entry->serialization_status.expected_offset += *out_payload_chunk_size;
    return 0;
}

static void response_handler(avs_coap_ctx_t *ctx,
                             avs_coap_exchange_id_t exchange_id,
                             avs_coap_client_request_state_t state,
                             const avs_coap_client_async_response_t *response,
                             avs_error_t err,
                             void *entry_) {
    (void) ctx;
    (void) exchange_id;
    (void) err;
    send_entry_t *entry = (send_entry_t *) entry_;
    assert(entry);
    if (entry->finished_handler) {
        static const int STATE_TO_RESULT[] = {
            [AVS_COAP_CLIENT_REQUEST_OK] = ANJAY_SEND_SUCCESS,
            [AVS_COAP_CLIENT_REQUEST_PARTIAL_CONTENT] = ANJAY_SEND_SUCCESS,
            [AVS_COAP_CLIENT_REQUEST_FAIL] = ANJAY_SEND_TIMEOUT,
            [AVS_COAP_CLIENT_REQUEST_CANCEL] = ANJAY_SEND_ABORT
        };
        assert(state >= 0 && state < AVS_ARRAY_SIZE(STATE_TO_RESULT));
        int result = STATE_TO_RESULT[state];
        if (result == ANJAY_SEND_SUCCESS) {
            if (response->header.code != AVS_COAP_CODE_CHANGED) {
                result = -response->header.code;
            } else if (response->payload_size) {
                send_log(WARNING,
                         _("Unexpected payload received in response to Send"));
            }
        }
        entry->finished_handler(entry->anjay, entry->target_ssid,
                                cast_to_const_send_batch(entry->payload_batch),
                                result, entry->finished_handler_data);
        // Prevent finished_handler from being called again if we're dealing
        // with AVS_COAP_CLIENT_REQUEST_PARTIAL_CONTENT.
        entry->finished_handler = NULL;
    }
    if (state == AVS_COAP_CLIENT_REQUEST_PARTIAL_CONTENT) {
        // We don't want/need to read the rest of the content, so we cancel the
        // exchange. Note that this will call this handler again with state set
        // to AVS_COAP_CLIENT_REQUEST_CANCEL.
        avs_coap_exchange_cancel(ctx, exchange_id);
    } else {
        delete_send_entry(&entry);
    }
}

static int start_send_exchange(anjay_t *anjay,
                               anjay_connection_ref_t connection,
                               uint16_t content_format,
                               anjay_send_finished_handler_t *finished_handler,
                               void *finished_handler_data,
                               const anjay_send_batch_t *batch) {
    assert(connection.server);
    assert(connection.conn_type != ANJAY_CONNECTION_UNSET);
    avs_coap_ctx_t *coap = _anjay_connection_get_coap(connection);
    if (!coap) {
        return -1;
    }

    send_entry_t *entry = (send_entry_t *) avs_calloc(1, sizeof(send_entry_t));
    if (!entry) {
        send_log(ERROR, _("out of memory"));
        return -1;
    }
    entry->anjay = anjay;
    entry->finished_handler = finished_handler;
    entry->finished_handler_data = finished_handler_data;
    entry->target_ssid = _anjay_server_ssid(connection.server);
    entry->payload_batch = _anjay_batch_acquire(cast_to_const_batch(batch));

    const anjay_url_t *server_uri = _anjay_connection_uri(connection);
    assert(server_uri);

    avs_coap_request_header_t request = {
        .code = AVS_COAP_CODE_POST
    };

    avs_error_t err;
    if (avs_is_err((err = avs_coap_options_dynamic_init(&request.options)))
            || avs_is_err(
                       (err = setup_send_options(&request.options, server_uri,
                                                 content_format)))) {
        goto finish;
    }

    if (!(entry->serialization_status.memstream = avs_stream_membuf_create())
            || !(entry->serialization_status.out_ctx =
                         _anjay_output_senml_like_create(
                                 entry->serialization_status.memstream,
                                 &MAKE_ROOT_PATH(), content_format))) {
        send_log(ERROR, _("out of memory"));
        goto finish;
    }
    entry->serialization_status.serialization_time = avs_time_real_now();
    err = avs_coap_client_send_async_request(coap, NULL, &request,
                                             request_payload_writer, entry,
                                             response_handler, entry);
finish:
    avs_coap_options_cleanup(&request.options);
    if (avs_is_err(err)) {
        delete_send_entry(&entry);
        return -1;
    }
    return 0;
}

anjay_send_result_t anjay_send(anjay_t *anjay,
                               anjay_ssid_t ssid,
                               const anjay_send_batch_t *data,
                               anjay_send_finished_handler_t *finished_handler,
                               void *finished_handler_data) {
    anjay_iid_t server_iid;
    if (_anjay_find_server_iid(anjay, ssid, &server_iid)) {
        return ANJAY_SEND_ERR_SSID;
    }

    bool is_lwm2m_send_muted;
    if (_anjay_dm_read_resource_bool(
                anjay,
                &MAKE_RESOURCE_PATH(ANJAY_DM_OID_SERVER,
                                    server_iid,
                                    ANJAY_DM_RID_SERVER_MUTE_SEND),
                &is_lwm2m_send_muted)) {
        return ANJAY_SEND_ERR_INTERNAL;
    }
    if (is_lwm2m_send_muted) {
        return ANJAY_SEND_ERR_MUTED;
    }

    if (anjay_is_offline(anjay)) {
        send_log(DEBUG,
                 _("Cannot perform LwM2M Send when Anjay is in offline mode"));
        return ANJAY_SEND_ERR_OFFLINE;
    }

    if (_anjay_bootstrap_in_progress(anjay)) {
        send_log(DEBUG, _("Cannot perform LwM2M Send during bootstrap"));
        return ANJAY_SEND_ERR_BOOTSTRAP;
    }

    const anjay_connection_ref_t connection =
            _anjay_servers_find_active_primary_connection(anjay, ssid);
    if (!connection.server) {
        send_log(DEBUG,
                 _("SSID ") "%u" _(
                         " does not belong to a known non-Bootstrap server or "
                         "the server is currently disabled"),
                 ssid);
        return ANJAY_SEND_ERR_SSID;
    }

    if (_anjay_server_registration_info(connection.server)->lwm2m_version
            < ANJAY_LWM2M_VERSION_1_1) {
        send_log(
                DEBUG,
                _("Server SSID ") "%u" _(
                        " is registered with LwM2M version ") "%s" _(", which "
                                                                     "does not "
                                                                     "support "
                                                                     "Send"),
                ssid,
                _anjay_lwm2m_version_as_string(
                        _anjay_server_registration_info(connection.server)
                                ->lwm2m_version));
        return ANJAY_SEND_ERR_PROTOCOL;
    }

    uint16_t content_format = _anjay_default_hierarchical_format(
            _anjay_server_registration_info(connection.server)->lwm2m_version);
    if (start_send_exchange(anjay, connection, content_format, finished_handler,
                            finished_handler_data, data)) {

        return ANJAY_SEND_ERR_INTERNAL;
    }
    return ANJAY_SEND_OK;
}

anjay_send_batch_builder_t *anjay_send_batch_builder_new(void) {
    return cast_to_send_builder(_anjay_batch_builder_new());
}

void anjay_send_batch_builder_cleanup(
        anjay_send_batch_builder_t **builder_ptr) {
    anjay_batch_builder_t *builder = cast_to_builder(*builder_ptr);
    _anjay_batch_builder_cleanup(&builder);
    assert(!builder);
    *builder_ptr = NULL;
}

int anjay_send_batch_add_int(anjay_send_batch_builder_t *builder,
                             anjay_oid_t oid,
                             anjay_iid_t iid,
                             anjay_rid_t rid,
                             anjay_riid_t riid,
                             avs_time_real_t timestamp,
                             int64_t value) {
    return _anjay_batch_add_int(cast_to_builder(builder),
                                &MAKE_RESOURCE_INSTANCE_PATH(oid, iid, rid,
                                                             riid),
                                timestamp, value);
}

int anjay_send_batch_add_uint(anjay_send_batch_builder_t *builder,
                              anjay_oid_t oid,
                              anjay_iid_t iid,
                              anjay_rid_t rid,
                              anjay_riid_t riid,
                              avs_time_real_t timestamp,
                              uint64_t value) {
    return _anjay_batch_add_uint(cast_to_builder(builder),
                                 &MAKE_RESOURCE_INSTANCE_PATH(oid, iid, rid,
                                                              riid),
                                 timestamp, value);
}

int anjay_send_batch_add_double(anjay_send_batch_builder_t *builder,
                                anjay_oid_t oid,
                                anjay_iid_t iid,
                                anjay_rid_t rid,
                                anjay_riid_t riid,
                                avs_time_real_t timestamp,
                                double value) {
    return _anjay_batch_add_double(cast_to_builder(builder),
                                   &MAKE_RESOURCE_INSTANCE_PATH(oid, iid, rid,
                                                                riid),
                                   timestamp, value);
}

int anjay_send_batch_add_bool(anjay_send_batch_builder_t *builder,
                              anjay_oid_t oid,
                              anjay_iid_t iid,
                              anjay_rid_t rid,
                              anjay_riid_t riid,
                              avs_time_real_t timestamp,
                              bool value) {
    return _anjay_batch_add_bool(cast_to_builder(builder),
                                 &MAKE_RESOURCE_INSTANCE_PATH(oid, iid, rid,
                                                              riid),
                                 timestamp, value);
}

int anjay_send_batch_add_string(anjay_send_batch_builder_t *builder,
                                anjay_oid_t oid,
                                anjay_iid_t iid,
                                anjay_rid_t rid,
                                anjay_riid_t riid,
                                avs_time_real_t timestamp,
                                const char *str) {
    return _anjay_batch_add_string(
            cast_to_builder(builder),
            &MAKE_RESOURCE_INSTANCE_PATH(oid, iid, rid, riid), timestamp, str);
}

int anjay_send_batch_add_bytes(anjay_send_batch_builder_t *builder,
                               anjay_oid_t oid,
                               anjay_iid_t iid,
                               anjay_rid_t rid,
                               anjay_riid_t riid,
                               avs_time_real_t timestamp,
                               const void *data,
                               size_t length) {
    return _anjay_batch_add_bytes(cast_to_builder(builder),
                                  &MAKE_RESOURCE_INSTANCE_PATH(oid, iid, rid,
                                                               riid),
                                  timestamp, data, length);
}

int anjay_send_batch_add_objlnk(anjay_send_batch_builder_t *builder,
                                anjay_oid_t oid,
                                anjay_iid_t iid,
                                anjay_rid_t rid,
                                anjay_riid_t riid,
                                avs_time_real_t timestamp,
                                anjay_oid_t objlnk_oid,
                                anjay_iid_t objlnk_iid) {
    return _anjay_batch_add_objlnk(cast_to_builder(builder),
                                   &MAKE_RESOURCE_INSTANCE_PATH(oid, iid, rid,
                                                                riid),
                                   timestamp, objlnk_oid, objlnk_iid);
}

int anjay_send_batch_data_add_current(anjay_send_batch_builder_t *builder,
                                      anjay_t *anjay,
                                      anjay_oid_t oid,
                                      anjay_iid_t iid,
                                      anjay_rid_t rid) {
    assert(builder);
    assert(anjay);
    assert(oid != ANJAY_ID_INVALID);
    assert(iid != ANJAY_ID_INVALID);
    assert(rid != ANJAY_ID_INVALID);

    const anjay_dm_object_def_t *const *obj =
            _anjay_dm_find_object_by_oid(anjay, oid);
    if (!obj) {
        send_log(ERROR, _("unregistered Object ID: ") "%u", oid);
        return -1;
    }
    anjay_dm_path_info_t path_info;
    int result =
            _anjay_dm_path_info(anjay, obj, &MAKE_RESOURCE_PATH(oid, iid, rid),
                                &path_info);
    if (result) {
        return result;
    }
    return _anjay_dm_read_into_batch(cast_to_builder(builder), anjay, obj,
                                     &path_info, ANJAY_SSID_BOOTSTRAP);
}

anjay_send_batch_t *
anjay_send_batch_builder_compile(anjay_send_batch_builder_t **builder_ptr) {
    anjay_batch_builder_t *builder = cast_to_builder(*builder_ptr);
    anjay_send_batch_t *result =
            cast_to_send_batch(_anjay_batch_builder_compile(&builder));
    *builder_ptr = cast_to_send_builder(builder);
    return result;
}

anjay_send_batch_t *anjay_send_batch_acquire(const anjay_send_batch_t *batch) {
    return cast_to_send_batch(_anjay_batch_acquire(cast_to_const_batch(batch)));
}

void anjay_send_batch_release(anjay_send_batch_t **batch_ptr) {
    anjay_batch_t *batch = cast_to_batch(*batch_ptr);
    _anjay_batch_release(&batch);
    assert(!batch);
    *batch_ptr = NULL;
}

#    else // ANJAY_WITH_SEND

anjay_send_result_t anjay_send(anjay_t *anjay,
                               anjay_ssid_t ssid,
                               const anjay_send_batch_t *data,
                               anjay_send_finished_handler_t *finished_handler,
                               void *finished_handler_data) {
    (void) anjay;
    (void) ssid;
    (void) data;
    (void) finished_handler;
    (void) finished_handler_data;
    send_log(ERROR,
             _("LwM2M Send operation is disabled. You are using non-commercial "
               "version of Anjay or Anjay has been compiled without "
               "ANJAY_WITH_SEND option."));
    return ANJAY_SEND_ERR_UNSUPPORTED;
}

#    endif // ANJAY_WITH_SEND

#endif // ANJAY_WITH_LWM2M11
