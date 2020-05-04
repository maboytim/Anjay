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

#ifdef ANJAY_WITH_CORE_PERSISTENCE

#    include <avsystem/commons/avs_persistence.h>
#    include <avsystem/commons/avs_utils.h>

#    define ANJAY_SERVERS_INTERNALS

#    include "../anjay_servers_inactive.h"
#    include "anjay_activate.h"
#    include "anjay_server_connections.h"
#    include "anjay_servers_internal.h"

VISIBILITY_SOURCE_BEGIN

static AVS_LIST(anjay_server_info_t) separate_active_servers(anjay_t *anjay) {
    AVS_LIST(anjay_server_info_t) result = NULL;
    AVS_LIST(anjay_server_info_t) *tail_ptr = &result;
    AVS_LIST(anjay_server_info_t) *anjay_it = &anjay->servers->servers;
    while (*anjay_it) {
        if (_anjay_server_active(*anjay_it)) {
            AVS_LIST_INSERT(tail_ptr, AVS_LIST_DETACH(anjay_it));
            AVS_LIST_ADVANCE_PTR(&tail_ptr);
        } else {
            AVS_LIST_ADVANCE_PTR(&anjay_it);
        }
    }
    return result;
}

static void
remove_preexisting_servers(anjay_t *anjay,
                           AVS_LIST(anjay_server_info_t) *new_server_list_ptr) {
    assert(new_server_list_ptr);
    AVS_LIST(anjay_server_info_t) *anjay_it = &anjay->servers->servers;
    while (*anjay_it && *new_server_list_ptr) {
        if ((*anjay_it)->ssid < (*new_server_list_ptr)->ssid) {
            AVS_LIST_ADVANCE_PTR(&anjay_it);
        } else if ((*anjay_it)->ssid == (*new_server_list_ptr)->ssid) {
            // server already exists, destroy
            _anjay_server_cleanup(*new_server_list_ptr);
            AVS_LIST_DELETE(new_server_list_ptr);
        } else {
            AVS_LIST_ADVANCE_PTR(&new_server_list_ptr);
        }
    }
}

static void
reinsert_new_servers(anjay_t *anjay,
                     AVS_LIST(anjay_server_info_t) *new_server_list_ptr) {
    assert(new_server_list_ptr);
    AVS_LIST(anjay_server_info_t) *anjay_it = &anjay->servers->servers;
    while (*new_server_list_ptr) {
        while (*anjay_it && (*anjay_it)->ssid < (*new_server_list_ptr)->ssid) {
            AVS_LIST_ADVANCE_PTR(&anjay_it);
        }
        assert(!*anjay_it || (*anjay_it)->ssid > (*new_server_list_ptr)->ssid);
        AVS_LIST_INSERT(anjay_it, AVS_LIST_DETACH(new_server_list_ptr));
        AVS_LIST_ADVANCE_PTR(&anjay_it);
    }
}

static avs_error_t handle_data_with_null_at_end(avs_persistence_context_t *ctx,
                                                char *buf,
                                                size_t buf_size) {
    assert(buf_size <= UINT16_MAX);
    uint16_t size;
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        size = (uint16_t) buf_size;
        while (size > 0 && !buf[size - 1]) {
            --size;
        }
    }
    avs_error_t err = avs_persistence_u16(ctx, &size);
    if (avs_is_ok(err) && size > buf_size) {
        err = avs_errno(AVS_EBADMSG);
    }
    if (avs_is_ok(err)) {
        err = avs_persistence_bytes(ctx, buf, size);
    }
    if (avs_is_ok(err)
            && avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        memset(&buf[size], 0, buf_size - size);
    }
    return err;
}

static avs_error_t handle_endpoint_path(avs_persistence_context_t *ctx,
                                        AVS_LIST(void) *element_ptr_,
                                        void *unused) {
    (void) unused;
    AVS_LIST(const anjay_string_t) *element_ptr =
            (AVS_LIST(const anjay_string_t) *) (intptr_t) element_ptr_;

    uint16_t length16;
    AVS_STATIC_ASSERT(sizeof(size_t) > sizeof(uint16_t),
                      size_t_is_larger_than_16_bits);

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        size_t length = strlen((*element_ptr)->c_str);
        length16 = (uint16_t) length;
        if (length != length16) {
            anjay_log(ERROR, _("String too long to persist"));
            return avs_errno(AVS_EINVAL);
        }
    }

    avs_error_t err = avs_persistence_u16(ctx, &length16);
    if (avs_is_err(err)) {
        return err;
    }

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE
            && !(*element_ptr = (AVS_LIST(const anjay_string_t))
                         AVS_LIST_NEW_BUFFER((size_t) length16 + 1))) {
        anjay_log(ERROR, _("out of memory"));
        return avs_errno(AVS_ENOMEM);
    }

    return avs_persistence_bytes(ctx, (char *) (intptr_t) (*element_ptr)->c_str,
                                 length16);
}

static avs_error_t handle_update_params(avs_persistence_context_t *ctx,
                                        anjay_update_parameters_t *params) {
    avs_error_t err;
    (void) (avs_is_err((err = avs_persistence_i64(ctx, &params->lifetime_s)))
            || avs_is_err((err = avs_persistence_string(ctx, &params->dm)))
            || avs_is_err((err = avs_persistence_bytes(
                                   ctx, params->binding_mode,
                                   sizeof(params->binding_mode)))));
    return err;
}

static avs_error_t
handle_registration_info(avs_persistence_context_t *ctx,
                         anjay_registration_info_t *registration_info) {
    avs_error_t err;
    (void) (avs_is_err((err = avs_persistence_custom_allocated_list(
                                ctx,
                                (AVS_LIST(void) *) (intptr_t) &registration_info
                                        ->endpoint_path,
                                handle_endpoint_path, NULL, NULL)))
            || avs_is_err((err = avs_persistence_bool(
                                   ctx, &registration_info->queue_mode)))
            || avs_is_err((err = avs_persistence_i64(
                                   ctx,
                                   &registration_info->expire_time
                                            .since_real_epoch.seconds)))
            || avs_is_err((err = avs_persistence_i32(
                                   ctx,
                                   &registration_info->expire_time
                                            .since_real_epoch.nanoseconds)))
            || avs_is_err(
                       (err = handle_update_params(
                                ctx, &registration_info->last_update_params))));
    return err;
}

static avs_error_t handle_transport(avs_persistence_context_t *ctx,
                                    anjay_socket_transport_t *transport) {
    char letter;
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        const anjay_binding_info_t *info =
                _anjay_binding_info_by_transport(*transport);
        if (!info) {
            return avs_errno(AVS_EINVAL);
        }
        letter = info->letter;
    }

    AVS_STATIC_ASSERT(sizeof(char) == sizeof(uint8_t), char_is_sane);
    avs_error_t err = avs_persistence_u8(ctx, (uint8_t *) &letter);
    if (avs_is_err(err)) {
        return err;
    }

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        const anjay_binding_info_t *info =
                _anjay_binding_info_by_letter(letter);
        if (!info) {
            return avs_errno(AVS_EBADMSG);
        }
        *transport = info->transport;
    }

    return AVS_OK;
}

static avs_error_t handle_conn_nontransient_state(
        avs_persistence_context_t *ctx,
        anjay_server_connection_nontransient_state_t *state) {
    AVS_STATIC_ASSERT(sizeof(state->dtls_session_buffer) <= UINT16_MAX,
                      dtls_session_buffer_size_representable_as_u16);

    avs_error_t err;
    assert(state->last_local_port[sizeof(state->last_local_port) - 1] == '\0');
    (void) (avs_is_err((err = avs_persistence_u8(
                                ctx, &state->preferred_endpoint.size)))
            || avs_is_err((err = avs_persistence_bytes(
                                   ctx,
                                   state->preferred_endpoint.data.buf,
                                   state->preferred_endpoint.size)))
            || avs_is_err((err = handle_data_with_null_at_end(
                                   ctx,
                                   state->dtls_session_buffer,
                                   sizeof(state->dtls_session_buffer))))
            || avs_is_err((err = avs_persistence_bytes(
                                   ctx,
                                   state->last_local_port,
                                   sizeof(state->last_local_port) - 1))));
    return err;
}

static avs_error_t
handle_server(avs_persistence_context_t *ctx, void *server_, void *anjay_) {
    anjay_server_info_t *server = (anjay_server_info_t *) server_;
    anjay_server_connection_t *primary_connection =
            _anjay_connection_get(&server->connections,
                                  ANJAY_CONNECTION_PRIMARY);
    anjay_t *anjay = (anjay_t *) anjay_;
    avs_error_t err;
    if (avs_is_ok((err = avs_persistence_u16(ctx, &server->ssid)))
            && avs_is_ok((err = handle_registration_info(
                                  ctx, &server->registration_info)))
            && avs_is_ok((err = handle_transport(
                                  ctx, &primary_connection->transport)))) {
        if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
            server->anjay = anjay;
            server->last_used_security_iid = ANJAY_ID_INVALID;
            server->reactivate_time = avs_time_real_now();
            const char *binding_mode =
                    server->registration_info.last_update_params.binding_mode;

            _anjay_conn_session_token_reset(&primary_connection->session_token);
            server->registration_info.session_token =
                    primary_connection->session_token;

            if (_anjay_connection_ensure_coap_context(
                        server, ANJAY_CONNECTION_PRIMARY,
                        primary_connection->transport)) {
                return avs_errno(AVS_ENOMEM);
            }

#    ifdef ANJAY_WITH_SMS
            anjay_server_connection_t *trigger_connection =
                    _anjay_connection_get(&server->connections,
                                          ANJAY_CONNECTION_TRIGGER);
            _anjay_conn_session_token_reset(&trigger_connection->session_token);
            trigger_connection->transport = ANJAY_SOCKET_TRANSPORT_SMS;

            if (_anjay_connections_is_trigger_requested(binding_mode)
                    && primary_connection->transport
                                   != ANJAY_SOCKET_TRANSPORT_SMS
                    && _anjay_connection_ensure_coap_context(
                               server, ANJAY_CONNECTION_TRIGGER,
                               trigger_connection->transport)) {
                return avs_errno(AVS_ENOMEM);
            }
#    endif // ANJAY_WITH_SMS
        }
        anjay_connection_ref_t ref = {
            .server = server,
            .conn_type = ANJAY_CONNECTION_PRIMARY
        };
        err = handle_conn_nontransient_state(
                ctx, &_anjay_get_server_connection(ref)->nontransient_state);
    }
    return err;
}

avs_error_t _anjay_servers_persistence(anjay_t *anjay,
                                       avs_persistence_context_t *persistence) {
    AVS_LIST(anjay_server_info_t) persistent_servers = NULL;

    if (avs_persistence_direction(persistence) == AVS_PERSISTENCE_STORE) {
        persistent_servers = separate_active_servers(anjay);
    }

    avs_error_t err = avs_persistence_list(
            persistence, (AVS_LIST(void) *) &persistent_servers,
            sizeof(*persistent_servers), handle_server, anjay, NULL);

    if (avs_persistence_direction(persistence) == AVS_PERSISTENCE_STORE) {
        reinsert_new_servers(anjay, &persistent_servers);
    } else {
        remove_preexisting_servers(anjay, &persistent_servers);

        if (avs_is_ok(err)) {
            // Note: not scheduling servers reload. For anything to work, the
            // Security object needs to be registered. anjay_register_object()
            // will call anjay_notify_instances_changed(), which will indirectly
            // schedule reload_servers_sched_job().
            reinsert_new_servers(anjay, &persistent_servers);
        } else {
            // something went wrong, rollback
            AVS_LIST_CLEAR(&persistent_servers) {
                _anjay_server_cleanup(persistent_servers);
            }
        }
    }
    return err;
}

#endif // ANJAY_WITH_CORE_PERSISTENCE
