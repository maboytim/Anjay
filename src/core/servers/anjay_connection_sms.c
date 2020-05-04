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

#ifdef ANJAY_WITH_SMS

#    include <avsystem/commons/avs_utils.h>

#    include <inttypes.h>

#    include <avsystem/commons/avs_errno.h>

#    include "../sms/anjay_sms_socket.h"

#    define ANJAY_SERVERS_CONNECTION_SOURCE
#    define ANJAY_SERVERS_INTERNALS

#    include "anjay_connections_internal.h"

VISIBILITY_SOURCE_BEGIN

static const avs_net_dtls_handshake_timeouts_t *
get_sms_dtls_handshake_timeouts(anjay_t *anjay) {
    (void) anjay;
    static const avs_net_dtls_handshake_timeouts_t TIMEOUTS = {
        // see LwM2M Technical Specification 1.0, section 7.2.2.1.5
        .min = { 9, 0 },
        .max = { 60, 0 }
    };
    return &TIMEOUTS;
}

static avs_error_t
prepare_sms_connection(anjay_t *anjay,
                       anjay_server_connection_t *out_conn,
                       const avs_net_ssl_configuration_t *socket_config,
                       const anjay_connection_info_t *info) {
    if (!anjay->sms_router) {
        anjay_log(ERROR, _("SMS driver not present"));
        return avs_errno(AVS_EBADF);
    }

    avs_url_t *avs_url = NULL;
    if (info->transport_info
            && info->transport_info->transport == ANJAY_SOCKET_TRANSPORT_SMS) {
        // TODO: SMS binding with SMS trigger on a different number
        // currently won't work
        avs_url = info->uri;
    } else {
        if (_anjay_connection_security_smstrigger_get_uri(
                    anjay, info->security_iid, &avs_url)) {
            anjay_log(ERROR, _("Could not read SMS URI"));
            return avs_errno(AVS_EINVAL);
        }
    }

    avs_error_t err = AVS_OK;
    avs_net_socket_t *socket = NULL;
    assert(avs_url);
    assert(strcmp(avs_url_protocol(avs_url), ANJAY_SMS_URI_SCHEME) == 0);
    const char *path = avs_url_path(avs_url);
    const char *path_end;
    if (avs_url_host(avs_url) || avs_url_port(avs_url)) {
        anjay_log(ERROR,
                  _("SMS URI is not supposed to have host or port segments"));
        err = avs_errno(AVS_EINVAL);
        goto finish;
    }
    if (!path || !*path || *path == '/') {
        anjay_log(ERROR,
                  _("SMS URI is supposed to have the phone number right after "
                    "the scheme"));
        err = avs_errno(AVS_EINVAL);
        goto finish;
    }
    if (!(path_end = strpbrk(path, "/?"))) {
        path_end = path + strlen(path);
    }
    // tel:+1234567890 - phone number is actually in the first path segment;
    // move it to host
    if (path_end >= path + sizeof(out_conn->uri.host)) {
        anjay_log(ERROR, _("Phone number too long"));
        err = avs_errno(AVS_EINVAL);
        goto finish;
    }
    memcpy(out_conn->uri.host, path, (size_t) (path_end - path));
    out_conn->uri.host[path_end - path] = '\0';
    out_conn->uri.port[0] = '\0';
    assert(!out_conn->uri.uri_path);
    assert(!out_conn->uri.uri_query);
    if (_anjay_url_parse_path_and_query(path_end, &out_conn->uri.uri_path,
                                        &out_conn->uri.uri_query)) {
        anjay_log(ERROR, _("Could not copy URI path and query string"));
        err = avs_errno(AVS_ENOMEM);
        goto finish;
    }

    if (!(socket = _anjay_sms_socket_create(anjay->sms_router))) {
        anjay_log(ERROR, _("could not create SMS socket"));
        err = avs_errno(AVS_ENOMEM);
        goto finish;
    }
    if (info->is_encrypted) {
        if (avs_is_err((err = avs_net_dtls_socket_decorate_in_place(
                                &socket, socket_config)))) {
            _anjay_socket_cleanup(anjay, &socket);
            goto finish;
        }
        out_conn->stateful = true;
    } else {
        out_conn->stateful = false;
    }
    out_conn->conn_socket_ = socket;
finish:
    if (avs_url && avs_url != info->uri) {
        avs_url_free(avs_url);
    }
    return err;
}

static int ensure_udp_coap_context(anjay_t *anjay,
                                   anjay_server_connection_t *connection) {
    if (!connection->coap_ctx) {
        connection->coap_ctx = avs_coap_udp_ctx_create(
                anjay->sched, &anjay->sms_tx_params, anjay->in_shared_buffer,
                anjay->out_shared_buffer,
                NULL /* SMSes are reliable; no point in caching responses */,
                anjay->prng_ctx.ctx);
        if (!connection->coap_ctx) {
            anjay_log(ERROR, _("could not create CoAP/UDP context"));
            return -1;
        }
    }
    return 0;
}

static avs_error_t connect_sms_socket(anjay_t *anjay,
                                      anjay_server_connection_t *connection) {
    (void) anjay;
    avs_net_socket_t *socket =
            _anjay_connection_internal_get_socket(connection);
    avs_error_t err =
            avs_net_socket_connect(socket, connection->uri.host, NULL);
    if (avs_is_err(err)) {
        anjay_log(ERROR, _("could not connect to phone number ") "%s",
                  connection->uri.host);
        return err;
    }

    if (!avs_coap_ctx_has_socket(connection->coap_ctx)
            && avs_is_err((err = avs_coap_ctx_set_socket(connection->coap_ctx,
                                                         socket)))) {
        anjay_log(ERROR, _("could not assign socket to CoAP/UDP context"));
        return err;
    }

    return AVS_OK;
}

const anjay_connection_type_definition_t ANJAY_CONNECTION_DEF_SMS = {
    .name = "SMS",
    .get_dtls_handshake_timeouts = get_sms_dtls_handshake_timeouts,
    .prepare_connection = prepare_sms_connection,
    .ensure_coap_context = ensure_udp_coap_context,
    .connect_socket = connect_sms_socket
};

#endif // ANJAY_WITH_SMS
