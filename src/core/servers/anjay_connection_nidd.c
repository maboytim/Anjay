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

#ifdef ANJAY_WITH_NIDD

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_utils.h>

#    include <inttypes.h>

#    include "../nidd/anjay_nidd_socket.h"

#    define ANJAY_SERVERS_CONNECTION_SOURCE
#    define ANJAY_SERVERS_INTERNALS

#    include "anjay_connections_internal.h"

VISIBILITY_SOURCE_BEGIN

static const avs_net_dtls_handshake_timeouts_t *
get_nidd_dtls_handshake_timeouts(anjay_t *anjay) {
    (void) anjay;
    static const avs_net_dtls_handshake_timeouts_t TIMEOUTS = {
        // see LwM2M Technical Specification 1.0, section 7.2.2.1.5
        .min = { 9, 0 },
        .max = { 60, 0 }
    };
    return &TIMEOUTS;
}

static avs_error_t
prepare_nidd_connection(anjay_t *anjay,
                        anjay_server_connection_t *out_conn,
                        const avs_net_ssl_configuration_t *socket_config,
                        const anjay_connection_info_t *info) {
    (void) socket_config;
    (void) info;
    if (!anjay->nidd_driver) {
        anjay_log(ERROR, _("NIDD driver not present"));
        return avs_errno(AVS_EBADF);
    }

    const char *host = avs_url_host(info->uri);
    if (host && *host) {
        anjay_log(ERROR,
                  _("Non-empty hostname \"") "%s" _(
                          "\" not supported for NIDD"),
                  host);
        return avs_errno(AVS_EADDRNOTAVAIL);
    }

    if (_anjay_url_from_avs_url(info->uri, &out_conn->uri)) {
        return avs_errno(AVS_ENOMEM);
    }

    avs_net_socket_t *socket = _anjay_nidd_socket_create(anjay);
    if (!socket) {
        anjay_log(ERROR, _("could not create NIDD socket"));
        return avs_errno(AVS_ENOMEM);
    }
    out_conn->conn_socket_ = socket;

    return AVS_OK;
}

static int ensure_coap_context(anjay_t *anjay,
                               anjay_server_connection_t *connection) {
    if (!connection->coap_ctx) {
        connection->coap_ctx = avs_coap_udp_ctx_create(
                anjay->sched, &anjay->nidd_tx_params, anjay->in_shared_buffer,
                anjay->out_shared_buffer,
                NULL /* We are assuming NIDD transport is reliable */,
                anjay->prng_ctx.ctx);
        if (!connection->coap_ctx) {
            anjay_log(ERROR, _("could not create CoAP/NIDD context"));
            return -1;
        }
    }

    return 0;
}

static avs_error_t connect_nidd_socket(anjay_t *anjay,
                                       anjay_server_connection_t *connection) {
    (void) anjay;
    avs_net_socket_t *socket =
            _anjay_connection_internal_get_socket(connection);
    avs_error_t err = avs_net_socket_connect(socket, NULL, NULL);
    if (avs_is_err(err)) {
        anjay_log(ERROR, _("could not initialize NIDD connection"));
        return err;
    }

    if (!avs_coap_ctx_has_socket(connection->coap_ctx)
            && avs_is_err((err = avs_coap_ctx_set_socket(connection->coap_ctx,
                                                         socket)))) {
        anjay_log(ERROR, _("could not assign socket to CoAP/NIDD context"));
        return err;
    }
    return AVS_OK;
}

const anjay_connection_type_definition_t ANJAY_CONNECTION_DEF_NIDD = {
    .name = "NIDD",
    .get_dtls_handshake_timeouts = get_nidd_dtls_handshake_timeouts,
    .prepare_connection = prepare_nidd_connection,
    .ensure_coap_context = ensure_coap_context,
    .connect_socket = connect_nidd_socket
};

#endif // ANJAY_WITH_NIDD
