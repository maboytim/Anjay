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

#    include <inttypes.h>

#    define ANJAY_SERVERS_CONNECTION_SOURCE
#    define ANJAY_SERVERS_INTERNALS

#    include "anjay_connections_internal.h"
#    include "anjay_security.h"

VISIBILITY_SOURCE_BEGIN

int _anjay_connection_security_smstrigger_get_uri(anjay_t *anjay,
                                                  anjay_iid_t security_iid,
                                                  avs_url_t **out_uri) {
    /*
     * NOTE: This adds a "+" at the beginning because the resource is an MSISDN
     * as defined by 3GPP TS 23.003; see also:
     * https://github.com/OpenMobileAlliance/OMA_LwM2M_for_Developers/issues/148
     */
    static const char URI_PREFIX[] = "tel:+";
    static const size_t URI_PREFIX_LENGTH = sizeof(URI_PREFIX) - 1;
    char uri[21] = ""; // "tel:+" + MSISDN (max 15 digits) + "\0"
    const anjay_uri_path_t path =
            MAKE_RESOURCE_PATH(ANJAY_DM_OID_SECURITY, security_iid,
                               ANJAY_DM_RID_SECURITY_SMS_MSISDN);
    int result =
            _anjay_dm_read_resource_string(anjay, &path,
                                           uri + URI_PREFIX_LENGTH,
                                           sizeof(uri) - URI_PREFIX_LENGTH);
    if (!result && uri[URI_PREFIX_LENGTH]) {
        memcpy(uri, URI_PREFIX, URI_PREFIX_LENGTH);
        if (!(*out_uri = avs_url_parse_lenient(uri))) {
            result = -1;
        }
    }
    return result;
}

static int get_sms_security_mode(anjay_t *anjay,
                                 anjay_iid_t security_iid,
                                 anjay_sms_security_mode_t *out_mode) {
    int64_t mode;
    const anjay_uri_path_t path =
            MAKE_RESOURCE_PATH(ANJAY_DM_OID_SECURITY, security_iid,
                               ANJAY_DM_RID_SECURITY_SMS_MODE);

    if (_anjay_dm_read_resource_i64(anjay, &path, &mode)) {
        anjay_log(ERROR,
                  _("could not read LWM2M server SMS security mode from ") "%s",
                  ANJAY_DEBUG_MAKE_PATH(&path));
        return -1;
    }

    switch (mode) {
    case ANJAY_SMS_SECURITY_SECURE_PACKET:
        anjay_log(ERROR, _("unsupported SMS security mode: ") "%" PRId64, mode);
        return -1;
    case ANJAY_SMS_SECURITY_DTLS_PSK:
    case ANJAY_SMS_SECURITY_NOSEC:
        *out_mode = (anjay_sms_security_mode_t) mode;
        return 0;
    default:
        anjay_log(ERROR, _("invalid SMS security mode: ") "%" PRId64, mode);
        return -1;
    }
}

static int get_sms_dtls_keys(anjay_t *anjay,
                             anjay_iid_t security_iid,
                             anjay_sms_security_mode_t security_mode,
                             anjay_server_dtls_keys_t *out_keys) {
    if (security_mode == ANJAY_SMS_SECURITY_NOSEC) {
        return 0;
    }

    const struct {
        anjay_rid_t rid;
        char *buffer;
        size_t buffer_capacity;
        size_t *buffer_size_ptr;
    } values[] = {
        {
            /*
             * NOTE: This is a wild guess. The specification does not define
             * where the identity shall be stored for DTLS mode.
             *
             * This needs to be addressed once
             * https://github.com/OpenMobileAlliance/OMA_LwM2M_for_Developers/issues/149
             * is resolved.
             */
            .rid = ANJAY_DM_RID_SECURITY_SMS_KEY_PARAMETERS,
            .buffer = out_keys->pk_or_identity,
            .buffer_capacity = sizeof(out_keys->pk_or_identity),
            .buffer_size_ptr = &out_keys->pk_or_identity_size
        },
        {
            .rid = ANJAY_DM_RID_SECURITY_SMS_SECRET_KEY,
            .buffer = out_keys->secret_key,
            .buffer_capacity = sizeof(out_keys->secret_key),
            .buffer_size_ptr = &out_keys->secret_key_size
        }
    };

    for (size_t i = 0; i < AVS_ARRAY_SIZE(values); ++i) {
        const anjay_uri_path_t path =
                MAKE_RESOURCE_PATH(ANJAY_DM_OID_SECURITY, security_iid,
                                   values[i].rid);
        if (_anjay_dm_read_resource(anjay, &path, values[i].buffer,
                                    values[i].buffer_capacity,
                                    values[i].buffer_size_ptr)) {
            anjay_log(WARNING, _("read ") "%s" _(" failed"),
                      ANJAY_DEBUG_MAKE_PATH(&path));
            return -1;
        }
    }

    return 0;
}

static int init_sms_security(avs_net_security_info_t *security,
                             anjay_sms_security_mode_t sms_security_mode,
                             const anjay_server_dtls_keys_t *keys) {
    switch (sms_security_mode) {
    case ANJAY_SMS_SECURITY_NOSEC:
        return 0;
    case ANJAY_SMS_SECURITY_DTLS_PSK:
        return _anjay_connection_init_psk_security(security, keys);
    case ANJAY_SMS_SECURITY_SECURE_PACKET:
    default:
        anjay_log(ERROR, _("unsupported SMS security mode: ") "%d",
                  (int) sms_security_mode);
        return -1;
    }
}

typedef struct {
    anjay_security_config_t security_config;
    anjay_server_dtls_keys_t dtls_keys;
} security_config_with_keys_t;

anjay_security_config_t *_anjay_connection_security_smstrigger_get_config(
        anjay_t *anjay, anjay_connection_info_t *inout_info) {
    anjay_sms_security_mode_t sms_security_mode;
    security_config_with_keys_t *result =
            (security_config_with_keys_t *) avs_calloc(
                    1, sizeof(security_config_with_keys_t));
    const char *path = NULL;
    if (!result) {
        anjay_log(ERROR, _("out of memory"));
        return NULL;
    }

    if (get_sms_security_mode(anjay, inout_info->security_iid,
                              &sms_security_mode)
            || get_sms_dtls_keys(anjay, inout_info->security_iid,
                                 sms_security_mode, &result->dtls_keys)
            || init_sms_security(&result->security_config.security_info,
                                 sms_security_mode, &result->dtls_keys)) {
        goto error;
    }
    inout_info->is_encrypted = (sms_security_mode != ANJAY_SMS_SECURITY_NOSEC);
    result->security_config.tls_ciphersuites = anjay->default_tls_ciphersuites;
    if (inout_info->uri) {
        path = avs_url_path(inout_info->uri);
    }
    anjay_log(DEBUG,
              _("server ") "/%u/%u" _(": ") "%s" _(
                      ", SMS security mode = ") "%d",
              ANJAY_DM_OID_SECURITY, inout_info->security_iid, path ? path : "",
              (int) sms_security_mode);
    AVS_STATIC_ASSERT(offsetof(security_config_with_keys_t, security_config)
                              == 0,
                      security_config_pointers_castable);
    return &result->security_config;
error:
    avs_free(result);
    return NULL;
}

#endif // ANJAY_WITH_SMS
