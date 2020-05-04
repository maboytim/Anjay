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

#    include <inttypes.h>
#    include <math.h>

#    include <avsystem/commons/avs_persistence.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    include <anjay_modules/anjay_time_defs.h>

#    include "../anjay_core.h"
#    include "../coap/anjay_content_format.h"
#    include "../dm/anjay_query.h"

#    define ANJAY_OBSERVE_SOURCE

#    include "../anjay_servers_inactive.h"

#    include "anjay_observe_internal.h"

VISIBILITY_SOURCE_BEGIN

static avs_error_t connection_ref_persistence(avs_persistence_context_t *ctx,
                                              anjay_t *anjay,
                                              anjay_connection_ref_t *ref) {
    avs_persistence_direction_t direction = avs_persistence_direction(ctx);

    avs_error_t err;

    uint16_t ssid;
    int8_t conn_type_i8 = 0;
    if (direction == AVS_PERSISTENCE_STORE) {
        ssid = _anjay_server_ssid(ref->server);
        conn_type_i8 = (int8_t) ref->conn_type;
        assert(ref->conn_type == conn_type_i8);
    }

    (void) (avs_is_err((err = avs_persistence_u16(ctx, &ssid)))
            || avs_is_err((err = avs_persistence_i8(ctx, &conn_type_i8))));

    if (avs_is_ok(err) && direction == AVS_PERSISTENCE_RESTORE) {
        if (!(ref->server = _anjay_servers_find(anjay, ssid))) {
            return avs_errno(AVS_EBADMSG);
        }
        ref->conn_type = (anjay_connection_type_t) conn_type_i8;
    }
    return err;
}

static avs_persistence_handler_custom_allocated_tree_element_t
        observation_persistence;
static avs_persistence_cleanup_collection_element_t observation_cleanup;

/* NOTE: this function leaves @p details in inconsistent state on failed
 * restore */
static avs_error_t
observe_msg_details_persistence(avs_persistence_context_t *ctx,
                                anjay_msg_details_t *details) {
    // these are never set for Notify messages
    assert(details->uri_path == NULL);
    assert(details->uri_query == NULL);
    assert(details->location_path == NULL);

    avs_error_t err;
    (void) (avs_is_err((err = avs_persistence_u8(ctx, &details->msg_code)))
            || avs_is_err((err = avs_persistence_u16(ctx, &details->format))));

    return err;
}

static avs_error_t observe_token_persistence(avs_persistence_context_t *ctx,
                                             avs_coap_token_t *token) {
    avs_coap_token_t copy = *token;
    avs_error_t err = avs_persistence_u8(ctx, &copy.size);
    if (avs_is_err(err)) {
        return err;
    }
    if (copy.size > sizeof(copy.bytes)) {
        return avs_errno(AVS_EBADMSG);
    }
    if (avs_is_ok((err = avs_persistence_bytes(ctx, &copy.bytes, copy.size)))) {
        *token = copy;
    }
    return err;
}

static avs_error_t observe_time_persistence(avs_persistence_context_t *ctx,
                                            avs_time_real_t *time) {
    avs_error_t err;
    avs_time_real_t copy = *time;

    (void) (avs_is_err((err = avs_persistence_i64(
                                ctx, &copy.since_real_epoch.seconds)))
            || avs_is_err((err = avs_persistence_i32(
                                   ctx, &copy.since_real_epoch.nanoseconds))));

    if (avs_is_ok(err)) {
        *time = copy;
    }
    return err;
}

static avs_error_t observe_path_persistence(avs_persistence_context_t *ctx,
                                            anjay_uri_path_t *path) {
    AVS_STATIC_ASSERT(
            AVS_ARRAY_SIZE(path->ids) == 4,
            path_size_is_4_change_would_require_persistent_data_version_bump);

    anjay_uri_path_t copy = *path;
    avs_error_t err = AVS_OK;
    for (size_t i = 0; avs_is_ok(err) && i < AVS_ARRAY_SIZE(path->ids); ++i) {
        err = avs_persistence_u16(ctx, &copy.ids[i]);
    }
    if (avs_is_ok(err)) {
        *path = copy;
    }

    return err;
}

static avs_error_t
observe_reliability_hint_persistence(avs_persistence_context_t *ctx,
                                     avs_coap_notify_reliability_hint_t *hint) {
    uint8_t mapped_value;
    switch (*hint) {
    case AVS_COAP_NOTIFY_PREFER_CONFIRMABLE:
        mapped_value = 'C';
        break;
    case AVS_COAP_NOTIFY_PREFER_NON_CONFIRMABLE:
        mapped_value = 'N';
        break;
    default:
        return avs_errno(AVS_EINVAL);
    }

    avs_error_t err = avs_persistence_u8(ctx, &mapped_value);
    if (avs_is_err(err)) {
        return err;
    }

    // If it was restore operation, we need to remap it back.
    switch (mapped_value) {
    case 'C':
        *hint = AVS_COAP_NOTIFY_PREFER_CONFIRMABLE;
        break;
    case 'N':
        *hint = AVS_COAP_NOTIFY_PREFER_NON_CONFIRMABLE;
        break;
    default:
        return avs_errno(AVS_EBADMSG);
    }
    return AVS_OK;
}

typedef struct {
    AVS_RBTREE_ELEM(anjay_observation_t) observation;
    AVS_RBTREE(anjay_observation_t) observations;
} observation_value_persistence_arg_t;

static avs_error_t observation_value_persistence(avs_persistence_context_t *ctx,
                                                 AVS_LIST(void) *element_ptr_,
                                                 void *arg_) {
    AVS_LIST(anjay_observation_value_t) *element_ptr =
            (AVS_LIST(anjay_observation_value_t) *) element_ptr_;
    const observation_value_persistence_arg_t *arg =
            (observation_value_persistence_arg_t *) arg_;
    assert(arg);
    // Exactly one of observation and observations must be set
    assert(!arg->observation == !!arg->observations);

    avs_persistence_direction_t direction = avs_persistence_direction(ctx);

    avs_coap_token_t token;
    anjay_msg_details_t details;
    avs_coap_notify_reliability_hint_t reliability_hint;
    if (direction == AVS_PERSISTENCE_STORE) {
        token = (*element_ptr)->ref->token;
        details = (*element_ptr)->details;
        reliability_hint = (*element_ptr)->reliability_hint;
        assert((*element_ptr)->ref->paths_count < UINT32_MAX);
    } else {
        memset(&token, 0, sizeof(token));
        memset(&details, 0, sizeof(details));
        memset(&reliability_hint, 0, sizeof(reliability_hint));
    }

    avs_error_t err;
    if (avs_is_err((err = observe_token_persistence(ctx, &token)))
            || avs_is_err(
                       (err = observe_msg_details_persistence(ctx, &details)))
            || avs_is_err((err = observe_reliability_hint_persistence(
                                   ctx, &reliability_hint)))) {
        return err;
    }

    anjay_observation_t *ref;
    if (direction == AVS_PERSISTENCE_RESTORE) {
        if (arg->observation) {
            ref = arg->observation;
            if (!avs_coap_token_equal(&token, &ref->token)) {
                anjay_log(WARNING,
                          _("malformed persisted value: unexpected "
                            "token ") "%s" _(", expected ") "%s",
                          ANJAY_TOKEN_TO_STRING(ref->token),
                          ANJAY_TOKEN_TO_STRING(token));
                return avs_errno(AVS_EBADMSG);
            }
        } else if (!(ref = AVS_RBTREE_FIND(arg->observations,
                                           _anjay_observation_query(&token)))) {
            anjay_log(WARNING,
                      _("malformed persisted value: no observe entry for "
                        "token ") "%s",
                      ANJAY_TOKEN_TO_STRING(token));
            return avs_errno(AVS_EBADMSG);
        }
    } else {
        ref = (*element_ptr)->ref;
    }

    const size_t paths_count =
            _anjay_observe_is_error_details(&details) ? 0 : ref->paths_count;

    if (direction == AVS_PERSISTENCE_RESTORE) {
        assert(!*element_ptr);
        if (!(*element_ptr =
                      (AVS_LIST(anjay_observation_value_t)) AVS_LIST_NEW_BUFFER(
                              offsetof(anjay_observation_value_t, values)
                              + paths_count * sizeof(anjay_batch_t *)))) {
            anjay_log(ERROR, _("out of memory"));
            return avs_errno(AVS_ENOMEM);
        }

        memcpy((void *) (intptr_t) (const void *) &(*element_ptr)->ref, &ref,
               sizeof(ref));
        (*element_ptr)->details = details;
    }

    err = observe_time_persistence(ctx, &(*element_ptr)->timestamp);
    for (size_t i = 0; avs_is_ok(err) && i < paths_count; ++i) {
        err = _anjay_batch_persistence(ctx, &(*element_ptr)->values[i]);
    }

    if (avs_is_ok(err)) {
        anjay_log(
                LAZY_TRACE,
                _("Observe value ") "%p" _(" ") "%sst" _("ored: token ") "%s" _(
                        ", timestamp: ") "%ld" _(".") "%09lds",
                (void *) *element_ptr,
                avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE ? ""
                                                                        : "re",
                ANJAY_TOKEN_TO_STRING(token),
                (long) (*element_ptr)->timestamp.since_real_epoch.seconds,
                (long) (*element_ptr)->timestamp.since_real_epoch.nanoseconds);
    }

    return err;
}

static void observation_value_cleanup(void *element_) {
    anjay_observation_value_t *element = (anjay_observation_value_t *) element_;
    if (element->ref && !_anjay_observe_is_error_details(&element->details)) {
        for (size_t i = 0; i < element->ref->paths_count; ++i) {
            if (element->values[i]) {
                _anjay_batch_release(&element->values[i]);
            }
        }
    }
}

static AVS_LIST(anjay_observation_value_t)
find_last_observation_value(AVS_LIST(anjay_observation_value_t) values,
                            anjay_observation_t *observation) {
    AVS_LIST(anjay_observation_value_t) last_matching = NULL;
    AVS_LIST(anjay_observation_value_t) it = NULL;
    AVS_LIST_FOREACH(it, values) {
        if (it->ref == observation) {
            last_matching = it;
        }
    }
    return last_matching;
}

static avs_error_t
rebuild_observed_paths(anjay_observe_connection_entry_t *conn) {
    if (!(conn->observed_paths = AVS_RBTREE_NEW(
                  anjay_observe_path_entry_t, _anjay_observe_path_entry_cmp))) {
        anjay_log(ERROR, _("out of memory"));
        return avs_errno(AVS_ENOMEM);
    }

    AVS_RBTREE_ELEM(anjay_observation_t) observation;
    AVS_RBTREE_FOREACH(observation, conn->observations) {
        if (_anjay_observe_add_to_observed_paths(conn, observation)) {
            AVS_RBTREE_DELETE(&conn->observed_paths) {
                AVS_LIST_CLEAR(&(*conn->observed_paths)->refs);
            }
            return avs_errno(AVS_ENOMEM);
        }
    }
    return AVS_OK;
}

static avs_error_t observe_connection_entry_persistence(
        avs_persistence_context_t *ctx, void *conn_, void *anjay_) {
    anjay_observe_connection_entry_t *conn =
            (anjay_observe_connection_entry_t *) conn_;
    anjay_t *anjay = (anjay_t *) anjay_;

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        if (!(conn->observations = AVS_RBTREE_NEW(anjay_observation_t,
                                                  _anjay_observation_cmp))) {
            anjay_log(ERROR, _("out of memory"));
            return avs_errno(AVS_ENOMEM);
        }
    }

    avs_error_t err;
    if (avs_is_err((
                err = connection_ref_persistence(
                        ctx, anjay,
                        (anjay_connection_ref_t *) (intptr_t) &conn->conn_ref)))
            || avs_is_err((err = avs_persistence_custom_allocated_tree(
                                   ctx,
                                   (AVS_RBTREE(void)) conn->observations,
                                   observation_persistence,
                                   (void *) (intptr_t) &conn->conn_ref,
                                   observation_cleanup)))
            || (anjay_log(TRACE,
                          _("storing unsent notifications list for "
                            "SSID ") "%" PRIu16 _(", connection type ") "%d",
                          _anjay_server_ssid(conn->conn_ref.server),
                          (int) conn->conn_ref.conn_type),
                false)
            || avs_is_err((err = avs_persistence_custom_allocated_list(
                                   ctx, (AVS_LIST(void) *) &conn->unsent,
                                   observation_value_persistence,
                                   &(observation_value_persistence_arg_t) {
                                       .observations = conn->observations
                                   },
                                   observation_value_cleanup)))) {
        return err;
    }

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        if (avs_is_err((err = rebuild_observed_paths(conn)))) {
            return err;
        }

        conn->unsent_last = AVS_LIST_TAIL(conn->unsent);

        /*
         * The sad thing about the data structures stored in
         * anjay_observe_state_t is that it contains a pointer cycle:
         *
         * anjay_observe_connection_entry_t contains (among others):
         * - a tree of anjay_observation_t, which contains:
         *   - a pointer to the last_unsent value from the list below,
         * - a list of unsent anjay_observation_value_t which contains:
         *   - a pointer to the anjay_observation_t the value belongs to.
         *
         * So, to restore anjay_observation_t::last_unsent, we need the list of
         * anjay_observation_value_t, and to restore
         * anjay_observation_value_t::ref we need the set of
         * anjay_observation_t.
         *
         * For that reason anjay_observation_t::last_unsent field for all
         * entries is filled in a separate step after restoring both structures.
         */
        AVS_RBTREE_ELEM(anjay_observation_t) observation = NULL;
        AVS_RBTREE_FOREACH(observation, conn->observations) {
            observation->last_unsent =
                    find_last_observation_value(conn->unsent, observation);
        }
    }

    return err;
}

static void observe_connection_entry_cleanup(void *entry_) {
    _anjay_observe_cleanup_connection(
            (anjay_observe_connection_entry_t *) entry_);
}

static avs_error_t
observe_persist_coap_state(avs_coap_ctx_t *coap,
                           const anjay_observation_t *entry,
                           avs_persistence_context_t *persistence) {
    return avs_coap_observe_persist(coap,
                                    (avs_coap_observe_id_t) {
                                        .token = entry->token
                                    },
                                    persistence);
}

static avs_error_t
observe_restore_coap_state(avs_coap_ctx_t *coap,
                           anjay_connection_ref_t ref,
                           avs_persistence_context_t *persistence) {
    anjay_connection_ref_t *heap_conn = (anjay_connection_ref_t *) avs_malloc(
            sizeof(anjay_connection_ref_t));
    if (!heap_conn) {
        return avs_errno(AVS_ENOMEM);
    }
    *heap_conn = ref;
    avs_error_t err =
            avs_coap_observe_restore(coap, _anjay_observe_cancel_handler,
                                     heap_conn, persistence);
    if (avs_is_err(err)) {
        avs_free(heap_conn);
    }
    return err;
}

static avs_error_t
observation_persistence(avs_persistence_context_t *ctx,
                        AVS_RBTREE_ELEM(void) *observation_ptr_,
                        void *conn_ptr) {
    AVS_RBTREE_ELEM(anjay_observation_t) *observation_ptr =
            (AVS_RBTREE_ELEM(anjay_observation_t) *) observation_ptr_;
    assert(observation_ptr);

    uint32_t paths_count;
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        paths_count = (uint32_t) (*observation_ptr)->paths_count;
        if (paths_count != (*observation_ptr)->paths_count
                || paths_count == UINT32_MAX) {
            anjay_log(ERROR,
                      _("Observation has too many paths to persist (") "%lu" _(
                              " is larger than or equal to ") "%" PRIu32 _(")"),
                      (unsigned long) (*observation_ptr)->paths_count,
                      UINT32_MAX);
            return avs_errno(AVS_EINVAL);
        }
    }

    avs_error_t err = avs_persistence_u32(ctx, &paths_count);
    if (avs_is_err(err)) {
        return err;
    }

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        assert(!*observation_ptr);
        if (paths_count != (size_t) paths_count) {
            anjay_log(
                    ERROR,
                    _("Observation has too many paths to restore (") "%" PRIu32
                            _(" is larger than ") "%llu" _(")"),
                    paths_count, (unsigned long long) SIZE_MAX);
            return avs_errno(AVS_EBADMSG);
        }
        if (!(*observation_ptr = (AVS_RBTREE_ELEM(anjay_observation_t))
                      AVS_RBTREE_ELEM_NEW_BUFFER(
                              offsetof(anjay_observation_t, paths)
                              + paths_count
                                        * sizeof(const anjay_uri_path_t)))) {
            anjay_log(ERROR, _("out of memory"));
            return avs_errno(AVS_ENOMEM);
        }
        memcpy((void *) (intptr_t) (const void *) &(*observation_ptr)
                       ->paths_count,
               &(const size_t[]) { paths_count }, sizeof(size_t));
    }

    if (avs_is_err((err = observe_token_persistence(
                            ctx,
                            (avs_coap_token_t *) (intptr_t)
                                    & (*observation_ptr)->token)))
            || avs_is_err(
                       (err = observe_time_persistence(
                                ctx, &(*observation_ptr)->last_confirmable)))) {
        return err;
    }

    anjay_log(LAZY_TRACE, _("storing sent notifications list for ") "%s",
              ANJAY_TOKEN_TO_STRING((*observation_ptr)->token));

    for (size_t i = 0; avs_is_ok(err) && i < (*observation_ptr)->paths_count;
         ++i) {
        (void) (avs_is_err((err = observe_path_persistence(
                                    ctx,
                                    (anjay_uri_path_t *) (intptr_t)
                                            & (*observation_ptr)->paths[i])))
                || avs_is_err((err = avs_persistence_custom_allocated_list(
                                       ctx,
                                       (AVS_LIST(void) *) &(*observation_ptr)
                                               ->last_sent,
                                       observation_value_persistence,
                                       &(observation_value_persistence_arg_t) {
                                           .observation = *observation_ptr,
                                       },
                                       observation_value_cleanup))));
    }
    if (avs_is_err(err)) {
        return err;
    }
    anjay_connection_ref_t connection_ref =
            *(anjay_connection_ref_t *) conn_ptr;
    avs_coap_ctx_t *coap = _anjay_connection_get_coap(connection_ref);
    if (!coap) {
        anjay_log(WARNING,
                  _("No CoAP connection associated with observe entry"));
        return avs_errno(AVS_EBADMSG);
    }
    switch (avs_persistence_direction(ctx)) {
    case AVS_PERSISTENCE_STORE:
        err = observe_persist_coap_state(coap, *observation_ptr, ctx);
        break;
    case AVS_PERSISTENCE_RESTORE:
        err = observe_restore_coap_state(coap, connection_ref, ctx);
        break;
    default:
        err = avs_errno(AVS_EBADMSG);
        break;
    }
    return err;
}

static void observation_cleanup(void *observation_) {
    anjay_observation_t *observation = (anjay_observation_t *) observation_;
    AVS_LIST_CLEAR(&observation->last_sent) {
        observation_value_cleanup(observation->last_sent);
    }
}

static avs_error_t reschedule_notifications(anjay_observe_state_t *observe) {
    avs_error_t err = AVS_OK;

    AVS_LIST(anjay_observe_connection_entry_t) conn = NULL;
    AVS_LIST_FOREACH(conn, observe->connection_entries) {
        AVS_RBTREE_ELEM(anjay_observation_t) observation = NULL;
        AVS_RBTREE_FOREACH(observation, conn->observations) {
            if (_anjay_observe_schedule_pmax_trigger(conn, observation)) {
                err = avs_errno(AVS_ENOMEM);
            }
        }
    }

    return err;
}

static avs_error_t observe_persistence(anjay_t *anjay,
                                       anjay_observe_state_t *observe,
                                       avs_persistence_context_t *ctx) {
    return avs_persistence_list(ctx,
                                (AVS_LIST(void) *) &observe->connection_entries,
                                sizeof(anjay_observe_connection_entry_t),
                                observe_connection_entry_persistence, anjay,
                                observe_connection_entry_cleanup);
}

avs_error_t _anjay_observe_persistence(anjay_t *anjay,
                                       avs_persistence_context_t *ctx) {
    anjay_observe_state_t persistent_observe;
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        persistent_observe = anjay->observe;
    } else {
        memset(&persistent_observe, 0, sizeof(persistent_observe));

        size_t limit = anjay->observe.notify_queue_limit;
        if (anjay->observe.notify_queue_limit_mode == NOTIFY_QUEUE_UNLIMITED) {
            limit = 0;
        }

        _anjay_observe_init(&persistent_observe,
                            anjay->observe.confirmable_notifications, limit);
    }

    avs_error_t err = observe_persistence(anjay, &persistent_observe, ctx);

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        if (avs_is_err(err)) {
            anjay_log(DEBUG, _("could not restore observation state: ") "%s",
                      AVS_COAP_STRERROR(err));
        }

        if (avs_is_ok(err)
                && avs_is_err((err = reschedule_notifications(
                                       &persistent_observe)))) {
            anjay_log(WARNING,
                      _("could not schedule notification tasks for some "
                        "observations"));
        }

        if (avs_is_ok(err)) {
            _anjay_observe_cleanup(&anjay->observe);
            anjay->observe = persistent_observe;
        } else {
            _anjay_observe_cleanup(&persistent_observe);
        }
    }
    return err;
}

#endif // ANJAY_WITH_CORE_PERSISTENCE
