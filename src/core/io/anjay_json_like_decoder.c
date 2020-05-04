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

#if defined(ANJAY_WITH_CBOR) || defined(ANJAY_WITH_SENML_JSON)

#    include "anjay_json_like_decoder_vtable.h"

VISIBILITY_SOURCE_BEGIN

struct anjay_json_like_decoder_struct {
    const anjay_json_like_decoder_vtable_t *vtable;
};

void _anjay_json_like_decoder_delete(anjay_json_like_decoder_t **ctx) {
    if (ctx && *ctx) {
        assert((*ctx)->vtable);
        assert((*ctx)->vtable->cleanup);
        (*ctx)->vtable->cleanup(ctx);
        assert(!*ctx);
    }
}

anjay_json_like_decoder_state_t
_anjay_json_like_decoder_state(const anjay_json_like_decoder_t *ctx) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->state);
    return ctx->vtable->state(ctx);
}

int _anjay_json_like_decoder_current_value_type(
        anjay_json_like_decoder_t *ctx,
        anjay_json_like_value_type_t *out_type) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->current_value_type);
    return ctx->vtable->current_value_type(ctx, out_type);
}

int _anjay_json_like_decoder_bool(anjay_json_like_decoder_t *ctx,
                                  bool *out_value) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->read_bool);
    return ctx->vtable->read_bool(ctx, out_value);
}

int _anjay_json_like_decoder_number(anjay_json_like_decoder_t *ctx,
                                    anjay_json_like_number_t *out_value) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->number);
    return ctx->vtable->number(ctx, out_value);
}

int _anjay_json_like_decoder_bytes(anjay_json_like_decoder_t *ctx,
                                   avs_stream_t *target_stream) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->bytes);
    return ctx->vtable->bytes(ctx, target_stream);
}

int _anjay_json_like_decoder_enter_array(anjay_json_like_decoder_t *ctx) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->enter_array);
    return ctx->vtable->enter_array(ctx);
}

int _anjay_json_like_decoder_enter_map(anjay_json_like_decoder_t *ctx) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->enter_map);
    return ctx->vtable->enter_map(ctx);
}

size_t _anjay_json_like_decoder_nesting_level(anjay_json_like_decoder_t *ctx) {
    assert(ctx && ctx->vtable);
    assert(ctx->vtable->nesting_level);
    return ctx->vtable->nesting_level(ctx);
}

#endif // defined(ANJAY_WITH_CBOR) || defined(ANJAY_WITH_SENML_JSON)
