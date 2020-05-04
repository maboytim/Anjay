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

#ifndef ANJAY_IO_JSON_LIKE_DECODER_VTABLE_H
#define ANJAY_IO_JSON_LIKE_DECODER_VTABLE_H

#include "anjay_json_like_decoder.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef anjay_json_like_decoder_state_t
json_like_decoder_state_t(const anjay_json_like_decoder_t *ctx);

typedef int
json_like_decoder_current_value_type_t(anjay_json_like_decoder_t *ctx,
                                       anjay_json_like_value_type_t *out_type);

typedef int json_like_decoder_bool_t(anjay_json_like_decoder_t *ctx,
                                     bool *out_value);

typedef int json_like_decoder_number_t(anjay_json_like_decoder_t *ctx,
                                       anjay_json_like_number_t *out_value);

typedef int json_like_decoder_bytes_t(anjay_json_like_decoder_t *ctx,
                                      avs_stream_t *target_stream);

typedef int json_like_decoder_enter_array_t(anjay_json_like_decoder_t *ctx);

typedef int json_like_decoder_enter_map_t(anjay_json_like_decoder_t *ctx);

typedef size_t
json_like_decoder_nesting_level_t(anjay_json_like_decoder_t *ctx);

typedef void json_like_decoder_cleanup_t(anjay_json_like_decoder_t **ctx);

typedef struct {
    json_like_decoder_state_t *state;
    json_like_decoder_current_value_type_t *current_value_type;
    json_like_decoder_bool_t *read_bool;
    json_like_decoder_number_t *number;
    json_like_decoder_bytes_t *bytes;
    json_like_decoder_enter_array_t *enter_array;
    json_like_decoder_enter_map_t *enter_map;
    json_like_decoder_nesting_level_t *nesting_level;
    json_like_decoder_cleanup_t *cleanup;
} anjay_json_like_decoder_vtable_t;

VISIBILITY_PRIVATE_HEADER_END

#endif /* ANJAY_IO_JSON_LIKE_DECODER_VTABLE_H */
