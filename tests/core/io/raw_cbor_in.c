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

#define AVS_UNIT_ENABLE_SHORT_ASSERTS
#include <avsystem/commons/avs_unit_memstream.h>
#include <avsystem/commons/avs_unit_test.h>

static const anjay_uri_path_t TEST_RESOURCE_PATH =
        RESOURCE_PATH_INITIALIZER(12, 34, 56);

#define TEST_ENV(Data, Path)                                        \
    avs_stream_t *stream = NULL;                                    \
    ASSERT_OK(avs_unit_memstream_alloc(&stream, sizeof(Data) - 1)); \
    ASSERT_OK(avs_stream_write(stream, Data, sizeof(Data) - 1));    \
    anjay_input_ctx_t *in;                                          \
    ASSERT_OK(_anjay_input_cbor_create(&in, &stream, &(Path)));

#define TEST_TEARDOWN                             \
    do {                                          \
        ASSERT_OK(_anjay_input_ctx_destroy(&in)); \
        ASSERT_OK(avs_stream_cleanup(&stream));   \
    } while (0)

AVS_UNIT_TEST(raw_cbor_in, single_integer) {
    static const char RESOURCE[] = {
        "\x18\x2A" // unsigned(42)
    };
    TEST_ENV(RESOURCE, TEST_RESOURCE_PATH);

    anjay_uri_path_t path;
    ASSERT_OK(_anjay_input_get_path(in, &path, NULL));
    ASSERT_TRUE(_anjay_uri_path_equal(&path, &TEST_RESOURCE_PATH));

    int32_t value;
    ASSERT_OK(anjay_get_i32(in, &value));
    ASSERT_EQ(value, 42);

    ASSERT_OK(_anjay_input_next_entry(in));
    ASSERT_EQ(_anjay_input_get_path(in, NULL, NULL), ANJAY_GET_PATH_END);
    cbor_in_t *cbor_input_ctx = (cbor_in_t *) in;
    ASSERT_TRUE(cbor_input_ctx->msg_finished);
    ASSERT_EQ(_anjay_json_like_decoder_state(cbor_input_ctx->cbor_decoder),
              ANJAY_JSON_LIKE_DECODER_STATE_FINISHED);

    TEST_TEARDOWN;
}

AVS_UNIT_TEST(raw_cbor_in, too_short_buffer_for_string) {
    static const char RESOURCE[] = {
        "\x6C#ZostanWDomu" // text(12)
    };
    TEST_ENV(RESOURCE, TEST_RESOURCE_PATH);

    anjay_uri_path_t path;
    ASSERT_OK(_anjay_input_get_path(in, &path, NULL));
    ASSERT_TRUE(_anjay_uri_path_equal(&path, &TEST_RESOURCE_PATH));

    char too_short_buffer[8] = "SOMEDATA";
    ASSERT_EQ(anjay_get_string(in, too_short_buffer, sizeof(too_short_buffer)),
              ANJAY_BUFFER_TOO_SHORT);
    ASSERT_EQ_STR(too_short_buffer, "#Zostan");
    cbor_in_t *cbor_input_ctx = (cbor_in_t *) in;
    ASSERT_FALSE(cbor_input_ctx->msg_finished);
    ASSERT_EQ(_anjay_json_like_decoder_state(cbor_input_ctx->cbor_decoder),
              ANJAY_JSON_LIKE_DECODER_STATE_OK);
    ASSERT_OK(_anjay_input_get_path(in, NULL, NULL));

    ASSERT_OK(anjay_get_string(in, too_short_buffer, sizeof(too_short_buffer)));
    ASSERT_EQ_STR(too_short_buffer, "WDomu");
    ASSERT_TRUE(cbor_input_ctx->msg_finished);
    ASSERT_EQ(_anjay_json_like_decoder_state(cbor_input_ctx->cbor_decoder),
              ANJAY_JSON_LIKE_DECODER_STATE_FINISHED);
    ASSERT_EQ(_anjay_input_get_path(in, NULL, NULL), ANJAY_GET_PATH_END);

    TEST_TEARDOWN;
}

AVS_UNIT_TEST(raw_cbor_in, empty_string) {
    static const char RESOURCE[] = {
        "\x60" // text(0)
    };
    TEST_ENV(RESOURCE, TEST_RESOURCE_PATH);

    anjay_uri_path_t path;
    ASSERT_OK(_anjay_input_get_path(in, &path, NULL));
    ASSERT_TRUE(_anjay_uri_path_equal(&path, &TEST_RESOURCE_PATH));

    char buffer[8];
    ASSERT_OK(anjay_get_string(in, buffer, sizeof(buffer)));
    ASSERT_EQ_STR(buffer, "");
    cbor_in_t *cbor_input_ctx = (cbor_in_t *) in;
    ASSERT_TRUE(cbor_input_ctx->msg_finished);
    ASSERT_EQ(_anjay_json_like_decoder_state(cbor_input_ctx->cbor_decoder),
              ANJAY_JSON_LIKE_DECODER_STATE_FINISHED);
    ASSERT_EQ(_anjay_input_get_path(in, NULL, NULL), ANJAY_GET_PATH_END);

    TEST_TEARDOWN;
}
