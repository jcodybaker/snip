//
// Created by Cody Baker on 4/4/17.
//

#include "gtest/gtest.h"
#include "../tls.h"

TEST(tls, snip_tls_get_next_record_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06, 'H', 'e', 'l',
            'l', 'o', '\0'
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add(test_data_buf, test_data, sizeof(test_data));
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, 0, &record);
    EXPECT_EQ(state, snip_parser_state_record_parsed);
    EXPECT_STREQ((const char *) record.fragment, (const char *) test_data + SNIP_TLS_RECORD_HEADER_LENGTH);
    EXPECT_EQ(record.length, 6);
    EXPECT_EQ(record.version.major, 3);
    EXPECT_EQ(record.version.minor, 2);
    EXPECT_EQ(record.content_type, SNIP_TLS_RECORD_TYPE_HANDSHAKE);
}


TEST(tls, snip_tls_get_next_record_short_header_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00,
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add(test_data_buf, test_data, sizeof(test_data));
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, 0, &record);
    EXPECT_EQ(state, snip_parser_state_record_incomplete);
}

TEST(tls, snip_tls_get_next_record_header_no_data_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add(test_data_buf, test_data, sizeof(test_data));
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, 0, &record);
    EXPECT_EQ(state, snip_parser_state_record_incomplete);
}

TEST(tls, snip_tls_get_next_record_header_some_data_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06, 'H'
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add(test_data_buf, test_data, sizeof(test_data));
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, 0, &record);
    EXPECT_EQ(state, snip_parser_state_record_incomplete);
}

TEST(tls, snip_tls_compare_tls_version_test) {
    const snip_tls_version_t max_version = SNIP_TLS_MAX_KNOWN_VERSION;
    const snip_tls_version_t greater_major = {4, 0};
    const snip_tls_version_t greater_minor = {3, 4};
    EXPECT_TRUE(SNIP_TLS_COMPARE_TLS_VERSION(max_version, <=, greater_major));
    EXPECT_TRUE(SNIP_TLS_COMPARE_TLS_VERSION(max_version, <=, greater_minor));
    EXPECT_TRUE(SNIP_TLS_COMPARE_TLS_VERSION(max_version, ==, max_version));
    EXPECT_FALSE(SNIP_TLS_COMPARE_TLS_VERSION(max_version, ==, greater_major));
    EXPECT_FALSE(SNIP_TLS_COMPARE_TLS_VERSION(max_version, ==, greater_minor));
    EXPECT_FALSE(SNIP_TLS_COMPARE_TLS_VERSION(max_version, >=, greater_major));
    EXPECT_FALSE(SNIP_TLS_COMPARE_TLS_VERSION(max_version, >=, greater_minor));
}

