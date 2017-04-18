//
// Created by Cody Baker on 4/4/17.
//

#include "gtest/gtest.h"
#include "../tls.h"
#include <stdio.h>
#include <event2/buffer.h>
#include <string.h>

/**
 * Quick and dirty, blocking read a file into an evbuffer.
 * @param path - Path to the file we want to read.
 * @return
 */
struct evbuffer *
load_file_to_evbuffer(const char *path) {
    FILE *f = fopen(path, "rb");
    if(!f) {
        return NULL;
    }
    unsigned char buffer[1024];
    size_t bytes_read;
    struct evbuffer *out = evbuffer_new();
    while((bytes_read = fread(&buffer, 1, 1024, f)) > 0) {
        evbuffer_add(out, buffer, bytes_read);
    }
    fclose(f);
    return out;
}

TEST(tls, snip_tls_get_next_record_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06, 'H', 'e', 'l',
            'l', 'o', '\0'
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add(test_data_buf, test_data, sizeof(test_data));
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, NULL, &record);
    EXPECT_EQ(state, snip_parser_state_parsed);
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
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, NULL, &record);
    EXPECT_EQ(state, snip_parser_state_more_data_needed);
}

TEST(tls, snip_tls_get_next_record_header_no_data_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add(test_data_buf, test_data, sizeof(test_data));
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, NULL, &record);
    EXPECT_EQ(state, snip_parser_state_more_data_needed);
}

TEST(tls, snip_tls_get_next_record_header_some_data_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06, 'H'
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add(test_data_buf, test_data, sizeof(test_data));
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, NULL, &record);
    EXPECT_EQ(state, snip_parser_state_more_data_needed);
}

TEST(tls, snip_tls_get_next_record_header_multiple_buffers_test) {
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06, 'H'
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add_reference(test_data_buf, test_data, sizeof(test_data), NULL, NULL);
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, NULL, &record);
    EXPECT_EQ(state, snip_parser_state_more_data_needed);
    unsigned char test_data_rest[] = {
            'e', 'l', 'l', 'o', '\0'
    };
    evbuffer_add_reference(test_data_buf, test_data_rest, sizeof(test_data_rest), NULL, NULL);
    state = snip_tls_get_next_record(test_data_buf, NULL, &record);
    EXPECT_EQ(state, snip_parser_state_parsed);
    EXPECT_STREQ((const char *) record.fragment, "Hello");
    EXPECT_EQ(record.length, 6);
    EXPECT_EQ(record.version.major, 3);
    EXPECT_EQ(record.version.minor, 2);
    EXPECT_EQ(record.content_type, SNIP_TLS_RECORD_TYPE_HANDSHAKE);
}

TEST(tls, snip_tls_get_next_record_header_multiple_records_test) {
    // Recycle the snip_tls_get_next_record_header_multiple_buffers_test setup because we also want to make sure we
    // pullup with reference to the offset.
    size_t offset = 0;
    unsigned char test_data[] = {
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x02, 0x00, 0x06, 'H'
    };
    struct evbuffer *test_data_buf = evbuffer_new();
    evbuffer_add_reference(test_data_buf, test_data, sizeof(test_data), NULL, NULL);
    snip_tls_record_t record;
    snip_parser_state_t state = snip_tls_get_next_record(test_data_buf, &offset, &record);
    EXPECT_EQ(state, snip_parser_state_more_data_needed);
    unsigned char test_data_rest[] = {
            'e', 'l', 'l', 'o', '\0',
            SNIP_TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x06, 'W', 'o', 'r', 'l', 'd', '\0'
    };
    evbuffer_add_reference(test_data_buf, test_data_rest, sizeof(test_data_rest), NULL, NULL);
    state = snip_tls_get_next_record(test_data_buf, &offset, &record);
    EXPECT_EQ(state, snip_parser_state_parsed);
    EXPECT_STREQ((const char *) record.fragment, "Hello");
    EXPECT_EQ(record.length, 6);
    EXPECT_EQ(record.version.major, 3);
    EXPECT_EQ(record.version.minor, 2);
    EXPECT_EQ(record.content_type, SNIP_TLS_RECORD_TYPE_HANDSHAKE);
    state = snip_tls_get_next_record(test_data_buf, &offset, &record);
    EXPECT_EQ(state, snip_parser_state_parsed);
    EXPECT_STREQ((const char *) record.fragment, "World");
    EXPECT_EQ(record.length, 6);
    EXPECT_EQ(record.version.major, 3);
    EXPECT_EQ(record.version.minor, 3);
    EXPECT_EQ(record.content_type, SNIP_TLS_RECORD_TYPE_HANDSHAKE);

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

TEST(tls, snip_tls_handshake_parse_test) {
    struct evbuffer *test_data = load_file_to_evbuffer(
            SNIP_TEST_CAPTURES "/osx_10.12.3_safari_10.0.3_12602.4.8_client_hello.raw");
    EXPECT_NE(test_data, nullptr);
    snip_tls_handshake_message_t message;
    snip_tls_handshake_message_reset(&message);
    snip_tls_handshake_message_parser_context_t parser_context;
    snip_tls_handshake_message_parser_context_init(&parser_context);
    snip_tls_record_t record;
    snip_tls_record_reset(&record);
    size_t record_offset = 0;
    int records = 0;
    while(snip_tls_get_next_record(test_data, &record_offset, &record) == snip_parser_state_parsed) {
        records += 1;
        size_t fragment_offset = 0;
        snip_parser_state_t message_state = snip_tls_handshake_message_parser_add_record(
                &parser_context, &message, &record, &fragment_offset);
        EXPECT_EQ(message_state, snip_parser_state_parsed);
        EXPECT_EQ(message.type, snip_tls_handshake_message_type_client_hello);
    }
    EXPECT_EQ(records, 1);
}

/**
 * This test builds a handshake mesage, byte by byte with single-byte records.  Then it validates the record was built
 * correctly.
 */
TEST(tls, snip_tls_handshake_parse_multiple_records_test) {
    struct evbuffer *test_data = load_file_to_evbuffer(
    SNIP_TEST_CAPTURES "/osx_10.12.3_safari_10.0.3_12602.4.8_client_hello.raw");
    EXPECT_NE(test_data, nullptr);
    snip_tls_handshake_message_t message;
    snip_tls_handshake_message_reset(&message);
    snip_tls_handshake_message_parser_context_t parser_context;
    snip_tls_handshake_message_parser_context_init(&parser_context);
    snip_tls_record_t record;
    snip_tls_record_reset(&record);
    size_t record_offset = 0;
    int records = 0;
    while(snip_tls_get_next_record(test_data, &record_offset, &record) == snip_parser_state_parsed) {
        records += 1;
        size_t fragment_offset = 0;
        snip_parser_state_t message_state = snip_tls_handshake_message_parser_add_record(
                &parser_context, &message, &record, &fragment_offset);
        EXPECT_EQ(message_state, snip_parser_state_parsed);
        EXPECT_EQ(message.type, snip_tls_handshake_message_type_client_hello);
    }
    EXPECT_EQ(records, 1);
    EXPECT_EQ(message.body[0], 3);
    EXPECT_EQ(message.body[1], 3);
    snip_tls_record_t short_record;
    snip_tls_record_reset(&short_record);
    const unsigned char *message_data = record.fragment;
    size_t message_data_bytes_remaining = record.length;
    snip_tls_handshake_message_t built_message;
    snip_tls_handshake_message_reset(&built_message);
    snip_tls_handshake_message_parser_context_t built_message_parser_context;
    snip_tls_handshake_message_parser_context_init(&built_message_parser_context);
    // Build a message with single-byte records.
    records = 0;
    while(message_data_bytes_remaining) {
        snip_tls_record_reset(&short_record);
        short_record.length = 1;
        short_record.fragment = message_data;
        message_data += 1;
        message_data_bytes_remaining -= 1;
        records += 1;
        short_record.content_type = SNIP_TLS_RECORD_TYPE_HANDSHAKE;
        short_record.version = SNIP_TLS_MAX_KNOWN_VERSION_OBJECT;
        size_t fragment_offset = 0;
        snip_parser_state_t built_message_state = snip_tls_handshake_message_parser_add_record(
                &built_message_parser_context, &built_message, &short_record, &fragment_offset);
        // fragment_offset should always be 1. It's seto to the number of bytes read from the record.
        EXPECT_EQ(fragment_offset, 1);
        EXPECT_EQ(short_record.fragment + fragment_offset, message_data);
        /* fprintf(stderr,
                "message_data_bytes_remaining: %lu - %s(%d)\n",
                message_data_bytes_remaining,
                built_message_state == snip_parser_state_more_data_needed ?
                "snip_parser_state_more_data_needed" : "snip_parser_state_parsed",
                built_message_state
        ); */
        if(message_data_bytes_remaining) {
            EXPECT_EQ(built_message_state, snip_parser_state_more_data_needed);
        }
        else {
            EXPECT_EQ(built_message_state, snip_parser_state_parsed);
            break;
        }
    }
    EXPECT_EQ(message.length, built_message.length);
    EXPECT_EQ(message.type, message.type);
    EXPECT_TRUE(!memcmp(message.body, built_message.body, message.length));
}

TEST(tls, snip_tls_handshake_client_hello_parse_test) {
    struct evbuffer *test_data = load_file_to_evbuffer(
            SNIP_TEST_CAPTURES "/osx_10.12.3_safari_10.0.3_12602.4.8_client_hello.raw");
    EXPECT_NE(test_data, nullptr);
    snip_tls_handshake_message_t message;
    snip_tls_handshake_message_reset(&message);
    snip_tls_handshake_message_parser_context_t parser_context;
    snip_tls_handshake_message_parser_context_init(&parser_context);
    snip_tls_record_t record;
    snip_tls_record_reset(&record);
    size_t record_offset = 0;
    int records = 0;
    while(snip_tls_get_next_record(test_data, &record_offset, &record) == snip_parser_state_parsed) {
        records += 1;
        size_t fragment_offset = 0;
        snip_parser_state_t message_state = snip_tls_handshake_message_parser_add_record(
                &parser_context, &message, &record, &fragment_offset);
        EXPECT_EQ(message_state, snip_parser_state_parsed);
        EXPECT_EQ(message.type, snip_tls_handshake_message_type_client_hello);
    }
    EXPECT_EQ(records, 1);
    snip_tls_client_hello_t client_hello;
    snip_tls_client_hello_reset(&client_hello);
    snip_parser_state_e client_hello_state = snip_tls_client_hello_parser(&message, &client_hello);
    EXPECT_EQ(client_hello_state, snip_parser_state_parsed);
    EXPECT_EQ(client_hello.client_version.major, 3);
    EXPECT_EQ(client_hello.client_version.minor, 3);
    const unsigned char *sni_hostname;
    size_t sni_hostname_size;
    snip_parser_state_t server_name_state = snip_tls_client_hello_find_server_name(
            &client_hello,
            snip_tls_client_hello_server_name_type_hostname,
            &sni_hostname,
            &sni_hostname_size
    );
    EXPECT_EQ(server_name_state, snip_parser_state_parsed);
    EXPECT_EQ(strlen( (const char *) sni_hostname), sni_hostname_size);
    EXPECT_STREQ("localhost", (const char *) sni_hostname);

}