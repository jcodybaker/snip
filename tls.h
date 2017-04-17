//
// Created by Cody Baker on 3/18/17.
//

#ifndef SNIP_TLS_H
#define SNIP_TLS_H

#include <stdint.h>
#include <stdio.h>
#include <event2/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct snip_tls_version_s {
    uint8_t major;
    uint8_t minor;
} snip_tls_version_t;

//
typedef struct snip_tls_record_s {
    uint8_t content_type;
    snip_tls_version_t version;
    uint16_t length;
    const unsigned char *fragment;
} snip_tls_record_t;


//
//struct snip_TLS_random {
//    uint32_t gmt_unix_time;
//    uint8_t random_bytes[28];
//};
//
//struct snip_TLS_client_hello {
//    struct snip_TLS_version client_version;
//    struct snip_TLS_random random;
//    uint32_t session_id[32];
//    uint16_t cipher_suite_length;
//    uint8_t *cipher_suites;
//    uint8_t *extensions;
//};
//

#define SNIP_TLS_RECORD_TYPE_HANDSHAKE 0x16
#define SNIP_TLS_RECORD_HEADER_LENGTH 5

#define SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_LENGTH 1
#define SNIP_TLS_HANDSHAKE_LENGTH_LENGTH 3
// Summarize the handshake message header length
#define SNIP_TLS_HANDSHAKE_HEADER_LENGTH SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_LENGTH + SNIP_TLS_HANDSHAKE_LENGTH_LENGTH

#define SNIP_TLS_CLIENT_HELLO_VERSION_LENGTH 2
#define SNIP_TLS_CLIENT_HELLO_RANDOM_LENGTH 32
#define SNIP_TLS_CLIENT_HELLO_SESSION_ID_LENGTH_LENGTH 1
#define SNIP_TLS_CLIENT_HELLO_CIPHER_SUITE_LENGTH_SIZE 2
#define SNIP_TLS_CLIENT_HELLO_COMPRESSION_METHOD_LENGTH_SIZE 1
#define SNIP_TLS_CLIENT_HELLO_EXTENSION_TYPE_LENGTH 2

#define SNIP_TLS_CLIENT_HELLO_EXTENSIONS_SECTION_LENGTH_LENGTH 2 /* This defines the length of the whole extensions section */

#define SNIP_TLS_CLIENT_HELLO_EXTENSION_LENGTH_LENGTH 2

#define SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_TYPE_LENGTH 1

#define SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_TYPE_HOST_NAME 0
#define SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_LENGTH_LENGTH 2
#define SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_NAME_LENGTH_LENGTH 2

#define SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_CLIENT_HELLO 0x01

#define SNIP_TLS_MAX_KNOWN_VERSION {3,3};  // TLS 1.3

/**
 * Compare two snip_tls_version_t objects.
 * @param A (snip_tls_version_t) - First snip_tls_version_t to compare.
 * @param OP (C comparison operator) - C comparison operator (ex. > >= < <= == !=)
 * @param B (snip_tls_version_t) - First snip_tls_version_t to compare.
 */
#define SNIP_TLS_COMPARE_TLS_VERSION(A, OP, B) ((A.major == B.major && A.minor OP B.minor) || \
    (A.major != B.major && A.major OP B.major))

/**
 * We use this state as the return value for various parsers.
 */
typedef enum snip_parser_state_e {
    snip_parser_state_error = 0,
    snip_parser_state_record_incomplete,
    snip_parser_state_record_parsed
} snip_parser_state_t;

/**
 * Find the next TLS record in the provided buffer.
 * @param input - libevent evbuffer record.
 * @param offset - Offset in bytes from the start of the evbuffer
 * @param record - A snip_tls_record object where we can store the info.
 * @return Status of the parse, see snip_parser_state_t.
 */
snip_parser_state_t
snip_tls_get_next_record(struct evbuffer *input, size_t offset, snip_tls_record_t *record);

#ifdef __cplusplus
}
#endif

#endif //SNIP_TLS_H
