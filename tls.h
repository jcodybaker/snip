//
// Created by Cody Baker on 3/18/17.
//

#ifndef SNIPROXY_TLS_H
#define SNIPROXY_TLS_H

#include <stdint.h>

struct snip_TLS_version {
    uint8_t major;
    uint8_t minor;
};

//
//struct snip_TLS_record {
//    uint8_t content_type;
//    struct snip_TLS_version version;
//    uint16_t length; /* this will be unaligned and cause headaches */
//    uint8_t fragment[16384];
//};
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



#endif //SNIPROXY_TLS_H
