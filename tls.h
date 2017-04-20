// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#ifndef SNIP_TLS_H
#define SNIP_TLS_H

#include <stdint.h>
#include <stdio.h>
#include <event2/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * We use this state as the return value for various parsers.  Not all parsers use all states.
 */
typedef enum snip_parser_state_e {
    /**
     * The requested data can not be parsed because the source data is invalid or in an otherwise unexpected state.
     */
            snip_parser_state_error = 0,
    /**
     * Used by stream parsers to indicate they have not yet received enough data to complete the parse.  Add more data
     * and execute again.
     */
            snip_parser_state_more_data_needed,
    /**
     * The parse was successful and the structured data should be available. Refer to specific parser docs regarding
     * data lifecycle.
     */
            snip_parser_state_parsed,
    /**
     * Used to indicate a non-error, null state.  For example, a 0 length record, the end of a non-streaming list, or
     * a negative result for constrained parse.
     */
            snip_parser_state_not_found
} snip_parser_state_t;

typedef enum snip_encoder_state_e {
    snip_encoder_state_success = 0,
} snip_encoder_state_t;

typedef enum snip_tls_record_type_e {
    snip_tls_record_type_change_cipher_spec = 20,
    snip_tls_record_type_alert = 21,
    snip_tls_record_type_handshake = 22,
    snip_tls_record_type_application_data = 23
} snip_tls_record_type_t;

typedef enum snip_tls_alert_description_e {
    snip_tls_alert_description_close_notify = 0,
    snip_tls_alert_description_handshake_failure = 40,
    snip_tls_alert_description_access_denied = 49,
    snip_tls_alert_description_decode_error = 50,
    snip_tls_alert_description_protocol_version = 70,
    snip_tls_alert_description_internal_error = 80,
    snip_tls_alert_description_no_renegotiation = 100,
    snip_tls_alert_description_unrecognized_name = 112
} snip_tls_alert_description_t;

typedef enum snip_tls_alert_level_e {
    snip_tls_alert_level_warning = 1,
    snip_tls_alert_level_fatal = 2
} snip_tls_alert_level_t;

typedef struct snip_tls_version_s {
    uint8_t major;
    uint8_t minor;
} snip_tls_version_t;

//
typedef struct snip_tls_record_s {
    snip_tls_record_type_t content_type;
    snip_tls_version_t version;
    uint16_t length;
    const unsigned char *fragment;
} snip_tls_record_t;

typedef enum snip_tls_handshake_message_type_e {
    snip_tls_handshake_message_type_client_hello = 0x01,
    snip_tls_handshake_message_type_server_hello = 0x02
} snip_tls_handshake_message_type_t;

typedef struct snip_tls_handshake_message_s {
    snip_tls_handshake_message_type_t type;
    size_t length;
    const unsigned char *body;
} snip_tls_handshake_message_t;


typedef struct snip_tls_random_s {
    uint32_t gmt_unix_time;
    uint8_t random_bytes[28];
} snip_tls_random_t;

typedef struct snip_tls_client_hello_s {
    snip_tls_version_t client_version;
    snip_tls_random_t random;

    uint8_t session_id_length;
    const unsigned char *session_id;

    uint16_t cipher_suite_length;
    const unsigned char *cipher_suites_data;

    uint8_t compression_methods_length;
    const unsigned char *compression_methods_data;

    uint16_t extensions_data_length;
    const unsigned char *extensions_data;
} snip_tls_client_hello_t;

typedef struct snip_tls_alert_s {
    snip_tls_alert_level_t level;
    snip_tls_alert_description_t description;
} snip_tls_alert_t;

typedef enum snip_tls_extension_type_e {
    snip_tls_extension_type_server_name = 0,
    snip_tls_extension_type_max_fragment_length = 1,
    snip_tls_extension_type_client_certificate_url = 2,
    snip_tls_extension_type_trusted_ca_keys = 3,
    snip_tls_extension_type_truncated_hmac = 4,
    snip_tls_extension_type_status_request = 5,
    snip_tls_extension_type_user_mapping = 6,
    snip_tls_extension_type_client_authz = 7,
    snip_tls_extension_type_server_authz = 8,
    snip_tls_extension_type_cert_type = 9,
    snip_tls_extension_type_supported_groups = 10,
    snip_tls_extension_type_ec_point_formats = 11,
    snip_tls_extension_type_srp = 12,
    snip_tls_extension_type_signature_algorithms = 13,
    snip_tls_extension_type_use_srtp = 14,
    snip_tls_extension_type_heartbeat = 15,
    snip_tls_extension_type_application_layer_protocol_negotiation = 16,
    snip_tls_extension_type_status_request_v2 = 17,
    snip_tls_extension_type_signed_certificate_timestamp = 18,
    snip_tls_extension_type_client_certificate_type = 19,
    snip_tls_extension_type_server_certificate_type = 20,
    snip_tls_extension_type_padding = 21,
    snip_tls_extension_type_encrypt_then_mac = 22,
    snip_tls_extension_type_extended_master_secret = 23,
    snip_tls_extension_type_cached_info = 25,

    snip_tls_extension_type_session_ticket_tls = 35,

    snip_tls_extension_type_key_share = 40,
    snip_tls_extension_type_pre_shared_key = 41,
    snip_tls_extension_type_early_data = 42,
    snip_tls_extension_type_supported_versions = 43,
    snip_tls_extension_type_cookie = 44,
    snip_tls_extension_type_psk_key_exchange_modes = 45,
    snip_tls_extension_type_certificate_authorities = 47,
    snip_tls_extension_type_oid_filters = 48,
    snip_tls_extension_type_renegotiation_info = 65281
} snip_tls_extension_type_t;

typedef struct snip_tls_extension_s {
    snip_tls_extension_type_t type;
    const unsigned char *data;
    size_t length;
} snip_tls_extension_t;

typedef enum snip_tls_client_hello_server_name_type_e {
    snip_tls_client_hello_server_name_type_hostname = 0
} snip_tls_client_hello_server_name_type_t;

#define SNIP_TLS_RECORD_TYPE_HANDSHAKE 0x16
#define SNIP_TLS_RECORD_HEADER_LENGTH 5

#define SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_LENGTH 1
#define SNIP_TLS_HANDSHAKE_LENGTH_SIZE 3
// Summarize the handshake message header length
#define SNIP_TLS_HANDSHAKE_HEADER_LENGTH (SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_LENGTH + SNIP_TLS_HANDSHAKE_LENGTH_SIZE)

#define SNIP_TLS_VERSION_LENGTH 2
#define SNIP_TLS_CLIENT_HELLO_RANDOM_LENGTH 32
#define SNIP_TLS_CLIENT_HELLO_SESSION_ID_LENGTH_SIZE 1
#define SNIP_TLS_CLIENT_HELLO_CIPHER_SUITE_LENGTH_SIZE 2
#define SNIP_TLS_CLIENT_HELLO_COMPRESSION_METHOD_LENGTH_SIZE 1
#define SNIP_TLS_EXTENSION_TYPE_LENGTH 2

#define SNIP_TLS_EXTENSIONS_SECTION_LENGTH_SIZE 2 /* This defines the length of the whole extensions section */

#define SNIP_TLS_EXTENSION_LENGTH_SIZE 2
#define SNIP_TLS_EXTENSION_HEADER_LENGTH (SNIP_TLS_EXTENSION_LENGTH_SIZE + SNIP_TLS_EXTENSION_TYPE_LENGTH)

#define SNIP_TLS_EXTENSION_SERVER_NAME_LIST_LENGTH_SIZE 2

#define SNIP_TLS_EXTENSION_SERVER_NAME_TYPE_LENGTH 1

#define SNIP_TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME 0
#define SNIP_TLS_EXTENSION_SERVER_NAME_LENGTH_SIZE 2
#define SNIP_TLS_EXTENSION_SERVER_NAME_NAME_LENGTH_SIZE 2

#define SNIP_TLS_EXTENSION_VERSION_LENGTH_SIZE 1

#define SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_CLIENT_HELLO 0x01

#define SNIP_TLS_ALERT_LEVEL_LENGTH 1
#define SNIP_TLS_ALERT_DESCRIPTION_LENGTH 1
#define SNIP_TLS_ALERT_LENGTH (SNIP_TLS_ALERT_LEVEL_LENGTH + SNIP_TLS_ALERT_DESCRIPTION_LENGTH)

#define SNIP_TLS_MAX_KNOWN_VERSION {3,3};  // TLS 1.3
static const snip_tls_version_t SNIP_TLS_MAX_KNOWN_VERSION_OBJECT = SNIP_TLS_MAX_KNOWN_VERSION;

/**
 * Compare two snip_tls_version_t objects.
 * @param A (snip_tls_version_t) - First snip_tls_version_t to compare.
 * @param OP (C comparison operator) - C comparison operator (ex. > >= < <= == !=)
 * @param B (snip_tls_version_t) - First snip_tls_version_t to compare.
 */
#define SNIP_TLS_COMPARE_TLS_VERSION(A, OP, B) ((A.major == B.major && A.minor OP B.minor) || \
    (A.major != B.major && A.major OP B.major))


/**
 * TLS Messages are built from multiple TLS records.  In the case where messages span across two or more TLS records we
 * have to build a buffer.  Publish this semi-publically so it can be incorporated into other snip structures.
 */
typedef struct snip_tls_handshake_message_parser_context_s {
    struct evbuffer *tls_message_buffer;
} snip_tls_handshake_message_parser_context_t;

/**
 * Reset the contents of a snip_tls_record to prepare for a new record.
 * @param record
 */
void
snip_tls_record_reset(snip_tls_record_t *record);

/**
 * Find the next TLS record in the provided buffer.
 * @param input[in/out] - libevent evbuffer record.
 * @param offset[in/out] - Offset in bytes from the start of the evbuffer. On a successful parse, we update this value
 *      to the start of the next record.
 * @param record[out] - A snip_tls_record object where we can store the info.  record->fragment is only valid until
 *      the next evbuffer operation.  Can be NULL to indicate no offset and we don't care about the start of the next
 *      record.
 * @return Status of the parse, see snip_parser_state_t.
 */
snip_parser_state_t
snip_tls_record_get_next(struct evbuffer *input, size_t *offset, snip_tls_record_t *record);

/**
 * Given a snip_tls_record object, encode it into the provided evbuffer.
 * @param output
 * @param record
 * @return
 */
snip_encoder_state_t
snip_tls_record_encode(struct evbuffer *output, snip_tls_record_t *record);

/**
 * Encode a TLS alert and add it to the output buffer.
 * @param out
 * @param alert
 * @param version
 * @return
 */
snip_encoder_state_t
snip_tls_alert_encode(struct evbuffer *out, snip_tls_alert_t *alert, const snip_tls_version_t *version);

/**
 * Initialize the state of the of a TLS Message parser (snip_tls_message_parser_context_t)
 * @param message_parser_context
 */
void
snip_tls_handshake_message_parser_context_init(snip_tls_handshake_message_parser_context_t *message_parser_context);

/**
 * Reset the state of the of a TLS Message parser (snip_tls_handshake_message_parser_context_t)
 * @param message_parser_context[in/out]
 */
void
snip_tls_handshake_message_parser_context_reset(snip_tls_handshake_message_parser_context_t *message_parser_context);

/**
 * Reset the contents of a snip_tls_handshake_message to prepare for a new message.
 * @param handshake_message
 */
void
snip_tls_handshake_message_reset(snip_tls_handshake_message_t *handshake_message);

/**
 * Add a TLS record to the parser, and potentially get a message in return.
 * @param message_parser_context[in/out]
 * @param record[in]
 * @param fragment_offset[in/out] - TLS records can contains multiple messages or incomplete messages.  We start looking
 *      for the next message in record->fragment at *fragment_offset.  When we successfully parse a message, we update
 *      fragment_offset. Can be NULL to indicate no offset and we don't care about the start of the next message. If we
 *      return snip_parser_state_complete and record->length < fragment_offset, you should run this function again with
 *      the same record and updated fragment_offset, another message fragment is in the trailing space.
 * @return Status of the parse, see snip_parser_state_t.
 */
snip_parser_state_t
snip_tls_handshake_message_parser_add_record(
        snip_tls_handshake_message_parser_context_t *message_parser_context,
        snip_tls_handshake_message_t *message,
        snip_tls_record_t *record,
        size_t *fragment_offset
);

/**
 * Reset a snip_tls_client_hello_t to a fresh state to begin a new parse.
 * @param client_hello
 */
void
snip_tls_client_hello_reset(snip_tls_client_hello_t *client_hello);

/**
 * Parse a ClientHello handshake message from bytes to a snip_tls_client_hello_t object.
 * @param message[in] - The source handshake message.
 * @param client_hello[in/out] - The target client_hello struct where we will store the parsed data.
 * @return
 */
snip_parser_state_t
snip_tls_client_hello_parser(snip_tls_handshake_message_t *message, snip_tls_client_hello_t *client_hello);

/**
 * Retrieve the next extension from a TLS ClientHello message.
 * @param client_hello[in] - Parsed TLS ClientHello message.
 * @param extension_offset[in/out] - Our current position in the Extensions section of the ClientHello message.
 * @param extension[in/out] - The structure where we store results.
 * @return
 */
snip_parser_state_t
snip_tls_client_hello_get_next_extension(snip_tls_client_hello_t *client_hello,
                                         size_t *extension_offset,
                                         snip_tls_extension_t *extension
);

/**
 * Find a ClientHello extension segment by extension id.
 * @param client_hello - The parsed ClientHello record.
 * @param type - The extension id we're looking to find.  See snip_tls_extension_type_t for known types.
 * @param extension - The extension object where we should store the results.
 * @return - snip_parser_state_not_found if the specified type isn't found, snip_parser_state_error for an error, and
 *      snip_parser_state_parsed if we found the extension.
 */
snip_parser_state_t
snip_tls_client_hello_find_extension(snip_tls_client_hello_t *client_hello,
                                     snip_tls_extension_type_t type,
                                     snip_tls_extension_t *extension
);

/**
 * Retrieve a string copy of the server_name value in the ClientHello Handshake.
 *
 * @warning - This function allocates a new string. The user is responsible for free()'ing it.
 *
 * @param client_hello[in]
 * @param name_type[in] - The TLS standard allows for multiple name types, however currently only HostName (0x00
 *      snip_tls_client_hello_server_name_type_hostname) is in use.
 * @param dest_ptr[out] - Location where we can store a reference to the string. Set NULL if no appropriate server_name
 *      is found.
 * @param dest_size[out] - Size of the string in bytes (excluding NULL terminator).
 * @return
 */
snip_parser_state_t
snip_tls_client_hello_find_server_name(snip_tls_client_hello_t *client_hello,
                                       snip_tls_client_hello_server_name_type_t name_type,
                                       const unsigned char **dest_ptr,
                                       size_t *dest_size
);

#ifdef __cplusplus
}
#endif

#endif //SNIP_TLS_H
