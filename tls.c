// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#include "tls.h"
#include "compat.h"
#include <string.h>
#include <stdlib.h>

/**
 * Reset the contents of a snip_tls_record to prepare for a new record.
 * @param record
 */
void
snip_tls_record_reset(snip_tls_record_t *record) {
    memset(record, '\0', sizeof(snip_tls_record_t));
}

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
snip_tls_record_get_next(struct evbuffer *input, size_t *offset, snip_tls_record_t *record) {
    size_t zero_offset = 0;
    if(!offset) { // We allow this to be a NULL parameter, meaning no offset.
        offset = &zero_offset;
    }
    ssize_t available = evbuffer_get_length(input) - *offset;
    if(available < SNIP_TLS_RECORD_HEADER_LENGTH) {
        return snip_parser_state_more_data_needed;
    }
    unsigned char *buffer = evbuffer_pullup(input, (*offset) + SNIP_TLS_RECORD_HEADER_LENGTH) + (*offset);
    record->content_type = (snip_tls_record_type_t) buffer[0];
    record->version.major = buffer[1];
    record->version.minor = buffer[2];
    uint16_t network_order_size;
    memcpy(&network_order_size, buffer + 3, sizeof(uint16_t));
    record->length = ntohs(network_order_size);
    // Limited to 2^14 bytes.
    if(record->length & 0xC000) {
        return snip_parser_state_error;
    }
    if(available < SNIP_TLS_RECORD_HEADER_LENGTH + record->length) {
        return snip_parser_state_more_data_needed;
    }
    buffer = evbuffer_pullup(input, (*offset) + SNIP_TLS_RECORD_HEADER_LENGTH + record->length) + (*offset);
    record->fragment = buffer + SNIP_TLS_RECORD_HEADER_LENGTH;
    *offset += SNIP_TLS_RECORD_HEADER_LENGTH + record->length;
    return snip_parser_state_parsed;
}

/**
 * Initialize the state of the of a TLS Message parser (snip_tls_handshake_message_parser_context_t)
 * @param message_parser_context
 */
void
snip_tls_handshake_message_parser_context_init(snip_tls_handshake_message_parser_context_t *message_parser_context) {
    message_parser_context->tls_message_buffer = NULL;
}

/**
 * Reset the state of the of a TLS Message parser (snip_tls_handshake_message_parser_context_t)
 * @param message_parser_context
 */
void
snip_tls_handshake_message_parser_context_reset(snip_tls_handshake_message_parser_context_t *message_parser_context) {
    if(message_parser_context->tls_message_buffer) {
        evbuffer_free(message_parser_context->tls_message_buffer);
    }
}

/**
 * Reset the contents of a snip_tls_handshake_message to prepare for a new message.
 * @param handshake_message
 */
void
snip_tls_handshake_message_reset(snip_tls_handshake_message_t *handshake_message) {
    memset(handshake_message, '\0', sizeof(snip_tls_handshake_message_t));
}


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
) {
    size_t record_available = record->length + *fragment_offset;
    const unsigned char *record_data = record->fragment + *fragment_offset;
    if(!record_available) {
        // No new data.
        return snip_parser_state_more_data_needed;
    }
    size_t message_so_far = 0;
    if(message_parser_context->tls_message_buffer) {
        message_so_far = evbuffer_get_length(message_parser_context->tls_message_buffer);
    }
    const unsigned char *message_data;
    size_t message_available;
    if(message_so_far < SNIP_TLS_HANDSHAKE_HEADER_LENGTH) {
        // We need to finish the header.  It's still possible we don't have a full header.
        if(record_available + message_so_far < SNIP_TLS_HANDSHAKE_HEADER_LENGTH) {
            // We don't have a full header.  Save anything new, and ask for more data.
            if(!message_parser_context->tls_message_buffer) {
                message_parser_context->tls_message_buffer = evbuffer_new();
                evbuffer_expand(message_parser_context->tls_message_buffer, SNIP_TLS_HANDSHAKE_HEADER_LENGTH);
            }
            evbuffer_add(message_parser_context->tls_message_buffer, record_data, record_available);
            *fragment_offset += record_available;
            return snip_parser_state_more_data_needed;
        }
        // We have a full header.
        const unsigned char *header_data;
        if(message_parser_context->tls_message_buffer) {
            // Add only the header bits for now.  We don't know how long the rest of the message is.
            size_t message_to_add = MIN(record_available, SNIP_TLS_HANDSHAKE_HEADER_LENGTH - message_so_far);
            evbuffer_add(message_parser_context->tls_message_buffer,
                         record_data,
                         message_to_add
            );
            *fragment_offset += message_to_add;
            // Mark this data as consumed.
            // Get the data contiguous ofr parsing.
            message_data = record_data + message_to_add;
            message_available = record_available - message_to_add;
            header_data = evbuffer_pullup(message_parser_context->tls_message_buffer, SNIP_TLS_HANDSHAKE_HEADER_LENGTH);
        }
        else {
            *fragment_offset += SNIP_TLS_HANDSHAKE_HEADER_LENGTH;
            // This is the first piece of the message and at least the header is contiguous and complete in the record.
            header_data = record_data;
            message_data = record_data + SNIP_TLS_HANDSHAKE_HEADER_LENGTH;
            message_available = record_available - SNIP_TLS_HANDSHAKE_HEADER_LENGTH;
        }
        message->type = (snip_tls_handshake_message_type_t) header_data[0];
        uint32_t network_length;
        // This is actually 24 bits starting on the 2nd byte.  Copy all 32-bits, then 0 out the high-order byte because
        // its network order, leaving the lower 24bits, then convert them to the native endianess.
        memcpy(&network_length, header_data, sizeof(uint32_t));
        memset(&network_length, '\0', 1);
        message->length = ntohl(network_length);
        message_available = MIN(message_available, message->length);
        if(message_parser_context->tls_message_buffer) {
            // Let the evbuffer know how much data we have coming so we can avoid unnecessary allocations.
            evbuffer_expand(message_parser_context->tls_message_buffer,
                            SNIP_TLS_HANDSHAKE_HEADER_LENGTH + message->length);
        }
    }
    else {
        // We already have the header.  How much message body do we have in the buffer.
        message_available = MIN(record_available, message->length - (message_so_far - SNIP_TLS_HANDSHAKE_HEADER_LENGTH));
        message_data = record_data;
    }

    *fragment_offset += message_available;
    if(message_parser_context->tls_message_buffer) {
        // We already pulled some data for this message from another record.  We need to add this data to it.
        if(message_available) {
            evbuffer_add(message_parser_context->tls_message_buffer,
                         message_data,
                         message_available
            );
        }
        if(evbuffer_get_length(message_parser_context->tls_message_buffer) ==
                (message->length + SNIP_TLS_HANDSHAKE_HEADER_LENGTH))
        {
            // Prepare the buffer for use.  Skip the header bits.
            message->body = evbuffer_pullup(message_parser_context->tls_message_buffer, -1) +
                           SNIP_TLS_HANDSHAKE_HEADER_LENGTH;
            return snip_parser_state_parsed;
        }
        else {
            return snip_parser_state_more_data_needed;
        }
    }
    else {
        if(message_available < message->length) {
            message_parser_context->tls_message_buffer = evbuffer_new();
            evbuffer_expand(message_parser_context->tls_message_buffer,
                            message->length + SNIP_TLS_HANDSHAKE_HEADER_LENGTH);
            evbuffer_add(message_parser_context->tls_message_buffer, record_data, record_available);
            return snip_parser_state_more_data_needed;
        }
        message->body = message_data;
        return snip_parser_state_parsed;
    }
}

/**
 * Parse the Random section from a TLS 1.2 request into its constituent parts.
 * @param buffer[in] - Encoded buffer source for the Random segment.
 * @param buffer_length[in] - Total length of the buffer.
 * @param offset[in/out] - Current read position in the buffer. Updated to the current position after the parse is
 *      complete.  If you want this to always start 0, and don't care about offset, NULL is acceptable.
 * @param random[in/out] - Object to store.
 * @return
 */
snip_parser_state_t
snip_tls_random_parser(const unsigned char *buffer, size_t buffer_length, size_t *offset, snip_tls_random_t *random) {
    size_t zero = 0;
    if(!offset) {
        offset = &zero;
    }
    if(*offset + SNIP_TLS_CLIENT_HELLO_RANDOM_LENGTH > buffer_length) {
        return snip_parser_state_more_data_needed;
    }
    memcpy(&(random->gmt_unix_time), buffer + *offset, sizeof(random->gmt_unix_time));
    *offset += sizeof(random->gmt_unix_time);
    memcpy(&(random->random_bytes), buffer + *offset, sizeof(random->random_bytes));
    *offset += sizeof(random->random_bytes);
    return snip_parser_state_parsed;
}

/**
 * Reset a snip_tls_client_hello_t to a fresh state to begin a new parse.
 * @param client_hello
 */
void
snip_tls_client_hello_reset(snip_tls_client_hello_t *client_hello) {
    memset(client_hello, '\0', sizeof(snip_tls_client_hello_t));
}

/**
 * Parse a ClientHello handshake message from bytes to a snip_tls_client_hello_t object.
 * @param message[in] - The source handshake message.
 * @param client_hello[in/out] - The target client_hello struct where we will store the parsed data.
 * @return
 */
snip_parser_state_t
snip_tls_client_hello_parser(snip_tls_handshake_message_t *message, snip_tls_client_hello_t *client_hello) {
    size_t offset = 0;
    uint16_t tmp16;
    if (offset + SNIP_TLS_VERSION_LENGTH > message->length) {
        return snip_parser_state_error;
    }
    client_hello->client_version.major = message->body[offset];
    offset += 1;
    client_hello->client_version.minor = message->body[offset];
    offset += 1;

    if (snip_tls_random_parser(message->body, message->length, &offset, &(client_hello->random)) !=
        snip_parser_state_parsed) {
        return snip_parser_state_error;
    }

    if (SNIP_TLS_CLIENT_HELLO_SESSION_ID_LENGTH_SIZE + offset > message->length) {
        return snip_parser_state_error;
    }
    client_hello->session_id_length = message->body[offset];
    offset += SNIP_TLS_CLIENT_HELLO_SESSION_ID_LENGTH_SIZE;

    if (client_hello->session_id_length + offset > message->length) {
        return snip_parser_state_error;
    }
    client_hello->session_id = message->body + offset;
    offset += client_hello->session_id_length;

    if (SNIP_TLS_CLIENT_HELLO_CIPHER_SUITE_LENGTH_SIZE + offset > message->length) {
        return snip_parser_state_error;
    }
    memcpy(&(tmp16), message->body + offset, sizeof(uint16_t));
    client_hello->cipher_suite_length = ntohs(tmp16);
    offset += SNIP_TLS_CLIENT_HELLO_CIPHER_SUITE_LENGTH_SIZE;

    if (client_hello->cipher_suite_length + offset > message->length) {
        return snip_parser_state_error;
    }
    client_hello->cipher_suites_data = message->body + offset;
    offset += client_hello->cipher_suite_length;

    if (SNIP_TLS_CLIENT_HELLO_COMPRESSION_METHOD_LENGTH_SIZE + offset > message->length) {
        return snip_parser_state_error;
    }
    client_hello->compression_methods_length = message->body[offset];
    offset += SNIP_TLS_CLIENT_HELLO_COMPRESSION_METHOD_LENGTH_SIZE;

    if (client_hello->compression_methods_length + offset > message->length) {
        return snip_parser_state_error;
    }
    client_hello->compression_methods_data = message->body + offset;
    offset += client_hello->compression_methods_length;

    // The extensions section (and the 16-bit size prefix) are optional.
    if (SNIP_TLS_EXTENSION_LENGTH_SIZE + offset > message->length) {
        // Must match exactly.  Hopefully being dilligent on this will save some off-by-one errors.
        return offset == message->length ? snip_parser_state_parsed : snip_parser_state_error;
    }
    memcpy(&tmp16, message->body + offset, sizeof(uint16_t));
    client_hello->extensions_data_length = ntohs(tmp16);
    offset += SNIP_TLS_EXTENSION_LENGTH_SIZE;

    if(client_hello->extensions_data_length + offset > message->length) {
        return snip_parser_state_error;
    }
    client_hello->extensions_data = message->body + offset;
    offset += client_hello->extensions_data_length;

    // TLS 1.3 deprecates the client_version section of the ClientHello in favor of the the supported_versions extension
    // Find the highest version in that list.
    snip_tls_extension_t extension;
    snip_parser_state_t supported_versions_state = snip_tls_client_hello_find_extension(
            client_hello, snip_tls_extension_type_supported_versions, &extension);
    if(supported_versions_state == snip_parser_state_parsed) {
        uint8_t number_of_versions = extension.data[0];
        size_t extension_offset = SNIP_TLS_EXTENSION_VERSION_LENGTH_SIZE;
        // The list can be arbitrarily long (with 8bit size limit) but MUST be odd
        if(extension.length % SNIP_TLS_VERSION_LENGTH != SNIP_TLS_EXTENSION_VERSION_LENGTH_SIZE) {
            return snip_parser_state_error;
        }
        while(extension_offset < extension.length) {
            snip_tls_version_t candidate_version;
            candidate_version.major = extension.data[extension_offset];
            candidate_version.minor = extension.data[extension_offset + 1];
            extension_offset += SNIP_TLS_VERSION_LENGTH;
            // Find the highest version the client says they support.

            if(candidate_version.major == candidate_version.minor && ((candidate_version.major & 0x0F) == 0x0A)) {
                // These are fake versions. See https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01
                continue;
            }

            if(SNIP_TLS_COMPARE_TLS_VERSION(candidate_version, >, client_hello->client_version)) {
                client_hello->client_version = candidate_version;
            }

        }
    }
    else if(supported_versions_state == snip_parser_state_error) {
        return snip_parser_state_error;
    }
    return snip_parser_state_parsed;
}

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
) {
    uint16_t tmp16;
    if(*extension_offset == client_hello->extensions_data_length) {
        return snip_parser_state_not_found;
    }
    if((*extension_offset + SNIP_TLS_EXTENSION_HEADER_LENGTH) > client_hello->extensions_data_length) {
        return snip_parser_state_error;
    }
    memcpy(&tmp16, client_hello->extensions_data + *extension_offset, sizeof(uint16_t));
    extension->type = (snip_tls_extension_type_t) ntohs(tmp16);
    *extension_offset += SNIP_TLS_EXTENSION_TYPE_LENGTH;

    memcpy(&tmp16, client_hello->extensions_data + *extension_offset, sizeof(uint16_t));
    extension->length = (size_t) ntohs(tmp16);
    if(extension->length & 0xC000) {
        return snip_parser_state_error;
    }
    if((extension->length + *extension_offset) > client_hello->extensions_data_length) {
        return snip_parser_state_error;
    }
    *extension_offset += SNIP_TLS_EXTENSION_LENGTH_SIZE;
    extension->data = client_hello->extensions_data + *extension_offset;
    *extension_offset += extension->length;
    return snip_parser_state_parsed;
}

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
)
{
    size_t extension_offset = 0;
    while(TRUE) {
        snip_parser_state_t state = snip_tls_client_hello_get_next_extension(client_hello, &extension_offset, extension);
        if(state == snip_parser_state_parsed) {
            if(type == extension->type && extension->length) {
                return snip_parser_state_parsed;
            }
        }
        else if (state == snip_parser_state_not_found) {
            return state;
        }
        else {
            return snip_parser_state_error;
        }
    }
}

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
)
{
    snip_tls_extension_t extension;
    snip_parser_state_t state = snip_tls_client_hello_find_extension(client_hello,
                                                                     snip_tls_extension_type_server_name,
                                                                     &extension);
    if(state == snip_parser_state_parsed) {
        size_t offset = 0;
        if(extension.length < SNIP_TLS_EXTENSION_SERVER_NAME_LIST_LENGTH_SIZE) {
            return snip_parser_state_error;
        }
        uint16_t tmp16;
        memcpy(&tmp16, extension.data + offset, sizeof(uint16_t));
        uint16_t list_length = ntohs(tmp16);  // in bytes, not elements.
        offset += SNIP_TLS_EXTENSION_SERVER_NAME_LIST_LENGTH_SIZE;
        while(offset < extension.length &&
                (offset - SNIP_TLS_EXTENSION_SERVER_NAME_LIST_LENGTH_SIZE) < list_length)
        {
            snip_tls_client_hello_server_name_type_t type =
                    (snip_tls_client_hello_server_name_type_t) extension.data[offset];
            offset += SNIP_TLS_EXTENSION_SERVER_NAME_TYPE_LENGTH;
            memcpy(&tmp16, extension.data + offset, sizeof(uint16_t));
            size_t name_length = ntohs(tmp16);
            offset += SNIP_TLS_EXTENSION_SERVER_NAME_LENGTH_SIZE;
            if(type == name_type) {
                *dest_ptr = malloc(name_length + 1);
                memset((void *) *dest_ptr, '\0', name_length + 1);
                memcpy((void *) *dest_ptr, extension.data + offset, name_length);
                *dest_size = name_length;
                return snip_parser_state_parsed;
            }
            offset += name_length;
        }
        return offset == extension.length ? snip_parser_state_not_found : snip_parser_state_error;
    }
    else {
        *dest_ptr = NULL;
        return state;
    }
}