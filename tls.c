//
// Created by Cody Baker on 4/15/17.
//

#include "tls.h"
#include "compat.h"
#include <string.h>

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
snip_tls_get_next_record(struct evbuffer *input, size_t *offset, snip_tls_record_t *record) {
    size_t zero_offset = 0;
    if(!offset) { // We allow this to be a NULL parameter, meaning no offset.
        offset = &zero_offset;
    }
    ssize_t available = evbuffer_get_length(input) - *offset;
    if(available < SNIP_TLS_RECORD_HEADER_LENGTH) {
        return snip_parser_state_more_data_needed;
    }
    unsigned char *buffer = evbuffer_pullup(input, (*offset) + SNIP_TLS_RECORD_HEADER_LENGTH) + (*offset);
    record->content_type = buffer[0];
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
    memcpy(&(random->gmt_unix_time), buffer + *offset, sizeof(snip_tls_random_t.gmt_unix_time));
    *offset += sizeof(snip_tls_random_t.gmt_unix_time);
    memcpy(&(random->random_bytes), buffer + *offset, sizeof(snip_tls_random_t.random_bytes));
    *offset += sizeof(snip_tls_random_t.random_bytes);
    return snip_parser_state_parsed;
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
    if (offset + SNIP_TLS_CLIENT_HELLO_VERSION_LENGTH > message->length) {
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
    offset += SNIP_TLS_CLIENT_HELLO_SESSION_ID_LENGTH_SIZE;

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
    if (SNIP_TLS_CLIENT_HELLO_EXTENSION_LENGTH_SIZE + offset > message->length) {
        // Must match exactly.  Hopefully being dilligent on this will save some off-by-one errors.
        return offset == message->length ? snip_parser_state_parsed : snip_parser_state_error;
    }
    memcpy(&tmp16, message->body + offset, sizeof(uint16_t));
    client_hello->extensions_data_length = ntohs(tmp16);

}

    }
}