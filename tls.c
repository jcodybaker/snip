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
        return snip_parser_state_record_incomplete;
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
        return snip_parser_state_record_incomplete;
    }
    buffer = evbuffer_pullup(input, (*offset) + SNIP_TLS_RECORD_HEADER_LENGTH + record->length) + (*offset);
    record->fragment = buffer + SNIP_TLS_RECORD_HEADER_LENGTH;
    *offset += SNIP_TLS_RECORD_HEADER_LENGTH + record->length;
    return snip_parser_state_record_parsed;
}

/**
 * Reset the state of the of a TLS Message parser (snip_tls_message_parse_context_t)
 * @param message_parse_context
 */
void
snip_tls_message_parse_context_reset(snip_tls_message_parser_context_t *message_parse_context) {
    if(message_parse_context->tls_message_buffer) {
        evbuffer_free(message_parse_context->tls_message_buffer);
    }
}