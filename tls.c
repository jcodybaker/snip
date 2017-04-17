//
// Created by Cody Baker on 4/15/17.
//

#include "tls.h"
#include <string.h>

/**
 * Find the next TLS record in the provided buffer.
 * @param input - libevent evbuffer record.
 * @param offset - Offset in bytes from the start of the evbuffer
 * @param record - A snip_tls_record object where we can store the info.  record->fragment is only valid until the next
 *      evbuffer operation.
 * @return Status of the parse, see snip_parser_state_t.
 */
snip_parser_state_t
snip_tls_get_next_record(struct evbuffer *input, size_t offset, snip_tls_record_t *record) {
    ssize_t available = evbuffer_get_length(input) - offset;
    if(available < SNIP_TLS_RECORD_HEADER_LENGTH) {
        return snip_parser_state_record_incomplete;
    }
    unsigned char *buffer = evbuffer_pullup(input, offset + SNIP_TLS_RECORD_HEADER_LENGTH) + offset;
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
    record->fragment = buffer + SNIP_TLS_RECORD_HEADER_LENGTH;
    return snip_parser_state_record_parsed;
}