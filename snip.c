//
// Created by Cody Baker on 3/16/17.
//

#include <event2/thread.h>
#include <event2/event.h>
#include <event2/dns.h>

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <signal.h>

#include "config.h"
#include "compat.h"
#include "snip.h"
#include "tls.h"
#include "log.h"

#include <pthread.h>


const struct timeval snip_shutdown_timeout = {5, 0};

typedef struct snip_context_e {
    snip_config_t *config;
    struct evdns_base *dns_base;
    struct event_base *event_base;

    pthread_t event_thread;
    pthread_cond_t work_for_main_thread;
    pthread_mutex_t context_lock;

    struct event *hup_event;
    int pending_reload;

    int argc;
    char **argv;

    int shutting_down;
} snip_context_t;

enum snip_socket_state_e {
    snip_socket_state_initial = 0,
    snip_socket_state_connecting,

    snip_socket_state_connected,

    snip_socket_state_output_finished,
    snip_socket_state_input_eof,

    snip_socket_state_finished,
    snip_socket_state_error
};

enum snip_pair_state {
    snip_pair_state_record_header = 0,
    snip_pair_state_reading_record,
    snip_pair_state_error_not_tls,
    snip_pair_state_error_invalid_tls_version,
    snip_pair_state_error_found_http,
    snip_pair_state_error_protocol_violation,
    snip_pair_state_have_client_hello,
    snip_pair_state_sni_found,
    snip_pair_state_sni_not_found,
    snip_pair_state_waiting_for_dns,
    snip_pair_state_waiting_for_connect,
    snip_pair_state_proxying,
    snip_pair_state_error_dns_failed,
    snip_pair_state_error_connect_failed,
    snip_pair_state_error_no_route
};

typedef struct snip_pair_e {
    struct bufferevent *client_bev;
    enum snip_socket_state_e client_state;

    enum snip_pair_state state;
    size_t current_record_start;
    uint16_t current_record_length;
    uint32_t current_message_length;

    struct evbuffer *handshake_buffer;

    evutil_socket_t client_fd;
    struct sockaddr_storage client_address; // Hold the address locally in this structure.
    size_t client_address_len;

    struct bufferevent *target_bev;
    enum snip_socket_state_e target_state;

    char *target_hostname;
    evutil_socket_t target_fd;
    struct sockaddr_storage target_address; // Hold the address locally in this structure.
    size_t target_address_len;

    uint16_t sni_hostname_length;
    char *sni_hostname;

    int references;

    struct snip_TLS_version client_version;

    snip_config_listener_t *listener;
    snip_config_route_t *route;
    struct sockaddr_storage target;
    char target_string[INET6_ADDRSTRLEN_WITH_PORT];
    evutil_socket_t target_socket;
    snip_context_t *context;

    struct evdns_getaddrinfo_request *dns_request;
} snip_pair_t;


// Local definitions
/**
 * Handle disconnections and errors on the client channel.
 * @param bev
 * @param events
 * @param ctx
 */
static void
snip_client_event_cb(
        struct bufferevent *bev,
        short events,
        void *ctx
);

/**
 * Handle disconnections and errors on the target channel.
 * @param bev
 * @param events
 * @param ctx
 */
static void
snip_target_event_cb(
        struct bufferevent *bev,
        short events,
        void *ctx
);

/**
 * Handle incoming data on the client-connection.
 * @param bev
 * @param ctx
 */
static void
snip_client_read_cb(
        struct bufferevent *bev,
        void *ctx
);





/**
 * Create an snip_client record.
 * @return
 */
snip_pair_t *
snip_client_create() {
    snip_pair_t *client = (snip_pair_t *) malloc(sizeof(snip_pair_t));
    memset(client, '\0', sizeof(snip_pair_t));
    return client;
}

/**
 * Release, and if appropriate cleanup/free a snip_client record.
 * @param client
 */
void
snip_client_destroy(
        snip_pair_t *client
) {
    if(client->client_bev) {
        bufferevent_free(client->client_bev);
    }
    if(client->target_bev) {
        bufferevent_free(client->target_bev);
    }
    if(client->listener) {
        snip_config_release(client->listener->config);
        client->listener = NULL;
    }
    // These are malloc'ed by libevent's evbuffer_readln function.
    if(client->target_hostname) {
        free(client->target_hostname);
    }
    free(client);
}

/**
 * Get the length of data held in the handshake buffer.
 * @param client
 * @return
 */
size_t
snip_get_handshake_buffer_length(snip_pair_t *client) {
    // If the ClientHello is contained in a single TLS record, we can just borrow their buffer.
    if(!client->handshake_buffer) {
        return client->current_record_length;
    }
    return evbuffer_get_length(client->handshake_buffer);
}

/**
 * Return a pointer to contiguous chunk of memory containing all of the handshake data we have so far.
 *
 * @param client
 * @param input
 * @param pullup
 * @param available [OUT] - Number of bytes available in the buffer
 * @return The start of the handshake message buffer.
 */
unsigned char *
snip_get_handshake_buffer(snip_pair_t *client, struct evbuffer *input, size_t pullup, size_t *available) {
    // If the ClientHello is contained in a single TLS record, we can just borrow their buffer.
    if(!client->handshake_buffer) {
        *available = client->current_record_length;
        return evbuffer_pullup(input, client->current_record_length + SNIP_TLS_RECORD_HEADER_LENGTH) +
               SNIP_TLS_RECORD_HEADER_LENGTH;
    }
    *available = evbuffer_get_length(client->handshake_buffer);
    return evbuffer_pullup(client->handshake_buffer, -1);
}

/**
 * Determin the port we should connect to on the target.  If the route we resolved doesn't specify a port, we return
 * the port the client connected on.
 * @param client
 * @return
 */
uint16_t
snip_client_get_target_port(snip_pair_t *client) {
    if(client->route->port) {
        return client->route->port;
    }
    return client->listener->bind_port;
}

/**
 * Start the process of connecting to the target.
 * @param client
 */
void
snip_connect_to_target(snip_pair_t *client) {
    struct sockaddr *address = (struct sockaddr *) &(client->target);
    client->target_socket = socket(address->sa_family, SOCK_STREAM, IPPROTO_TCP);
    evutil_make_socket_nonblocking(client->target_socket);
    if(address->sa_family == AF_INET) {
        struct sockaddr_in *address4 = (struct sockaddr_in *) &(client->target);

    }
    else if (address->sa_family == AF_INET6) {
        struct sockaddr_in6 *address6 = (struct sockaddr_in6 *) &(client->target);
    }
}

/**
 * Handle incoming data on the client-connection.
 * @param bev
 * @param ctx
 */
static void
snip_target_read_cb(
        struct bufferevent *bev,
        void *ctx
) {
    snip_pair_t *client = (snip_pair_t *) ctx;
    struct evbuffer *input_from_target = bufferevent_get_input(bev);
    if(client->client_bev) {
        bufferevent_write_buffer(client->client_bev, input_from_target);
    }
}

/**
 * Callback triggered when the output buffer on a bufferevent_socket is finished flushing.
 * @param bev
 * @param ctx
 */
void
snip_shutdown_write_buffer_on_flushed(struct bufferevent *bev, void *ctx) {
    snip_pair_t *client = (snip_pair_t *) ctx;
    // Safe to call this because we've already flushed the write buffer to 0.
    shutdown(bufferevent_getfd(bev), SHUT_WR);

    if(bev == client->target_bev) {
        if(client->target_state == snip_socket_state_input_eof) {
            client->target_state = snip_socket_state_finished;
            client->target_bev = NULL;
            bufferevent_free(bev);
        }
        else if(client->target_state == snip_socket_state_connected) {
            client->target_state = snip_socket_state_output_finished;
        }
    }
    else if(bev == client->client_bev) {
        if(client->client_state == snip_socket_state_input_eof) {
            client->client_state = snip_socket_state_finished;
            client->client_bev = NULL;
            bufferevent_free(bev);
        }
        else if(client->client_state == snip_socket_state_connected) {
            client->client_state = snip_socket_state_output_finished;
        }
    }
    else {
        // This shouldn't happen, but if it does we should know it does.
        snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED, "Unexpected output-drained event.");
        return;
    }

    if((!client->target_bev || client->target_state == snip_socket_state_output_finished) &&
            (!client->client_bev || client->client_state == snip_socket_state_output_finished))
    {
        snip_client_destroy(client);
    }
}

/**
 * Finish writing any buffered data to the client socket, shutdown the output stream, and reevaluate.
 * @param client
 */
void
snip_client_finish_writing(snip_pair_t *client) {
    struct evbuffer *output = bufferevent_get_output(client->client_bev);
    size_t output_length = evbuffer_get_length(output);
    if(client->target_bev) {
        bufferevent_write_buffer(client->client_bev, bufferevent_get_input(client->target_bev));
    }
    bufferevent_setcb(
            client->client_bev,
            client->client_state != snip_socket_state_input_eof ? snip_client_read_cb : NULL,
            output_length ? snip_shutdown_write_buffer_on_flushed : NULL, // write cb, triggered when the write buf is 0
            snip_client_event_cb,
            (void *) client
    );
    if(!output_length) {
        // If the output buffer is already empty we won't get the callback and need to shut it down now.
        snip_shutdown_write_buffer_on_flushed(client->client_bev, (void *) client);
    }
}

/**
 * Finish writing any buffered data to the target socket, shutdown the output stream, and reevaluate.
 * @param client
 */
void
snip_target_finish_writing(snip_pair_t *client) {
    struct evbuffer *output = bufferevent_get_output(client->target_bev);
    size_t output_length = evbuffer_get_length(output);
    if (client->client_bev) {
        bufferevent_write_buffer(client->target_bev, bufferevent_get_input(client->client_bev));
    }
    bufferevent_setcb(
            client->target_bev,
            client->target_state != snip_socket_state_input_eof ? snip_target_read_cb : NULL,
            output_length ? snip_shutdown_write_buffer_on_flushed : NULL, // write cb, triggered when the write buf is 0
            snip_target_event_cb,
            (void *) client
    );
    if(!output_length) {
        // If the output buffer is already empty we won't get the callback and need to shut it down now.
        snip_shutdown_write_buffer_on_flushed(client->target_bev, (void *) client);
    }
}

/**
 * Handle disconnections and errors on the target channel.
 * @param bev
 * @param events
 * @param ctx
 */
static void
snip_target_event_cb(
        struct bufferevent *bev,
        short events,
        void *ctx
) {
    snip_pair_t *client = (snip_pair_t *) ctx;
    // TODO - Better log messages. It's unclear if we can get the resolved address
    // with bufferevent_socket_connect_hostname
    if(events & BEV_EVENT_CONNECTED) {
        snip_log(SNIP_LOG_LEVEL_INFO, "Target connection succeeded.");
        client->target_state = snip_socket_state_connected;
    }
    else if (events & BEV_EVENT_ERROR) {
        int dns_error = bufferevent_socket_get_dns_error(bev);
        if(dns_error) {
            snip_log(SNIP_LOG_LEVEL_WARNING,
                     "Target connection failed: DNS Error (%d) - %s",
                     dns_error,
                     evutil_gai_strerror(dns_error));
        }
        else {
            int error_number = EVUTIL_SOCKET_ERROR();
            snip_log(SNIP_LOG_LEVEL_WARNING,
                     "Target connection failed: Socket error (%d) - %s",
                     error_number,
                     evutil_socket_error_to_string(error_number)
            );
            // If there's anything left on the write buffer, nab it before we shutdown.
            if(client->target_state >= snip_socket_state_connected)
            {
                client->target_state = snip_socket_state_error;
                // If the client is still around, lets clean up our relationship with it.
                if(client->client_bev) {
                    // We won't be able to output any more client-input.  Stop reading.
                    if (client->client_state == snip_socket_state_connected ||
                        client->client_state == snip_socket_state_output_finished) {

                        shutdown(bufferevent_getfd(client->client_bev), SHUT_RD);
                    }

                    // Similarly, we're done reading from the target.  Finish writing to the client.
                    if (client->client_state == snip_socket_state_connected ||
                        client->client_state == snip_socket_state_input_eof) {
                        snip_client_finish_writing(client);
                    }

                    bufferevent_free(client->target_bev);
                    client->target_bev = NULL;
                }
            }
            else {
                // If we never connected, there's nothing to relay. We may ultimately want to offer more polite failure
                // notices here.
                snip_client_destroy(client);
            }

        }
    }
    else if (events & BEV_EVENT_EOF) {
        snip_log(SNIP_LOG_LEVEL_INFO, "Target connection: remote input ended");
        client->target_state = snip_socket_state_input_eof;
        // Schedule any remaining target input for output
        snip_client_finish_writing(client);
    }
}

/**
 * Callback for DNS resolution on the target address.
 * @param error_code
 * @param response
 * @param arg
 */
void
snip_lookup_target_dns_callback(int error_code, struct evutil_addrinfo *response, void *arg) {
    snip_pair_t *client = (snip_pair_t *) arg;
    if(error_code) {
        snip_log(SNIP_LOG_LEVEL_WARNING,
                 "Failed to resolve target '%s' for client: %s",
                 client->route->dest_hostname,
                 evutil_gai_strerror(error_code));
        client->state = snip_pair_state_error_dns_failed;
        return;
    }
    uint16_t port = snip_client_get_target_port(client);
    struct evutil_addrinfo *address;
    for (address = response; address; address = address->ai_next) {
        char target_string[INET6_ADDRSTRLEN_WITH_PORT];
        const char *ntop_result = NULL;
        if (address->ai_family == AF_INET) {
            memcpy(&(client->target), address->ai_addr, sizeof(struct sockaddr_in));
            struct sockaddr_in *sin = (struct sockaddr_in *) &(client->target);
            sin->sin_port = port;
            ntop_result = evutil_inet_ntop(AF_INET, &sin->sin_addr, target_string, INET6_ADDRSTRLEN_WITH_PORT);
        }
        else if (address->ai_family == AF_INET6) {
            memcpy(&(client->target), address->ai_addr, sizeof(struct sockaddr_in6));
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &(client->target);
            sin6->sin6_port = port;
            ntop_result = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, target_string, INET6_ADDRSTRLEN_WITH_PORT);
        }
        else {
            continue;
        }

        evutil_freeaddrinfo(response);

        if (!ntop_result)
        {
            // Can't see why this would fail, but lets be safe.
            snip_log(SNIP_LOG_LEVEL_CRITICAL, "Failed to encode target address for client.");
            client->state = snip_pair_state_error_dns_failed;
            return;
        }
        int string_result = snprintf(client->target_string,
                 INET6_ADDRSTRLEN_WITH_PORT,
                 "%s:%hu",
                 target_string,
                 port);
        if(string_result <= 0 || (string_result + 1) > INET6_ADDRSTRLEN_WITH_PORT) {
            // Can't see why this would fail, but lets be safe.
            snip_log(SNIP_LOG_LEVEL_CRITICAL, "Failed to encode target address for client.");
            client->state = snip_pair_state_error_dns_failed;
            return;
        }
        // Time to move on.
        snip_connect_to_target(client);
        return;
    }
    // We only get here if there's no useful responses.
    snip_log(SNIP_LOG_LEVEL_WARNING,
             "Failed to resolve target '%s' for client: no results.",
             client->route->dest_hostname
    );
    client->state = snip_pair_state_error_dns_failed;
    evutil_freeaddrinfo(response);
}

void
snip_lookup_target_dns(snip_pair_t *client, char *hostname, uint16_t port) {
    struct evutil_addrinfo hints;
    struct evdns_getaddrinfo_request *req;
    struct user_data *user_data;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    client->dns_request = evdns_getaddrinfo(
            client->context->dns_base, hostname, NULL, &hints, snip_lookup_target_dns_callback, (void*) client);
}


/**
 * Handle incoming data on the client-connection.
 * @param bev
 * @param ctx
 */
static void
snip_client_read_cb(
        struct bufferevent *bev,
        void *ctx
) {
    snip_pair_t *client = (snip_pair_t *) ctx;

    // Initially we're just peeking on the request, so we don't remove anything from the input buffer until we
    // understand where the client is trying to get, and have connected to their ultimate destination.
    snip_context_t *context = client->context;

    struct evbuffer *input_from_client = bufferevent_get_input(bev);
    struct evbuffer *output_to_client = bufferevent_get_output(bev);


    size_t available_input = evbuffer_get_length(input_from_client);
    size_t available_record = 0;
    size_t available_handshake = 0;

    uint16_t extension_server_name_length;
    size_t extension_server_name_offset;
    uint8_t extension_server_name_type;
    uint16_t extension_server_name_blob_length;
    uint16_t extension_id;

    uint16_t extension_length;

    uint16_t extensions_section_length;
    size_t extensions_section_start;

    uint16_t tmp16;
    uint32_t tmp32;

    unsigned char *buffer = NULL;
    unsigned char *handshake_data;
    size_t offset = 0;
    while(1) {
        switch (client->state) {
            case snip_pair_state_record_header:
                // This is the beginning of the connection.  The first record SHOULD be a handshake message with type
                // ClientHello.  The ClientHello message *could* (but likely isn't) be split across multiple records.
                // We can get the length of the current record, and the total length of the ClientHello message with
                // fixed offsets from the beginning.  We can also verify that the versions and other fields match our
                // expectations.
                if ((available_input - client->current_record_start) < SNIP_TLS_RECORD_HEADER_LENGTH) {
                    return; // Come back when there's enough data.
                }
                buffer = evbuffer_pullup(input_from_client, client->current_record_start + SNIP_TLS_RECORD_HEADER_LENGTH);

                // This MUST be a handshake record.
                if((buffer[0] != SNIP_TLS_RECORD_TYPE_HANDSHAKE))
                {
                    client->state = snip_pair_state_error_not_tls;
                    break;
                }

                // Clients set the version on the frame to their lowest supported version. SSLv1 was never released,
                // SSLv2 had the same ClientHello format (though did not support extensions).  3.3 (TLSv3) is still a
                // draft, but holds the same ClientHello format. Since this is set to the client's LOWEST version, we'll
                // accept SSLv2 for now, but if that's their highest supported (or even SSLv3) we're not going to have a
                // lot useful to say to them.  For now we'll be conservative and won't pretend to understand anything
                // the TLS1.3 draft.
                if(buffer[1] < 0x02 || buffer[1] > 0x03 || buffer[2] > 0x03) {
                    client->state = snip_pair_state_error_invalid_tls_version;
                    break;
                }

                memcpy(&tmp16, buffer + 3, sizeof(uint16_t));
                client->current_record_length = ntohs(tmp16);

                if((client->current_record_length & 0x8000) || client->current_record_length == 0) {
                    // Max length is 2^14, can't be 0
                    client->state = snip_pair_state_error_protocol_violation;
                    break;
                }
                client->state = snip_pair_state_reading_record;
                break;
            case snip_pair_state_reading_record:
                // libevent is handling the buffering so we'll pull out the whole record at once. Can't be > than 16k
                offset = client->current_record_start + SNIP_TLS_RECORD_HEADER_LENGTH;
                if((available_input - offset) < client->current_record_length) {
                    // Wait for more input.
                    return;
                }

                buffer = evbuffer_pullup(
                        input_from_client,
                        client->current_record_start + SNIP_TLS_RECORD_HEADER_LENGTH + client->current_record_length
                );

                if(client->handshake_buffer) {
                    // This isn't the first record, add this record's data to the last so we can ultimately get a single
                    // concatenated message.
                    evbuffer_add(client->handshake_buffer,
                                 buffer + client->current_record_start, client->current_record_length);
                }

                if(!client->current_message_length) {
                    // We don't know how long the handshake message is yet.
                    handshake_data = snip_get_handshake_buffer(
                            client, input_from_client, SNIP_TLS_HANDSHAKE_HEADER_LENGTH, &available_handshake);
                    if(available_handshake >= SNIP_TLS_HANDSHAKE_HEADER_LENGTH)
                    {
                        if(handshake_data[0] != SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_CLIENT_HELLO) {
                            // The first message MUST be a ClientHello
                            client->state = snip_pair_state_error_protocol_violation;
                            break;
                        }
                        memcpy(&tmp32, handshake_data, sizeof(uint32_t));
                        // Could be slower, but doesn't make assumptions about endianess that bit math does.
                        memset(&tmp32, '\0', SNIP_TLS_HANDSHAKE_MESSAGE_TYPE_LENGTH);
                        client->current_message_length = ntohl(tmp32);
                    }
                }

                available_handshake = snip_get_handshake_buffer_length(client);
                if(client->current_message_length && (available_handshake >= client->current_message_length)) {
                    // Ok, cool, we've got the whole ClientHello
                    client->state = snip_pair_state_have_client_hello;
                    break;
                }

                // Ok, if we're here, we haven't yet captured all of the ClientHello.
                if(!client->handshake_buffer) {
                    // We delay creating this buffer because its not necessary if the data is already contiguious
                    client->handshake_buffer = evbuffer_new();
                    // If we know the size, pre-allocate.
                    evbuffer_expand(client->handshake_buffer,
                                    MAX(client->current_message_length, client->current_record_length));
                    evbuffer_add(client->handshake_buffer,
                                 buffer + client->current_record_start, client->current_record_length);
                }

                // Setup to read the next record.
                client->current_record_start = client->current_record_start +
                                               SNIP_TLS_RECORD_HEADER_LENGTH + client->current_record_length;
                client->current_record_length = 0;

                client->state = snip_pair_state_record_header;
                break;
            case snip_pair_state_have_client_hello:
                // Done reading, just process.
                handshake_data = snip_get_handshake_buffer(
                        client, input_from_client, client->current_message_length, &available_handshake);
                offset = SNIP_TLS_HANDSHAKE_HEADER_LENGTH; // We've already dealt with the header
                client->client_version.major = *(handshake_data + offset);
                client->client_version.minor = *(handshake_data + offset + 1);
                offset += SNIP_TLS_CLIENT_HELLO_VERSION_LENGTH;

                offset += SNIP_TLS_CLIENT_HELLO_RANDOM_LENGTH;
                if(offset + SNIP_TLS_CLIENT_HELLO_SESSION_ID_LENGTH_LENGTH > available_handshake) {
                    client->state = snip_pair_state_error_protocol_violation;
                    break;
                }
                offset += SNIP_TLS_CLIENT_HELLO_SESSION_ID_LENGTH_LENGTH + *(handshake_data + offset);

                // Skip the variable length cipher-suite section
                if((offset + SNIP_TLS_CLIENT_HELLO_CIPHER_SUITE_LENGTH_SIZE) > available_handshake) {
                    client->state = snip_pair_state_error_protocol_violation;
                    break;
                }
                memcpy(&tmp16, handshake_data + offset, SNIP_TLS_CLIENT_HELLO_CIPHER_SUITE_LENGTH_SIZE);
                offset += SNIP_TLS_CLIENT_HELLO_CIPHER_SUITE_LENGTH_SIZE + ntohs(tmp16);

                if((offset + SNIP_TLS_CLIENT_HELLO_COMPRESSION_METHOD_LENGTH_SIZE) > available_handshake) {
                    client->state = snip_pair_state_error_protocol_violation;
                    break;
                }

                offset += handshake_data[offset] + SNIP_TLS_CLIENT_HELLO_COMPRESSION_METHOD_LENGTH_SIZE;
                if((offset + SNIP_TLS_CLIENT_HELLO_EXTENSIONS_SECTION_LENGTH_LENGTH) > available_handshake) {
                    client->state = snip_pair_state_error_protocol_violation;
                    break;
                }


                memcpy(&tmp16, handshake_data + offset, sizeof(uint16_t));
                offset += SNIP_TLS_CLIENT_HELLO_EXTENSIONS_SECTION_LENGTH_LENGTH;
                // SOooo many redundant lengths.  We'll track em all just to be sure.
                extensions_section_start = offset;
                extensions_section_length = ntohs(tmp16);

                // Extensions take up the rest of the ClientHello.  They have a 16bit identifier, a 16bit length,
                // followed by a dynamic section.
                while (((offset +
                         SNIP_TLS_CLIENT_HELLO_EXTENSION_TYPE_LENGTH +
                         SNIP_TLS_CLIENT_HELLO_EXTENSION_LENGTH_LENGTH) < available_handshake) &&
                         (extensions_section_length > (offset - extensions_section_start))
                        )
                {
                    memcpy(&tmp16, handshake_data + offset, sizeof(uint16_t));
                    extension_id = ntohs(tmp16);
                    offset += SNIP_TLS_CLIENT_HELLO_EXTENSION_TYPE_LENGTH;

                    memcpy(&tmp16, handshake_data + offset, sizeof(uint16_t));
                    extension_length = ntohs(tmp16);
                    offset += SNIP_TLS_CLIENT_HELLO_EXTENSION_LENGTH_LENGTH;

                    if(extension_id == 0)
                    {
                        memcpy(&tmp16, handshake_data + offset, sizeof(uint16_t));
                        extension_server_name_length = ntohs(tmp16);
                        offset += SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_LENGTH_LENGTH;

                        extension_server_name_offset = 0;
                        while(extension_server_name_offset < extension_server_name_length) {
                            extension_server_name_type = *(handshake_data + offset + extension_server_name_offset);

                            extension_server_name_offset += SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_TYPE_LENGTH;
                            memcpy(&tmp16, handshake_data+offset+extension_server_name_offset, sizeof(uint16_t));
                            extension_server_name_blob_length = ntohs(tmp16);
                            extension_server_name_offset +=
                                    SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_NAME_LENGTH_LENGTH;

                            if(extension_server_name_type == SNIP_TLS_CLIENT_HELLO_EXTENSION_SERVER_NAME_TYPE_HOST_NAME)
                            {
                                // The structures allow for multiple instances of this record.  We'll take the last
                                // though it seems unlikely.
                                if(client->sni_hostname) {
                                    free(client->sni_hostname);
                                }

                                client->sni_hostname_length = extension_server_name_blob_length;
                                client->sni_hostname = (char *) malloc(client->sni_hostname_length + 1);
                                // We allocate and 0 an extra byte so the string can be guaranteed null terminated.
                                memset(client->sni_hostname, '\0', client->sni_hostname_length + 1);
                                memcpy(client->sni_hostname,
                                       handshake_data+offset+extension_server_name_offset,
                                       client->sni_hostname_length);
                                extension_server_name_offset += client->sni_hostname_length;
                            }
                            extension_server_name_offset += extension_server_name_blob_length;
                        }
                    }
                    offset += extension_length;
                }
                if(client->sni_hostname_length) {
                    client->state = snip_pair_state_sni_found;
                }
                else {
                    client->state = snip_pair_state_sni_not_found;
                }
                break;
            case snip_pair_state_sni_found:
                // Ok, cool, lets make some progress.
                snip_log(SNIP_LOG_LEVEL_DEBUG, "Found SNI '%s'\n", client->sni_hostname);
                client->route = snip_find_route_for_sni_hostname(client->listener, client->sni_hostname);
                if(!client->route) {
                    snip_log(SNIP_LOG_LEVEL_INFO,
                             "Unable to match SNI hostname '%s' to a route.",
                             client->sni_hostname
                    );
                    client->state = snip_pair_state_error_no_route;
                    break;
                }
                client->target_bev = bufferevent_socket_new(context->event_base, -1, BEV_OPT_CLOSE_ON_FREE);

                // Ok we have what we need from the listener.
                snip_config_release(client->listener->config);
                client->listener = NULL;

                bufferevent_setcb(
                        client->target_bev,
                        snip_target_read_cb,
                        NULL,
                        snip_target_event_cb,
                        (void*) client
                );

                /* Copy all the data from the input buffer to the output buffer. */
                bufferevent_write_buffer(client->target_bev, input_from_client);

                if(bufferevent_socket_connect_hostname(
                        client->target_bev,
                        context->dns_base,
                        AF_UNSPEC,
                        snip_route_and_sni_hostname_to_target_hostname(client->route, client->sni_hostname),
                        snip_client_get_target_port(client)))
                {
                    snip_log(SNIP_LOG_LEVEL_WARNING,
                             "Error opening a connection to '%s'.",
                             snip_route_and_sni_hostname_to_target_hostname(client->route, client->sni_hostname)
                    );
                    client->state = snip_pair_state_error_connect_failed;
                    break;
                };
                client->state = snip_pair_state_proxying;
                break;
            case snip_pair_state_waiting_for_dns:
            case snip_pair_state_waiting_for_connect:
            case snip_pair_state_error_dns_failed:
            case snip_pair_state_error_connect_failed:
                // The work for these states is handled in separate event handlers.  We won't read any more off the
                // buffer until we're proxying.
                break;
            case snip_pair_state_proxying:
                bufferevent_write_buffer(client->target_bev, input_from_client);
                break;
            case snip_pair_state_sni_not_found:
                break;
            case snip_pair_state_error_no_route:
                break;
            case snip_pair_state_error_not_tls:
                // So it looks like this isn't TLS, or at least isn't a version we know.  It may be that the client
                // connected with HTTP, in which case we can at least provide a helpful error. Apache does something
                // similar.
                buffer = evbuffer_pullup(input_from_client, 5);
                if(!memcmp(buffer, "GET /", 5) || !memcmp(buffer, "POST ", 5) || !memcmp(buffer, "HEAD ", 5)) {
                    client->state = snip_pair_state_error_found_http;
                    break;
                }
                break;
            case snip_pair_state_error_protocol_violation:
            case snip_pair_state_error_invalid_tls_version:
                printf("Error\n");
                break;
            case snip_pair_state_error_found_http:
                break;

        }
        break;
    }
}

/**
 * Handle disconnections and errors on the client channel.
 * @param bev
 * @param events
 * @param ctx
 */
static void
snip_client_event_cb(
        struct bufferevent *bev,
        short events,
        void *ctx
) {
    snip_pair_t *client = (snip_pair_t *) ctx;
    // TODO - Better log messages.
    if (events & BEV_EVENT_ERROR) {
        int error_number = EVUTIL_SOCKET_ERROR();
        snip_log(SNIP_LOG_LEVEL_WARNING,
                 "Client connection failed: Socket error (%d) - %s",
                 error_number,
                 evutil_socket_error_to_string(error_number)
        );
        client->client_state = snip_socket_state_error;
        // If the target is active, lets clean up our relationship with it.
        if(client->target_bev) {
            // We won't be able to output any more target-input.  Stop reading from the target.
            if (client->target_state== snip_socket_state_connected ||
                client->target_state== snip_socket_state_output_finished) {
                shutdown(bufferevent_getfd(client->target_bev), SHUT_RD);
            }

            // Similarly, we're done reading from the client.  Finish writing to the target.
            if (client->target_state== snip_socket_state_connected ||
                client->target_state== snip_socket_state_input_eof) {
                snip_target_finish_writing(client);
            }

            bufferevent_free(client->client_bev);
            client->client_bev = NULL;
        }
        else {
            // If we never connected, there's nothing to relay. We may ultimately want to offer more polite failure
            // notices here.
            snip_client_destroy(client);
        }
    }
    else if (events & BEV_EVENT_EOF) {
        snip_log(SNIP_LOG_LEVEL_INFO, "Target connection: remote input ended");
        client->client_state = snip_socket_state_input_eof;
        // Schedule any remaining client input for output
        snip_target_finish_writing(client);
    }
}

/**
 * Called when a new connection happens on the listener.
 * @param evconn
 * @param fd
 * @param address
 * @param socklen
 * @param ctx
 */
static void
snip_accept_incoming_cb(
        struct evconnlistener *evconn,
        evutil_socket_t fd,
        struct sockaddr *address,
        int socklen,
        void *ctx
) {
    struct event_base *base = evconnlistener_get_base(evconn);
    snip_config_listener_t *listener = (snip_config_listener_t *) ctx;

    // Save it all to the pair
    snip_pair_t *client = snip_client_create();
    snip_config_retain(listener->config);
    client->listener = listener;
    // We release the listener/config when we establish a destination. We still want to hold a way back to the context.
    client->context = listener->config->context;
    client->client_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(client->client_bev, snip_client_read_cb, NULL, snip_client_event_cb, (void *) client);

    memcpy((struct sockaddr *) &(client->client_address), address, socklen);
    client->client_address_len = (size_t) socklen;
    client->client_fd = fd;
    client->client_state = snip_socket_state_connected;

    // Set it ready
    bufferevent_enable(client->client_bev, EV_READ|EV_WRITE);
}

/**
 * Handle an error on the connection listener.
 * @param evconn
 * @param ctx
 */
static void
snip_accept_error_cb(struct evconnlistener *evconn, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(evconn);
    snip_config_listener_t *listener = (snip_config_listener_t *) ctx;
    int err = EVUTIL_SOCKET_ERROR();
    snip_log_fatal(
            SNIP_EXIT_ERROR_SOCKET,
            "An error occurred while setting up a listener: (%d) %s",
            err,
            evutil_socket_error_to_string(err)
    );
    snip_config_release(listener->config);
    event_base_loopexit(base, NULL);
}

/**
 * Open a socket and start listening for new connections based upon a configuration object.
 * @param context
 * @param config
 * @param listener
 * @return
 */
SNIP_BOOLEAN
snip_listen(snip_context_ref_t context, snip_config_t *config, snip_config_listener_t *listener) {
    memset(&(listener->socket_addr), 0, sizeof(listener->socket_addr));
    // We pass the config in directly instead of getting it from context because on a reload it hasn't been set yet.
    listener->config = snip_config_retain(config);


    listener->socket_addr.sin_family = AF_INET;
    listener->socket_addr.sin_addr.s_addr = htonl(0);
    listener->socket_addr.sin_port = htons(listener->bind_port);
    listener->socket = evconnlistener_new_bind(context->event_base,
                                               snip_accept_incoming_cb,
                                               (void *) listener,
                                               LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE|LEV_OPT_THREADSAFE,
                                               -1,
                                               (struct sockaddr*)&listener->socket_addr,
                                               sizeof(listener->socket_addr)
    );
    if (!listener->socket) {
        snip_config_release(config);
        snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                       "Failed to open socket: %s",
                       strerror(errno)
        );
        return FALSE;
    }
    evconnlistener_set_error_cb(listener->socket, snip_accept_error_cb);
    return TRUE;
}

/**
 * Create the snip_context object.
 * @return
 */
snip_context_t *
snip_context_create() {
    snip_context_t *context = malloc(sizeof(snip_context_t));
    memset(context, '\0', sizeof(snip_context_t));
    return context;
}

/**
 * Initialize the context, with event bases and the like.
 */
void
snip_context_init(snip_context_t *context, int argc, char **argv) {
    context->argc = argc;
    context->argv = argv;
    // right now we only support pthreads.  Windows threads are TODO.
    evthread_use_pthreads();
    context->event_base = event_base_new();
    context->dns_base = evdns_base_new(context->event_base, 1);

}


void snip_stop(snip_context_t *context) {
    context->shutting_down = 1;
    event_base_loopexit(context->event_base, &snip_shutdown_timeout);

}

void snip_sigint_handler(evutil_socket_t fd, short events, void *arg) {
    snip_context_t *context = (snip_context_t *) arg;
    if(context->shutting_down) {
        snip_stop(context);
    }
}

void snip_sighup_handler(evutil_socket_t fd, short events, void *arg) {
    snip_context_t *context = (snip_context_t *) arg;
    pthread_mutex_lock(&(context->context_lock));
    if(!context->pending_reload) {
        context->pending_reload = 1;
        pthread_cond_signal(&(context->work_for_main_thread));
        pthread_mutex_unlock(&(context->context_lock));
    }
}

void * snip_run_network(void *ctx)
{
    snip_context_t *context = (snip_context_t *) ctx;
    evsignal_new(context->event_base, SIGHUP, snip_sighup_handler, (void *) context);
    evsignal_new(context->event_base, SIGINT, snip_sigint_handler, (void *) context);
    event_base_dispatch(context->event_base);
    return NULL;
}



/**
 * Shutdown a listener inside the event loop.
 * @param fd
 * @param events
 * @param ctx
 */
void
snip_shutdown_listener(evutil_socket_t fd, short events, void *ctx) {
    snip_config_listener_t *listener = (snip_config_listener_t *) ctx;

}

void
snip_replace_config(evutil_socket_t fd, short events, void *ctx) {
    snip_config_t *new_config = (snip_config_t *) ctx;
    snip_context_t *context = new_config->context;
    snip_config_t *old_config = context->config; // May be NULL if this is the first config load.

    // We have a new config. We compare the old config to the new one because we don't want to shutdown and then reopen
    // sockets.  We copy the old socket onto the new config.
    snip_config_listener_list_t *new_listener = new_config->listeners;
    snip_config_listener_list_t *old_listener;
    while(new_listener) {
        old_listener = old_config ? old_config->listeners : NULL;
        while(old_listener) {
            if(old_listener->value.socket &&
               snip_listener_socket_is_equal(&(old_listener->value), &(new_listener->value)))
            {
                snip_listener_replace(&(old_listener->value), &(new_listener->value));
                break;
            }
            old_listener = old_listener->next;
        }
        if(!new_listener->value.socket) {
            // We're not already listening on this port/interface.  Start.
            snip_listen(context, new_config, &(new_listener->value));
        }
        new_listener = new_listener->next;
    }

    old_listener = old_config ? old_config->listeners : NULL;
    while(old_listener) {
        if(old_listener->value.socket) {
            evconnlistener_free(old_listener->value.socket);
            // We won't be accepting any new connections.  In-progress connections retain the config individually.
            snip_config_release(old_config);
            old_listener->value.socket = NULL;
        }
        old_listener = old_listener->next;
    }

    context->config = new_config;
    if(old_config) {
        snip_config_release(old_config);
    }
}

/**
 * Reload the configuration file asynchronously.
 * @param context
 * @param argc - argument count from the command line.  If this is being built into another package, this can be 0
 *      provided the default config location is sufficient.
 * @param argv - argument strings from the command line.  If this is being build into another package, this can be NULL
 *      provided the default config location is sufficient.
 */
void
snip_reload_config(snip_context_ref_t context, int argc, char **argv) {
    snip_config_t *old_config = context->config;

    // Create and parse a new config.
    snip_config_t *new_config = snip_config_retain(snip_config_create());
    new_config->context = context;

    if(argc && argv) {
        snip_config_parse_args(new_config, argc, argv);
    }
    if(!new_config->config_path) {
        new_config->config_path = SNIP_INSTALL_CONF_PATH;
    }
    if(!snip_parse_config_file(new_config)) {
        snip_log_fatal(SNIP_EXIT_ERROR_INVALID_CONFIG, "Invalid configuration file '%s'.", new_config->config_path);
        return;
    }



    //int evdns_base_clear_nameservers_and_suspend(struct evdns_base *base);
    //int evdns_base_resume(struct evdns_base *base);
}

/**
 * Read the configuration and start handling requests.
 * @param[in,out] context
 */
void snip_run(snip_context_t *context)
{
    snip_reload_config(context, context->argc, context->argv);
    pthread_cond_init(&(context->work_for_main_thread), NULL);

    // We want the event thread to catch the signals
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGQUIT);
    sigaddset(&sigset, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    pthread_create(&(context->event_thread), NULL, snip_run_network, (void *) context);
    pthread_mutex_init(&(context->context_lock), NULL);
    pthread_mutex_lock(&(context->context_lock));
    while(1) {
        pthread_cond_wait(&(context->work_for_main_thread), &(context->context_lock));
        if(context->shutting_down) {
            break;
        }
        if(context->pending_reload) {
            context->pending_reload = 0;
            pthread_mutex_unlock(&(context->context_lock));
            snip_reload_config(context, context->argc, context->argv);
            pthread_mutex_lock(&(context->context_lock));
        }
    }
    pthread_join(context->event_thread, NULL);
    pthread_mutex_unlock(&(context->context_lock));
    pthread_mutex_destroy(&(context->context_lock));
    pthread_cond_destroy(&(context->work_for_main_thread));
}