// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

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
#include <fcntl.h>

#include <signal.h>

#include "config.h"
#include "compat.h"
#include "snip.h"
#include "tls.h"
#include "log.h"
#include "net_util.h"
#include "sys_util.h"

#include <pthread.h>

// Globals for signal handlers
int snip_should_reload = 0;

// Constants
const struct timeval snip_shutdown_timeout = {5, 0};

/**
 * Describe the life cycle of a socket.
 */
typedef enum snip_socket_state_e {
    snip_socket_state_initial = 0,
    snip_socket_state_connecting,
    // server sockets start in connected after accept().
    snip_socket_state_connected,
    // a socket which is both finished sending, and has received an eof is automatically close()'d.
    snip_socket_state_output_finished,
    snip_socket_state_input_eof,
    snip_socket_state_input_discard,

    snip_socket_state_finished,
    snip_socket_state_error
} snip_socket_state_t;

typedef enum snip_session_state_e {
    snip_session_state_initial = 0,
    snip_session_state_waiting_for_tls_client_hello,
    snip_session_state_sni_hostname_found,
    snip_session_state_no_sni_hostname_found,
    snip_session_state_proxying,
    snip_session_state_tls_protocol_error,
    snip_session_state_waiting_for_connect
} snip_session_state_t;



/**
 * Master context for TLS SNIp.
 */
typedef struct snip_context_e {
    snip_config_t *config;
    struct evdns_base *dns_base;
    struct event_base *event_base;

    pthread_t event_thread;
    pthread_cond_t work_for_main_thread;
    pthread_mutex_t context_lock;

    int argc;
    char **argv;

    int shutting_down;

    SNIP_BOOLEAN dropped_privileges;

    uint64_t next_id;
} snip_context_t;


typedef struct snip_session_s {
    uint64_t id;

    // Reference back to the master context.
    snip_context_t *context;

    // These fields describe the inbound connection from the client.
    struct bufferevent *client_bev;
    snip_socket_state_t client_state;
    struct sockaddr_storage client_address; // Hold the address locally in this structure.
    size_t client_address_length;
    char client_address_string[INET6_ADDRSTRLEN_WITH_PORT];
    char client_local_address_string[INET6_ADDRSTRLEN_WITH_PORT];

    // General description of this session
    char *description;

    // These field describe the
    struct bufferevent *target_bev;
    snip_socket_state_t target_state;
    char *target_hostname;
    uint16_t target_port;
    struct sockaddr_storage target_address; // Hold the address locally in this structure.
    size_t target_address_len;
    char target_address_string[INET6_ADDRSTRLEN_WITH_PORT];

    // Reference to the listener which created this session.
    snip_config_listener_t *listener;

    snip_tls_record_t current_record;
    // Offset from the head of the input buffer where we should try reading our next record.
    size_t current_record_parse_offset;
    // Offset inside the current record where the next message fragment begins.
    size_t current_record_read_offset;

    snip_tls_handshake_message_parser_context_t handshake_message_parser_context;
    snip_tls_handshake_message_t current_handshake_message;

    snip_session_state_t state;

    size_t sni_hostname_length;
    const char *sni_hostname;

    snip_tls_version_t client_version;
} snip_session_t;


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
 * Apply the given route to the open client connection.
 * @param session
 * @param route
 */
void
snip_session_apply_route(snip_session_t *session, snip_config_route_t *route);



/**
 * Create an snip_session_t record.
 * @return
 */
snip_session_t *
snip_session_create() {
    snip_session_t *session = (snip_session_t *) malloc(sizeof(snip_session_t));
    memset(session, '\0', sizeof(snip_session_t));
    snip_tls_handshake_message_parser_context_init(&(session->handshake_message_parser_context));
    return session;
}

/**
 * Release, and if appropriate cleanup/free a snip_session_t record.
 * @param session
 */
void
snip_session_destroy(
        snip_session_t *session
) {
    if(session->client_bev) {
        bufferevent_free(session->client_bev);
    }
    if(session->target_bev) {
        bufferevent_free(session->target_bev);
    }
    if(session->sni_hostname) {
        free((void *) session->sni_hostname);
    }
    if(session->description) {
        free(session->description);
    }
    if(session->listener) {
        snip_config_release(session->listener->config);
        session->listener = NULL;
    }
    if(session->target_hostname) {
        free(session->target_hostname);
    }
    snip_tls_handshake_message_parser_context_reset(&(session->handshake_message_parser_context));
    free(session);
}

/**
 * Generate a description of the current connection state and store it in session->description.
 * @param session
 */
void
snip_pair_set_description(snip_session_t *session) {
    // This should only get longer each time, but lets be safe.
    if(session->description) {
        free(session->description);
        session->description = NULL;
    }
    if(session->target_hostname) {
        const char *format = "%016llX (%s->%s->%s:%hu)";
        int needed = snprintf(NULL,
                              0,
                              format,
                              session->id,
                              session->client_address_string,
                              session->client_local_address_string,
                              session->target_hostname,
                              session->target_port
        );
        if(needed > 0) {
            session->description = malloc((size_t) needed + 1);
            memset(session->description, '\0', needed + 1);
            needed = snprintf(session->description,
                              needed + 1,
                              format,
                              session->id,
                              session->client_address_string,
                              session->client_local_address_string,
                              session->target_hostname,
                              session->target_port
            );
        }
        if(needed < 0) {
            snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED, "Error creating description.");
        }
    }
    else {
        const char *format = "%016llX (%s->%s->!)";
        int needed = snprintf(NULL,
                              0,
                              format,
                              session->id,
                              session->client_address_string,
                              session->client_local_address_string
        );
        if(needed > 0) {
            session->description = malloc((size_t) needed + 1);
            memset(session->description, '\0', needed + 1);
            needed = snprintf(session->description,
                              needed + 1,
                              format,
                              session->id,
                              session->client_address_string,
                              session->client_local_address_string
            );
        }
        if(needed < 0) {
            snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED, "Error creating description.");
        }
    }
}

/**
 * Determin the port we should connect to on the target.  If the route we resolved doesn't specify a port, we return
 * the port the client connected on.
 * @param session
 * @return
 */
uint16_t
snip_route_get_target_port(snip_session_t *session, snip_config_route_t *route) {
    if(route->port) {
        return route->port;
    }
    return session->listener->bind_port;
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
    snip_session_t *session = (snip_session_t *) ctx;
    struct evbuffer *input_from_target = bufferevent_get_input(bev);
    if(session->client_bev) {
        bufferevent_write_buffer(session->client_bev, input_from_target);
    }
    else {
        // We close the read-stream when the matching output-buffer is gone, but that could still be pending.  Discard.
        struct evbuffer *input = bufferevent_get_input(bev);
        evbuffer_drain(input, evbuffer_get_length(input));
    }
}

/**
 * Callback triggered when the output buffer on a bufferevent_socket is finished flushing.
 * @param bev
 * @param ctx
 */
void
snip_shutdown_write_buffer_on_flushed(struct bufferevent *bev, void *ctx) {
    snip_session_t *session = (snip_session_t *) ctx;
    // Safe to call this because we've already flushed the write buffer to 0.
    shutdown(bufferevent_getfd(bev), SHUT_WR);

    if(bev == session->target_bev) {
        if(session->target_state == snip_socket_state_input_eof ||
                session->target_state == snip_socket_state_input_discard)
        {
            session->target_state = snip_socket_state_finished;
            session->target_bev = NULL;
            bufferevent_free(bev);
        }
        else if(session->target_state == snip_socket_state_connected) {
            session->target_state = snip_socket_state_output_finished;
        }
    }
    else if(bev == session->client_bev) {
        if(session->client_state == snip_socket_state_input_eof ||
                session->client_state == snip_socket_state_input_discard)
        {
            session->client_state = snip_socket_state_finished;
            session->client_bev = NULL;
            bufferevent_free(bev);
        }
        else if(session->client_state == snip_socket_state_connected) {
            session->client_state = snip_socket_state_output_finished;
        }
    }
    else {
        // This shouldn't happen, but if it does we should know it does.
        snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED, "%s: Unexpected output-drained event.", session->description);
        return;
    }

    if((!session->target_bev || session->target_state == snip_socket_state_output_finished) &&
            (!session->client_bev || session->client_state == snip_socket_state_output_finished))
    {
        snip_session_destroy(session);
    }
}

/**
 * Finish writing any buffered data to the client socket, shutdown the output stream, and reevaluate.
 * @param session
 */
void
snip_client_finish_writing(snip_session_t *session) {
    struct evbuffer *output = bufferevent_get_output(session->client_bev);
    size_t output_length = evbuffer_get_length(output);
    if(session->target_bev) {
        bufferevent_write_buffer(session->client_bev, bufferevent_get_input(session->target_bev));
    }
    bufferevent_setcb(
            session->client_bev,
            session->client_state != snip_socket_state_input_eof ? snip_client_read_cb : NULL,
            output_length ? snip_shutdown_write_buffer_on_flushed : NULL, // write cb, triggered when the write buf is 0
            snip_client_event_cb,
            (void *) session
    );
    if(!output_length) {
        // If the output buffer is already empty we won't get the callback and need to shut it down now.
        snip_shutdown_write_buffer_on_flushed(session->client_bev, (void *) session);
    }
}

/**
 * Finish writing any buffered data to the target socket, shutdown the output stream, and reevaluate.
 * @param session
 */
void
snip_target_finish_writing(snip_session_t *session) {
    struct evbuffer *output = bufferevent_get_output(session->target_bev);
    size_t output_length = evbuffer_get_length(output);
    if (session->client_bev) {
        bufferevent_write_buffer(session->target_bev, bufferevent_get_input(session->client_bev));
    }
    bufferevent_setcb(
            session->target_bev,
            session->target_state != snip_socket_state_input_eof ? snip_target_read_cb : NULL,
            output_length ? snip_shutdown_write_buffer_on_flushed : NULL, // write cb, triggered when the write buf is 0
            snip_target_event_cb,
            (void *) session
    );
    if(!output_length) {
        // If the output buffer is already empty we won't get the callback and need to shut it down now.
        snip_shutdown_write_buffer_on_flushed(session->target_bev, (void *) session);
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
    snip_session_t *session = (snip_session_t *) ctx;
    if(events & BEV_EVENT_CONNECTED) {
        session->state = snip_session_state_proxying;
        session->target_state = snip_socket_state_connected;

        session->target_address_len = sizeof(struct sockaddr_storage);
        int rv = getpeername(bufferevent_getfd(bev),
                    (struct sockaddr *) &(session->target_address),
                    (socklen_t *) &(session->target_address_len));
        if(rv < 0 ||
                (snip_sockaddr_to_string(session->target_address_string, (struct sockaddr *) &(session->target_address)) < 0))
        {
            // This should all be pretty safe, but JIC.
            session->target_state = snip_socket_state_error;
            snip_log(SNIP_LOG_LEVEL_WARNING,
                     "%s: Target connection succeeded but its address could not be decoded.",
                     session->description
            );
            snip_session_destroy(session);
        }
        snip_log(SNIP_LOG_LEVEL_INFO,
                 "%s: Target connection to (%s) succeeded.",
                 session->description,
                 session->target_address_string
        );
        // Ok we have what we need from the listener.
        snip_config_release(session->listener->config);
        session->listener = NULL;
    }
    else if (events & BEV_EVENT_ERROR) {
        int dns_error = bufferevent_socket_get_dns_error(bev);
        if(dns_error) {
            snip_log(SNIP_LOG_LEVEL_WARNING,
                     "%s: Unable to resolve target DNS: (%d) - %s.",
                     session->description,
                     dns_error,
                     evutil_gai_strerror(dns_error));
        }
        else {
            int error_number = EVUTIL_SOCKET_ERROR();
            snip_log(SNIP_LOG_LEVEL_WARNING,
                     "%s: Target connection socket error (%d) - %s.",
                     session->description,
                     error_number,
                     evutil_socket_error_to_string(error_number)
            );
            // If there's anything left on the write buffer, nab it before we shutdown.
            if(session->target_state >= snip_socket_state_connected)
            {
                session->target_state = snip_socket_state_error;
                // If the client is still around, lets clean up our relationship with it.
                if(session->client_bev) {
                    // We won't be able to output any more client-input.  Stop reading.
                    if (session->client_state == snip_socket_state_connected ||
                        session->client_state == snip_socket_state_output_finished) {

                        shutdown(bufferevent_getfd(session->client_bev), SHUT_RD);
                    }

                    // Similarly, we're done reading from the target.  Finish writing to the client.
                    if (session->client_state == snip_socket_state_connected ||
                            session->client_state == snip_socket_state_input_eof ||
                            session->client_state == snip_socket_state_input_discard) {
                        snip_client_finish_writing(session);
                    }

                    bufferevent_free(session->target_bev);
                    session->target_bev = NULL;
                }
            }
            else {
                // If we never connected, there's nothing to relay. We may ultimately want to offer more polite failure
                // notices here.
                snip_session_apply_route(session, snip_get_route_for_proxy_connect_failure(session->listener));
            }

        }
    }
    else if (events & BEV_EVENT_EOF) {
        snip_log(SNIP_LOG_LEVEL_INFO,
                 "%s: Target ended input.",
                 session->description
        );
        session->target_state = snip_socket_state_input_eof;
        // Schedule any remaining target input for output
        if(session->client_bev) {
            snip_client_finish_writing(session);
        }
    }
}

/**
 * Apply the given route to the open client connection.
 * @param session
 * @param route
 */
void
snip_session_apply_route(snip_session_t *session, snip_config_route_t *route) {
    snip_context_t *context = session->context;
    struct evbuffer *input_from_client = bufferevent_get_input(session->client_bev);
    if(route->action == snip_route_action_tls_pass_through) {
        session->target_state = snip_socket_state_connecting;
        session->target_bev = bufferevent_socket_new(context->event_base, -1, BEV_OPT_CLOSE_ON_FREE);

        bufferevent_setcb(
                session->target_bev,
                snip_target_read_cb,
                NULL,
                snip_target_event_cb,
                (void*) session
        );
        bufferevent_enable(session->target_bev, EV_READ|EV_WRITE);

        /* Copy all the data from the input buffer to the output buffer. */
        bufferevent_write_buffer(session->target_bev, input_from_client);

        session->target_port = snip_route_get_target_port(session, route);
        session->target_hostname = snip_route_and_sni_hostname_to_target_hostname(route, session->sni_hostname);
        snip_pair_set_description(session);

        int address_family = AF_UNSPEC;
        if(context->config->disable_ipv6) {
            address_family = AF_INET;
        }
        else if(context->config->disable_ipv4) {
            address_family = AF_INET6;
        }

        if(bufferevent_socket_connect_hostname(
                session->target_bev,
                context->dns_base,
                address_family,
                session->target_hostname,
                session->target_port))
        {
            snip_log(SNIP_LOG_LEVEL_WARNING,
                     "%s: Error opening target connection to '%s'.",
                     session->description,
                     session->target_hostname);
            snip_session_apply_route(session, snip_get_route_for_proxy_connect_failure(session->listener));
            return;
        };
        session->state = snip_session_state_waiting_for_connect;
        return;
    }
    else if(route->action == snip_route_action_send_file) {
        if(session->client_state == snip_socket_state_connected) {
            session->client_state = snip_socket_state_input_discard;
            int source_file = open(route->send_file, O_RDONLY);
            if(source_file < 0) {
                snip_log(SNIP_LOG_LEVEL_WARNING,
                         "%s: failed to open source file: (%d) %s.",
                         session->description,
                         errno,
                         strerror(errno)
                );
                snip_session_apply_route(session, snip_get_route_for_proxy_connect_failure(session->listener));
                return;
            }
            evbuffer_add_file(bufferevent_get_output(session->client_bev), source_file, 0, -1);
            snip_client_finish_writing(session);
        }
        return;
    }
    else if(route->action == snip_route_action_send_text) {
        if(session->client_state == snip_socket_state_connected) {
            session->client_state = snip_socket_state_input_discard;
            evbuffer_add(bufferevent_get_output(session->client_bev), route->send_text, strlen(route->send_text));
            snip_client_finish_writing(session);
        }
        return;
    }
    else {
        // TODO - Right now we're implementing all other actions as a hangup.  Implement TLS Alert protocol.
        snip_log(SNIP_LOG_LEVEL_INFO, "%s: Hanging up.", session->description);
        if(session->client_state == snip_socket_state_connected) {
            session->client_state = snip_socket_state_input_discard;
        }
        snip_session_destroy(session);
    }

}


/**
 * Determine if the input buffer looks to contain HTTP data.
 * @param session
 * @return TRUE if we suspect HTTP, FALSE otherwise.
 */
SNIP_BOOLEAN
snip_session_is_client_http(snip_session_t *session) {
    // So it looks like this isn't TLS, or at least isn't a version we know.  It may be that the client
    // connected with HTTP, in which case we can at least provide a helpful error. Apache does something
    // similar.
    struct evbuffer *input = bufferevent_get_input(session->client_bev);
    const size_t HTTP_HINT_LENGTH = 5;
    if(evbuffer_get_length(input) < HTTP_HINT_LENGTH) {
        return FALSE;
    }
    const unsigned char *buffer = evbuffer_pullup(input, HTTP_HINT_LENGTH);
    if(buffer && (!memcmp(buffer, "GET /", HTTP_HINT_LENGTH) ||
                  !memcmp(buffer, "POST ", HTTP_HINT_LENGTH) ||
                  !memcmp(buffer, "HEAD ", HTTP_HINT_LENGTH)))
    {
        return TRUE;
    }
    return FALSE;
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
    snip_session_t *session = (snip_session_t *) ctx;
    // Initially we're just peeking on the request, so we don't remove anything from the input buffer until we
    // understand where the client is trying to get, and have connected to their ultimate destination.
    snip_context_t *context = session->context;

    struct evbuffer *input_from_client = bufferevent_get_input(bev);
    while(TRUE) {
        // In a few cases we want to hold the read channel open, but discard anything the remote sends.
        if(session->client_state == snip_socket_state_input_discard) {
            evbuffer_drain(input_from_client, evbuffer_get_length(input_from_client));
            return;
        }

        if(session->state == snip_session_state_initial) {
            snip_tls_record_reset(&(session->current_record));
            session->state = snip_session_state_waiting_for_tls_client_hello;
        }
        else if (session->state == snip_session_state_waiting_for_tls_client_hello) {
            snip_parser_state_t record_parser_state = snip_tls_record_get_next(
                    input_from_client,
                    &(session->current_record_parse_offset),
                    &(session->current_record));
            if(record_parser_state == snip_parser_state_error) {
                session->state = snip_session_state_tls_protocol_error;
            }
            else if(record_parser_state == snip_parser_state_more_data_needed) {
                // We added the data we have, but it didn't make a full record.  Wait for more. Stay in the same state.
                return;
            }
            else if(record_parser_state == snip_parser_state_parsed) {
                if(session->current_record.content_type == snip_tls_record_type_handshake) {
                    // Cool, this is what we're expecting.
                    snip_parser_state_t handshake_message_parse_state = snip_tls_handshake_message_parser_add_record(
                            &(session->handshake_message_parser_context),
                            &(session->current_handshake_message),
                            &(session->current_record),
                            &(session->current_record_read_offset)
                    );
                    if(handshake_message_parse_state == snip_parser_state_more_data_needed) {
                        // The record did not contain a complete message. We're still waiting for the TLS ClientHello.
                        // If we restart this state-handler, we can read more data in.
                        continue;
                    }
                    else if(handshake_message_parse_state == snip_parser_state_parsed) {
                        // The first message MUST be a ClientHello.
                        if(session->current_handshake_message.type != snip_tls_handshake_message_type_client_hello) {
                            session->state = snip_session_state_tls_protocol_error;
                            continue;
                        }
                        // Blobs referenced in this client_hello are only safe until we manip the input evbuffer.
                        snip_tls_client_hello_t client_hello;
                        snip_tls_client_hello_reset(&client_hello);
                        snip_parser_state_t client_hello_parse_state =
                                snip_tls_client_hello_parser(&(session->current_handshake_message), &client_hello);
                        if(client_hello_parse_state != snip_parser_state_parsed) {
                            session->state = snip_session_state_tls_protocol_error;
                            continue;
                        }

                        // Save this for logging.
                        session->client_version = client_hello.client_version;

                        snip_parser_state_t server_name_parse_state = snip_tls_client_hello_find_server_name(
                                &client_hello,
                                snip_tls_client_hello_server_name_type_hostname,
                                (const unsigned char * *) &( session->sni_hostname),
                                &(session->sni_hostname_length)
                        );

                        // We're done with this message.  Cleanup.
                        snip_tls_handshake_message_parser_context_reset(&session->handshake_message_parser_context);
                        snip_tls_handshake_message_reset(&session->current_handshake_message);

                        snip_log(SNIP_LOG_LEVEL_DEBUG,
                                 "%s: Got ClientHello TLS(%hhu,%hhu) SNI: '%s'.",
                                 session->description,
                                 session->client_version.major,
                                 session->client_version.minor,
                                 session->sni_hostname);

                        if(server_name_parse_state == snip_parser_state_parsed) {
                            session->state = snip_session_state_sni_hostname_found;
                            continue;
                        }
                        else if(server_name_parse_state == snip_parser_state_not_found) {
                            session->state = snip_session_state_no_sni_hostname_found;
                            continue;
                        }
                        else {
                            session->state = snip_session_state_tls_protocol_error;
                            continue;
                        }
                    }
                }
                else if(session->current_record.content_type == snip_tls_record_type_alert) {

                }
                else {
                    session->state = snip_session_state_tls_protocol_error;
                }
            }
        }
        else if(session->state == snip_session_state_sni_hostname_found) {
            snip_session_apply_route(session,
                                     snip_find_route_for_sni_hostname(session->listener, session->sni_hostname));
        }
        else if (session->state == snip_session_state_no_sni_hostname_found) {
            snip_session_apply_route(session, snip_get_route_for_no_sni(session->listener));
        }
        else if(session->state == snip_session_state_proxying ||
                session->state == snip_session_state_waiting_for_connect)
        {
            bufferevent_write_buffer(session->target_bev, input_from_client);
            return;
        }
        else if(session->state == snip_session_state_tls_protocol_error) {
            if(snip_session_is_client_http(session)) {
                // This content looks like HTTP, we can direct them an HTTP server, or display an error, or redirect.
                snip_log(SNIP_LOG_LEVEL_WARNING,
                         "%s: TLS Protocol Error. Input looks like HTTP.",
                         session->description
                );
                snip_session_apply_route(session, snip_get_route_for_http_fallback(session->listener));
            }
            else {
                snip_log(SNIP_LOG_LEVEL_WARNING,
                         "%s: TLS Protocol Error.",
                         session->description
                );
                snip_session_apply_route(session, snip_get_route_for_tls_error(session->listener));
            }
            return;
        }
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
    snip_session_t *session = (snip_session_t *) ctx;
    if (events & BEV_EVENT_ERROR) {
        int error_number = EVUTIL_SOCKET_ERROR();
        snip_log(SNIP_LOG_LEVEL_WARNING,
                 "%s: Client connection failed: Socket error (%d) - %s.",
                 session->description,
                 error_number,
                 evutil_socket_error_to_string(error_number)
        );
        session->client_state = snip_socket_state_error;
        // If the target is active, lets clean up our relationship with it.
        if(session->target_bev) {
            // We won't be able to output any more target-input.  Stop reading from the target.
            if (session->target_state== snip_socket_state_connected ||
                session->target_state== snip_socket_state_output_finished) {
                shutdown(bufferevent_getfd(session->target_bev), SHUT_RD);
            }

            // Similarly, we're done reading from the client.  Finish writing to the target.
            if (session->target_state == snip_socket_state_connected ||
                    session->target_state == snip_socket_state_input_eof ||
                    session->target_state == snip_socket_state_input_discard)
            {
                snip_target_finish_writing(session);
            }

            bufferevent_free(session->client_bev);
            session->client_bev = NULL;
        }
        else {
            // If we never connected, there's nothing to relay. We may ultimately want to offer more polite failure
            // notices here.
            snip_session_destroy(session);
        }
    }
    else if (events & BEV_EVENT_EOF) {
        snip_log(SNIP_LOG_LEVEL_INFO, "%s: Client connection input ended.", session->description);
        session->client_state = snip_socket_state_input_eof;
        // Schedule any remaining client input for output
        if(session->target_bev) {
            snip_target_finish_writing(session);
        }
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
    snip_context_t *context = listener->config->context;

    // Save it all to the pair
    snip_session_t *session = snip_session_create();
    snip_config_retain(listener->config);
    session->id = context->next_id++;
    session->listener = listener;
    // We release the listener/config when we establish a destination. We still want to hold a way back to the context.
    session->context = listener->config->context;
    session->client_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(session->client_bev, snip_client_read_cb, NULL, snip_client_event_cb, (void *) session);

    memcpy(session->client_local_address_string,
           listener->bind_address_string,
           sizeof(session->client_local_address_string));
    memcpy((struct sockaddr *) &(session->client_address), address, socklen);
    session->client_address_length = (size_t) socklen;
    snip_sockaddr_to_string(session->client_address_string, address);

    snip_pair_set_description(session);

    snip_log(SNIP_LOG_LEVEL_DEBUG, "%s: Connection accepted.", session->description);
    session->client_state = snip_socket_state_connected;

    // Set it ready
    bufferevent_enable(session->client_bev, EV_READ|EV_WRITE);
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
            "An error occurred while setting up a listener (%s): (%d) %s.",
            listener->bind_address_string,
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
    // We pass the config in directly instead of getting it from context because on a reload it hasn't been set yet.
    snip_config_retain(listener->config);

    // The user can specify a bind address, or just a port.  If they JUST specify the port, we assume a dual-stack setup
    // and need to initialize the addresses.
    struct sockaddr_in *address4 = (struct sockaddr_in *) &listener->bind_address_4;
    struct sockaddr_in6 *address6 = (struct sockaddr_in6 *) &listener->bind_address_6;
    if(!listener->bind_address_length_4 && !listener->bind_address_length_6) {
        if(!config->disable_ipv4) {
            address4->sin_family = AF_INET;
            address4->sin_port = htons(listener->bind_port);
            address4->sin_addr.s_addr = INADDR_ANY;
            listener->bind_address_length_4 = sizeof(struct sockaddr_in);
        }
        if(!config->disable_ipv6) {
            address6->sin6_family = AF_INET6;
            address6->sin6_port = htons(listener->bind_port);
            address6->sin6_addr = in6addr_any;
            listener->bind_address_length_6 = sizeof(struct sockaddr_in6);
        }
    }

    listener->socket_disabled = TRUE;
    if(listener->bind_address_length_4) {
        listener->libevent_listener_4 = evconnlistener_new_bind(
                context->event_base,
                snip_accept_incoming_cb,
                (void *) listener,
                LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE|LEV_OPT_DISABLED,
                -1,
                (struct sockaddr*)&listener->bind_address_4,
                listener->bind_address_length_4);

        if (!listener->libevent_listener_4) {
            snip_config_release(config);
            snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                           "Failed to open IPv4 socket (%s): %d %s.",
                           listener->bind_address_string,
                           errno,
                           strerror(errno)
            );
            return FALSE;
        }
        evconnlistener_set_error_cb(listener->libevent_listener_4, snip_accept_error_cb);
    }
    if(listener->bind_address_length_6) {
        // This one is a bit more involved.  For consistency we need to set IPV6_V6ONLY on the socket before we bind.
        evutil_socket_t v6_fd = -1;

        // This is a linux shortcut lets us avoid some syscalls and is safer (if it works).
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
        v6_fd = socket(address6->sin6_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#endif
        if(v6_fd < 0 &&
                ((v6_fd = socket(address6->sin6_family, SOCK_STREAM, 0)) >= 0))
        {
            if((evutil_make_socket_nonblocking(v6_fd) < 0)) {
                evutil_closesocket(v6_fd);
                v6_fd = -1;
                snip_config_release(config);
                snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                               "Failed to set socket non-blocking (%s): %s.",
                               listener->bind_address_string,
                               strerror(errno)
                );
                return FALSE;
            }
            if(evutil_make_socket_closeonexec(v6_fd) < 0) {
                evutil_closesocket(v6_fd);
                v6_fd = -1;
                snip_config_release(config);
                snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                               "Failed to set socket to close on exec (%s): %s.",
                               listener->bind_address_string,
                               strerror(errno)
                );
                return FALSE;
            }
        }
        if(v6_fd < 0) {
            snip_config_release(config);
            snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                           "Failed to open IPv6 socket (%s): %s.",
                           listener->bind_address_string,
                           strerror(errno)
            );
            return FALSE;
        }
        // Ok, here's why do this dance.  We want our IPv6
        int no = 0;
        if(setsockopt(v6_fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0) {
            evutil_closesocket(v6_fd);
            v6_fd = -1;
            snip_config_release(config);
            snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                           "Failed to set IPv6 socket to v6 only (%s): %s.",
                           listener->bind_address_string,
                           strerror(errno)
            );
            return FALSE;
        }

        if(evutil_make_listen_socket_reuseable(v6_fd) < 0) {
            evutil_closesocket(v6_fd);
            v6_fd = -1;
            snip_config_release(config);
            snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                           "Failed to set IPv6 socket to v6 only (%s): %s.",
                           listener->bind_address_string,
                           strerror(errno)
            );
            return FALSE;
        }


        if(bind(v6_fd, (struct sockaddr *) &(listener->bind_address_6), (socklen_t) listener->bind_address_length_6) < 0) {
            evutil_closesocket(v6_fd);
            v6_fd = -1;
            snip_config_release(config);
            snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                           "Failed to set IPv6 socket to v6 only (%s): %s.",
                           listener->bind_address_string,
                           strerror(errno)
            );
            return FALSE;
        }

        listener->libevent_listener_6 = evconnlistener_new(context->event_base,
                                      snip_accept_incoming_cb,
                                      (void *) listener,
                                      LEV_OPT_DISABLED |  LEV_OPT_CLOSE_ON_FREE,
                                      -1,
                                      v6_fd);


        if (!listener->libevent_listener_6) {
            snip_config_release(config);
            snip_log_fatal(SNIP_EXIT_ERROR_SOCKET,
                           "Failed to bind IPv6 Socket (%s): %s.",
                           listener->bind_address_string,
                           strerror(errno)
            );
            return FALSE;
        }
        evconnlistener_set_error_cb(listener->libevent_listener_6, snip_accept_error_cb);
    }
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

    // We identify each connection with a 64-bit id.  To reduce  confusion between executions we randomize the initial.
    evutil_secure_rng_init();
    evutil_secure_rng_get_bytes(&(context->next_id), sizeof(context->next_id));

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

static void snip_sighup_handler(int signal, siginfo_t *info, void *ctx ) {
    snip_context_t *context = (snip_context_t *) ctx;
    snip_should_reload = 1;
}

void * snip_run_network(void *ctx)
{
    snip_context_t *context = (snip_context_t *) ctx;

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGQUIT);
    sigaddset(&sigset, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    //evsignal_new(context->event_base, SIGHUP, snip_sighup_handler, (void *) context);
    //evsignal_new(context->event_base, SIGINT, snip_sigint_handler, (void *) context);
    event_base_dispatch(context->event_base);
    return NULL;
}

/**
 * Given a pointer to an old listener configuration object, and a new one, copy the already bound socket from the old
 * to the new.
 * @param old_listener
 * @param new_listener
 */
void
snip_listener_replace(snip_config_listener_t *old_listener, snip_config_listener_t *new_listener) {
    new_listener->libevent_listener_4 = old_listener->libevent_listener_4;
    old_listener->libevent_listener_4 = NULL;
    new_listener->libevent_listener_6 = old_listener->libevent_listener_6;
    old_listener->libevent_listener_6 = NULL;
    memcpy(&(new_listener->bind_address_4), &(old_listener->bind_address_4), sizeof(struct sockaddr_storage));
    new_listener->bind_address_length_4 = old_listener->bind_address_length_4;
    memcpy(&(new_listener->bind_address_6), &(old_listener->bind_address_6), sizeof(struct sockaddr_storage));
    new_listener->bind_address_length_6 = old_listener->bind_address_length_6;
    if(new_listener->libevent_listener_4) {
        evconnlistener_set_cb(new_listener->libevent_listener_4, snip_accept_incoming_cb, new_listener);
    }
    if(new_listener->libevent_listener_6) {
        evconnlistener_set_cb(new_listener->libevent_listener_6, snip_accept_incoming_cb, new_listener);
    }
}

/**
 * Replace the existing configuration with an updated one.
 * @param fd
 * @param events
 * @param ctx
 */
void
snip_replace_config(evutil_socket_t fd, short events, void *ctx) {
    snip_config_t *new_config = (snip_config_t *) ctx;
    snip_context_t *context = new_config->context;
    snip_config_t *old_config = context->config; // May be NULL if this is the first config load.

    // TODO - do we need to futz with the dns_base?
    //int evdns_base_clear_nameservers_and_suspend(struct evdns_base *base);
    //int evdns_base_resume(struct evdns_base *base);

    // We have a new config. We compare the old config to the new one because we don't want to shutdown and then reopen
    // sockets.  We copy the old socket onto the new config.
    snip_config_listener_list_t *new_listener = new_config->listeners;
    snip_config_listener_list_t *old_listener;
    while(new_listener) {
        old_listener = old_config ? old_config->listeners : NULL;
        while(old_listener) {
            if(old_listener->value.libevent_listener_4 &&
               snip_listener_socket_is_equal(&(old_listener->value), &(new_listener->value)))
            {
                snip_listener_replace(&(old_listener->value), &(new_listener->value));
                break;
            }
            old_listener = old_listener->next;
        }
        if(!new_listener->value.libevent_listener_4) {
            // We're not already listening on this port/interface.  Start.
            snip_listen(context, new_config, &(new_listener->value));
        }
        new_listener = new_listener->next;
    }

    old_listener = old_config ? old_config->listeners : NULL;
    while(old_listener) {
        if(old_listener->value.libevent_listener_4) {
            evconnlistener_free(old_listener->value.libevent_listener_4);
            // We won't be accepting any new connections.  In-progress connections retain the config individually.
            snip_config_release(old_config);
            old_listener->value.libevent_listener_4 = NULL;
        }
        old_listener = old_listener->next;
    }

    // We can only drop privileges once.
    if(!context->dropped_privileges && new_config->user_id != -1) {
        if(!drop_privileges((uid_t) new_config->user_id, (gid_t) new_config->group_id)) {
            snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED, "Unable to drop privileges: (%d) %s", errno, strerror(errno));
            return;
        }
        context->dropped_privileges = TRUE;
    }

    new_listener = new_config->listeners;
    while(new_listener) {
        if(new_listener->value.socket_disabled) {
            if(new_listener->value.libevent_listener_4) {
                evconnlistener_enable(new_listener->value.libevent_listener_4);
            }
            if(new_listener->value.libevent_listener_6) {
                evconnlistener_enable(new_listener->value.libevent_listener_6);
            }
            new_listener->value.socket_disabled = FALSE;
        }
        new_listener = new_listener->next;
    }


    context->config = new_config;
    if(old_config) {
        snip_config_release(old_config);
    }
    snip_log(SNIP_LOG_LEVEL_INFO, "Successfully applied config from '%s'.", new_config->config_path);
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

    // Just test the config, don't actually launch the listeners.  If the config was invalid it would have exited with
    // a fatal log.
    if(new_config->just_test_config) {
        snip_log(SNIP_LOG_LEVEL_INFO, "Configuration looks good.");
        exit(EXIT_SUCCESS);
    }

    // Apply the config inside the event loop.
    event_base_once(context->event_base, -1, EV_TIMEOUT, snip_replace_config, (void *) new_config, NULL);
}


/**
 * Read the configuration and start handling requests.
 * @param[in,out] context
 */
void snip_run(snip_context_t *context)
{
    snip_reload_config(context, context->argc, context->argv);
    pthread_cond_init(&(context->work_for_main_thread), NULL);
    pthread_mutex_init(&(context->context_lock), NULL);
    pthread_mutex_lock(&(context->context_lock));

    snip_should_reload = 0;
    struct sigaction sighup_action;
    memset(&sighup_action, '\0', sizeof(struct sigaction));
    sighup_action.sa_sigaction = snip_sighup_handler;
    sighup_action.sa_flags = SA_SIGINFO;
    sigaction(SIGHUP, &sighup_action, NULL);

    pthread_create(&(context->event_thread), NULL, snip_run_network, (void *) context);
    while(1) {
        pthread_cond_wait(&(context->work_for_main_thread), &(context->context_lock));
        if(context->shutting_down) {
            break;
        }
        if(snip_should_reload) {
            snip_should_reload = 0;
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