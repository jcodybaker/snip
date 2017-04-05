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

#include "config.h"
#include "compat.h"
#include "sniproxy.h"
#include "tls.h"

#include <pthread.h>


const struct timeval snip_shutdown_timeout = {5, 0};

struct snip_context {
    struct snip_config *config;
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
    snip_pair_state_error_connect_failed

};

typedef struct snip_pair {
    struct bufferevent *client_bev;

    enum snip_pair_state state;
    size_t current_record_start;
    uint16_t current_record_length;
    uint32_t current_message_length;

    struct evbuffer *handshake_buffer;

    evutil_socket_t client_fd;
    struct sockaddr_storage client_address; // Hold the address locally in this structure.
    size_t client_address_len;

    char *target_hostname;
    evutil_socket_t target_fd;
    struct sockaddr_storage target_address; // Hold the address locally in this structure.
    size_t target_address_len;

    uint16_t sni_hostname_length;
    char *sni_hostname;

    int references;

    struct snip_TLS_version client_version;
} snip_pair;

/**
 * Create an snip_client record.
 * @return
 */
snip_pair *
snip_client_create() {
    snip_pair *client = (snip_pair *) malloc(sizeof(snip_pair));
    memset(client, '\0', sizeof(snip_pair));
    return client;
}

/**
 * Increase the reference count on the snip_pair.
 * @param client
 */
void
snip_client_retain(
        snip_pair *client
) {
    client->references += 1;
}

/**
 * Release, and if appropriate cleanup/free a snip_client record.
 * @param client
 */
void
snip_client_release(
        snip_pair *client
) {
    client->references -=1;
    if(!client->references) {
        // These are malloc'ed by libevent's evbuffer_readln function.
        if(client->target_hostname) {
            free(client->target_hostname);
        }
        free(client);
    }
}

/**
 * Get the length of data held in the handshake buffer.
 * @param client
 * @return
 */
size_t
snip_get_handshake_buffer_length(snip_pair *client) {
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
snip_get_handshake_buffer(snip_pair *client, struct evbuffer *input, size_t pullup, size_t *available) {
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
 * Handle incoming data on the client-connection.
 * @param bev
 * @param ctx
 */
static void
client_read_cb(
        struct bufferevent *bev,
        void *ctx
) {
    // Initially we're just peeking on the request, so we don't remove anything from the input buffer until we
    // understand where the client is trying to get, and have connected to their ultimate destination.
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    snip_pair *client = (snip_pair *) ctx;
    size_t available_input = evbuffer_get_length(input);
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
                buffer = evbuffer_pullup(input, client->current_record_start + SNIP_TLS_RECORD_HEADER_LENGTH);

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
                        input,
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
                            client, input, SNIP_TLS_HANDSHAKE_HEADER_LENGTH, &available_handshake);
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
                        client, input, client->current_message_length, &available_handshake);
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

                                printf("SNI: (%d) %s\n", client->sni_hostname_length, client->sni_hostname);
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

                break;
            case snip_pair_state_waiting_for_dns:
                break;
            case snip_pair_state_waiting_for_connect:
                break;
            case snip_pair_state_proxying:
                break;
            case snip_pair_state_sni_not_found:
                break;
            case snip_pair_state_error_dns_failed:
                break;
            case snip_pair_state_error_connect_failed:
                break;
            case snip_pair_state_error_not_tls:
                // So it looks like this isn't TLS, or at least isn't a version we know.  It may be that the client
                // connected with HTTP, in which case we can at least provide a helpful error. Apache does something
                // similar.
                buffer = evbuffer_pullup(input, 5);
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
    }
    if(!client->target_hostname) {
        // We don't know the target_hostname yet, so we're trying to read the first line. If we don't have an EOL, let our input
        // buffer keep growing.
        // TODO - We should set a limit on how large we'll let the buffer grow.
        // TODO - This will ultimately be switched to inspect the SNI, but lets avoid that complexity now.

        char buffer[8];

//        struct evbuffer_ptr eol_at = evbuffer_search_eol(input, NULL, NULL, EVBUFFER_EOL_CRLF);
//        if(eol_at.pos != -1) {
//            // Read in the target_hostname.
//            client->target_hostname = evbuffer_readln(input,NULL, EVBUFFER_EOL_CRLF);
//            // TODO - Validate the target_hostname.
//            printf("Got target: %s\n", client->target_hostname);
//        }
    }
    else {

    }

    /* Copy all the data from the input buffer to the output buffer. */
    evbuffer_add_buffer(output, input);
}

/**
 * Handle disconnections and errors on the client channel.
 * @param bev
 * @param events
 * @param ctx
 */
static void
client_event_cb(
        struct bufferevent *bev,
        short events,
        void *ctx
) {
    snip_pair *client = (snip_pair *) ctx;
    if (events & BEV_EVENT_ERROR)
        perror("Error from bufferevent");
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
        client->client_bev = NULL;
        snip_client_release(client);  // The target may still be out there.
    }
}

/**
 * Called when a new connection happens on the listener.
 * @param listener
 * @param fd
 * @param address
 * @param socklen
 * @param ctx
 */
static void
snip_accept_incoming_cb(
        struct evconnlistener *listener,
        evutil_socket_t fd,
        struct sockaddr *address,
        int socklen,
        void *ctx
) {
    struct event_base *base = evconnlistener_get_base(listener);

    // Save it all to the pair
    snip_pair *client = snip_client_create();
    client->client_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(client->client_bev, client_read_cb, NULL, client_event_cb, (void *) client);

    memcpy((struct sockaddr *) &(client->client_address), address, socklen);
    client->client_address_len = (size_t) socklen;
    client->client_fd = fd;

    // Set it ready
    bufferevent_enable(client->client_bev, EV_READ|EV_WRITE);
}

/**
 * Handle an error on the connection listener.
 * @param listener
 * @param ctx
 */
static void
snip_accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    // TODO - Should do something better than this.
    fprintf(stderr, "Got an error %d (%s) on the listener. "
            "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}
//
//
//static void
//snip_stop_listening(struct evconnlistener *listener) {
//
//}

/**
 * Start listening a given port.
 * @param base - Event base.
 * @param port - TCP Port
 * @return LibEvent connection listener structure.
 */
struct evconnlistener *
snip_start_listening(struct event_base *base, uint16_t port) {
    struct evconnlistener *listener;
    struct sockaddr_in sin;

    /* Clear the sockaddr before using it, in case there are extra
     * platform-specific fields that can mess us up. */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0);
    sin.sin_port = htons(port);

    listener = evconnlistener_new_bind(base, snip_accept_incoming_cb, NULL,
                                       LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
                                       (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return NULL;
    }
    evconnlistener_set_error_cb(listener, snip_accept_error_cb);
    return listener;
}

/**
 * Create the snip_context object.
 * @return
 */
struct snip_context *
snip_context_create() {
    struct snip_context *context = malloc(sizeof(struct snip_context));
    memset(context, '\0', sizeof(struct snip_context));
    return context;
}

/**
 * Initialize the context, with event bases and the like.
 */
void
snip_context_init(struct snip_context *context, int argc, char **argv) {
    context->argc = argc;
    context->argv = argv;
    // right now we only support pthreads.  Windows threads are TODO.
    evthread_use_pthreads();
    context->event_base = event_base_new();
    context->dns_base = evdns_base_new(context->event_base, 1);

}


void snip_stop(struct snip_context *context) {
    context->shutting_down = 1;
    event_base_loopexit(context->event_base, &snip_shutdown_timeout);

}

void snip_sigint_handler(evutil_socket_t fd, short events, void *arg) {
    struct snip_context *context = (struct snip_context *) arg;
    if(context->shutting_down) {
        snip_stop(context);
    }
}

void snip_sighup_handler(evutil_socket_t fd, short events, void *arg) {
    struct snip_context *context = (struct snip_context *) arg;
    pthread_mutex_lock(&(context->context_lock));
    if(!context->pending_reload) {
        context->pending_reload = 1;
        pthread_cond_signal(&(context->work_for_main_thread));
        pthread_mutex_unlock(&(context->context_lock));
    }
}

void * snip_run_network(void *ctx)
{
    struct snip_context *context = (struct snip_context *) ctx;
    evsignal_new(context->event_base, SIGHUP, snip_sighup_handler, (void *) context);
    evsignal_new(context->event_base, SIGINT, snip_sigint_handler, (void *) context);
    event_base_dispatch(context->event_base);
    return NULL;
}

/**
 * Read the configuration and start handling requests.
 * @param[in,out] context
 */
void snip_run(struct snip_context *context)
{
    snip_reload_config(context->event_base, context->argc, context->argv);
    pthread_cond_init(&(context->work_for_main_thread), NULL);
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
            snip_reload_config(context->event_base, context->argc, context->argv);
            pthread_mutex_lock(&(context->context_lock));
        }
    }
    pthread_join(context->event_thread, NULL);
    pthread_mutex_unlock(&(context->context_lock));
    pthread_mutex_destroy(&(context->context_lock));
    pthread_cond_destroy(&(context->work_for_main_thread));
}

