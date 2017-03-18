//
// Created by Cody Baker on 3/16/17.
//

#include <event2/event.h>

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

#include "sniproxy.h"

typedef struct snip_pair {
    struct bufferevent *client_bev;

    evutil_socket_t client_fd;
    struct sockaddr_storage client_address; // Hold the address locally in this structure.
    size_t client_address_len;

    char *target_hostname;
    evutil_socket_t target_fd;
    struct sockaddr_storage target_address; // Hold the address locally in this structure.
    size_t target_address_len;

    int references;
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
 * Handle incoming data on the client-connection.
 * @param bev
 * @param ctx
 */
static void
client_read_cb(
        struct bufferevent *bev,
        void *ctx
) {
    /* This callback is invoked when there is data to read on bev. */
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    snip_pair *client = (snip_pair *) ctx;
    if(!client->target_hostname) {
        // We don't know the target_hostname yet, so we're trying to read the first line. If we don't have an EOL, let our input
        // buffer keep growing.
        // TODO - We should set a limit on how large we'll let the buffer grow.
        // TODO - This will ultimately be switched to inspect the SNI, but lets avoid that complexity now.
        struct evbuffer_ptr eol_at = evbuffer_search_eol(input, NULL, NULL, EVBUFFER_EOL_CRLF);
        if(eol_at.pos != -1) {
            // Read in the target_hostname.
            client->target_hostname = evbuffer_readln(input,NULL, EVBUFFER_EOL_CRLF);
            // TODO - Validate the target_hostname.
            printf("Got target: %s\n", client->target_hostname);
        }
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
