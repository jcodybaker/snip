//
// Created by Cody Baker on 3/16/17.
//

#ifndef SNIPROXY_SNIPROXY_H
#define SNIPROXY_SNIPROXY_H

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


#ifdef __cplusplus
extern "C" {
#endif

// We want to keep the context anonymous to the outside.
typedef struct snip_context_e * snip_context_ptr_t;

/**
 * Create the snip_context object.
 * @return
 */
snip_context_ptr_t
snip_context_create();

/**
 * Initialize the context, with event bases and the like.
 */
void
snip_context_init(snip_context_ptr_t context, int argc, char **argv);

/**
 * Read the configuration and start handling requests.
 * @param[in,out] context
 */
void
snip_run(snip_context_ptr_t context);

#ifdef __cplusplus
}
#endif

#endif //SNIPROXY_SNIPROXY_H
