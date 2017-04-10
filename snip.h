//
// Created by Cody Baker on 3/16/17.
//

#ifndef SNIP_SNIP_H
#define SNIP_SNIP_H

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

/**
 * Open a socket and start listening for new connections based upon a configuration object.
 * @param context
 * @param listener
 * @return
 */
SNIP_BOOLEAN
snip_listen(snip_context_ptr_t context, snip_config_listener_t *listener);

/**
 * Reload the configuration file asynchronously.
 * @param context
 * @param argc - argument count from the command line.  If this is being built into another package, this can be 0
 *      provided the default config location is sufficient.
 * @param argv - argument strings from the command line.  If this is being build into another package, this can be NULL
 *      provided the default config location is sufficient.
 */
void
snip_reload_config(snip_context_ptr_t context, int argc, char **argv);


#ifdef __cplusplus
}
#endif

#endif //SNIP_SNIP_H
