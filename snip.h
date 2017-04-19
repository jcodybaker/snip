// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

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
typedef struct snip_context_e * snip_context_ref_t;

/**
 * Create the snip_context object.
 * @return
 */
snip_context_ref_t
snip_context_create();

/**
 * Initialize the context, with event bases and the like.
 */
void
snip_context_init(snip_context_ref_t context, int argc, char **argv);

/**
 * Read the configuration and start handling requests.
 * @param[in,out] context
 */
void
snip_run(snip_context_ref_t context);

#ifdef __cplusplus
}
#endif

#endif //SNIP_SNIP_H
