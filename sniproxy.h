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

/**
 * Start listening a given port.
 * @param base - Event base.
 * @param port - TCP Port
 * @return LibEvent connection listener structure.
 */
struct evconnlistener *
snip_start_listening(struct event_base *base, uint16_t port);

#endif //SNIPROXY_SNIPROXY_H
