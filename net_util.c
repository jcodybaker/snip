//
// Created by Cody Baker on 4/12/17.
//

#include <event2/util.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "net_util.h"
#include "compat.h"

/**
 * Convert a struct sockaddr to a string of the form "1.2.3.4:443" or its ipv6 equivilent.
 * @param buffer - Buffer for storing the resulting string.  MUST be atleast INET6_ADDRSTRLEN_WITH_PORT.
 * @param address
 * @return
 */
int
snip_sockaddr_to_string(char *buffer, struct sockaddr *address) {
    char target_string[INET6_ADDRSTRLEN_WITH_PORT];
    const char *ntop_result;
    uint16_t port;
    if(address->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) address;
        port = ntohs(sin->sin_port);
        ntop_result = evutil_inet_ntop(address->sa_family,
                                       (const void *) &(sin->sin_addr),
                                       target_string,
                                       INET6_ADDRSTRLEN_WITH_PORT
        );
    }
    else if(address->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) address;
        port = ntohs(((struct sockaddr_in6 *) address)->sin6_port);
        ntop_result = evutil_inet_ntop(address->sa_family,
                                       (const void *) &(sin6->sin6_addr),
                                       target_string,
                                       INET6_ADDRSTRLEN_WITH_PORT
        );
    }
    else {
        return -1;
    }
    if(!ntop_result) {
        return -1;
    }
    int string_result = snprintf(buffer,
                                 INET6_ADDRSTRLEN_WITH_PORT,
                                 address->sa_family == AF_INET6 ? "[%s]:%hu" : "%s:%hu",
                                 target_string,
                                 port);
    if(string_result <= 0 || (string_result + 1) > INET6_ADDRSTRLEN_WITH_PORT) {
        return -1;
    }
    return string_result;
}