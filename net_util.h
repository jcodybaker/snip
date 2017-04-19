// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#ifndef SNIP_NET_UTIL_H
#define SNIP_NET_UTIL_H
#include <sys/socket.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Convert a struct sockaddr to a string of the form "1.2.3.4:443" or its ipv6 equivilent.
 * @param buffer - Buffer for storing the resulting string.  MUST be atleast INET6_ADDRSTRLEN_WITH_PORT.
 * @param address
 * @return
 */
int
snip_sockaddr_to_string(char *buffer, struct sockaddr *address);

#ifdef __cplusplus
}
#endif

#endif //SNIP_NET_UTIL_H
