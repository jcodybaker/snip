//
// Created by Cody Baker on 3/19/17.
//

#ifndef SNIP_COMPAT_H
#define SNIP_COMPAT_H

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef SNIP_BOOLEAN
#define SNIP_BOOLEAN int
#endif
// IPv6 addresses get [] around the literal ip when a port is specified.  This keeps the port separate.
// INET6_ADDRSTRLEN is 46 bytes, [] 2, colon separator 1, 5 bytes for the port, and 1 for the null terminator
#define INET6_ADDRSTRLEN_WITH_PORT 54

#ifndef SHUT_RD
// Windows defines SD_RECEIVE instead of SHUT_RD, values are the same though.
#ifdef SD_RECEIVE
#define SHUT_RD SD_RECEIVE
#endif
#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#endif

#ifndef SHUT_WR
// Windows defines SD_SEND instead of SHUT_WR, values are the same though.
#ifdef SD_SEND
#define SHUT_WR SD_SEND
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#endif

#ifndef SHUT_RDWR
// Windows defines SHUT_BOTH instead of SHUT_RDWR, values are the same though.
#ifdef SHUT_BOTH
#define SHUT_RDWR SHUT_BOTH
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif
#endif

#endif //SNIP_COMPAT_H
