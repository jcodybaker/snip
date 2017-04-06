//
// Created by Cody Baker on 3/19/17.
//

#ifndef SNIPROXY_COMPAT_H
#define SNIPROXY_COMPAT_H

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

#ifndef SNIPROXY_BOOLEAN
#define SNIPROXY_BOOLEAN int
#endif

#endif //SNIPROXY_COMPAT_H
