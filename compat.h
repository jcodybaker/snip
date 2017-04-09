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

#endif //SNIP_COMPAT_H
