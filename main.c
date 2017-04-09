#include <stdio.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <signal.h>

#include "snip.h"
#include "config.h"

int main(int argc, char **argv) {
    snip_context_ptr_t context = snip_context_create();
    snip_context_init(context, argc, argv);
    snip_run(context);
    return 0;
}

