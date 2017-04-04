#include <stdio.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <signal.h>

#include "sniproxy.h"
#include "config.h"

int main(int argc, char **argv) {

    struct snip_context *context = snip_context_create();
    snip_context_init(context, argc, argv);
    snip_run(context);
    return 0;
}

