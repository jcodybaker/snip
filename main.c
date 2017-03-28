#include <stdio.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <signal.h>

#include "sniproxy.h"
#include "config.h"

int main(int argc, char **argv) {

    struct snip_context *context = snip_context_create();
    snip_context_init(context, argc, argv);

    context.hup_event = evsignal_new(context.event_base, SIGHUP, snip_reload, NULL);

    snip_start_listening(base, 8080);
    event_base_dispatch(base);

    return 0;
}

