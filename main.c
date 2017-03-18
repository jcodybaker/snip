#include <stdio.h>
#include <event2/event.h>
#include <signal.h>

#include "sniproxy.h"


int main() {

    struct event *hup_event;

    struct event_base *base = event_base_new();
    //hup_event = evsignal_new(base, SIGHUP, snip_reload, NULL);
    snip_start_listening(base, 8080);
    event_base_dispatch(base);

    return 0;
}

