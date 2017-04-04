//
// Created by Cody Baker on 3/27/17.
//

#ifndef SNIPROXY_CONFIG_H
#define SNIPROXY_CONFIG_H
#include <stdint.h>
#include <event2/event.h>
#include <event2/dns.h>

#define SNIPROXY


struct snip_route {
    char *sni_hostname;
    char *dest_hostname;
    uint16_t port;
};

struct snip_route_list {
    struct snip_route value;
    struct snip_route_list *next;
};


struct snip_config_listener {
    int ipv4;
    int ipv6;
    char *bind_addr;
    uint16_t bind_port;

    struct snip_route_list *routes;
    struct snip_route *default_route;
};

struct snip_config_listener_list {
    struct snip_config_listener value;
    struct snip_config_listener_list *next;
};

struct snip_config {
    const char *config_path;

    struct snip_config_listener_list *listeners;

    struct snip_route_list *routes;
    struct snip_route *default_route;
};


/**
 * Maps the SNI hostname into a destination hostname based upon configuration.
 * @param sni_hostname
 * @return
 */
char *
snip_get_target_hostname_from_sni_hostname(char *sni_hostname);

/**
 * Reload the configuration file asynchronously.
 * @param event_base
 * @param argc - argument count from the command line.  If this is being built into another package, this can be 0
 *      provided the default config location is sufficient.
 * @param argv - argument strings from the command line.  If this is being build into another package, this can be NULL
 *      provided the default config location is sufficient.
 */
void
snip_reload_config(struct event_base *event_base, int argc, char **argv);

#endif //SNIPROXY_CONFIG_H
