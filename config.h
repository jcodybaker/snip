//
// Created by Cody Baker on 3/27/17.
//

#ifndef SNIPROXY_CONFIG_H
#define SNIPROXY_CONFIG_H
#include <stdint.h>
#include <event2/event.h>
#include <event2/dns.h>

#ifdef __cplusplus
extern "C" {
#endif


struct snip_config_route {
    char *sni_hostname;
    char *dest_hostname;
    uint16_t port;
};

struct snip_config_route_list {
    struct snip_config_route value;
    struct snip_config_route_list *next;
};


struct snip_config_listener {
    int ipv4;
    int ipv6;
    char *bind_addr;
    uint16_t bind_port;

    struct snip_config_route_list *routes;
    struct snip_config_route *default_route;
};

struct snip_config_listener_list {
    struct snip_config_listener value;
    struct snip_config_listener_list *next;
};

struct snip_config {
    const char *config_path;

    struct snip_config_listener_list *listeners;

    struct snip_config_route_list *routes;
    struct snip_config_route *default_route;
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

/**
 * Given a string of format "www.example.com:12345", parse the hostname and port, and allocate a new string for the
 * separated hostname.
 *
 * @param target[in] - A target string of the format "www.example.com:12345" or "www.example.com".
 * @param target_length[in] - The length in bytes of the target string.
 * @param hostname[out] - A place where we can store a pointer to the hostname string.
 * @param port[out] - Address where we can store the port.  We set 0 if the port isn't specified.
 * @return true (1) if the parse was successful, false (0) otherwise.
 */
int
snip_parse_target(const char *target, size_t target_length, char **hostname, uint16_t *port);

#ifdef __cplusplus
}
#endif

#endif //SNIPROXY_CONFIG_H
