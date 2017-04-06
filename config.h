//
// Created by Cody Baker on 3/27/17.
//

#ifndef SNIPROXY_CONFIG_H
#define SNIPROXY_CONFIG_H

#include <stdint.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "compat.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct snip_config_route {
    char *sni_hostname;
    char *dest_hostname;
    uint16_t port;
} snip_config_route_t;

typedef struct snip_config_route_list {
    snip_config_route_t value;
    struct snip_config_route_list *next;
} snip_config_route_list_t;

typedef struct snip_config_listener_e {
    int ipv4;
    int ipv6;
    char *bind_addr;
    uint16_t bind_port;

    snip_config_route_list_t *routes;
    snip_config_route_t *default_route;
} snip_config_listener_t;

typedef struct snip_config_listener_list_e {
    snip_config_listener_t value;
    struct snip_config_listener_list_e *next;
} snip_config_listener_list_t;

typedef struct snip_config_e {
    const char *config_path;

    snip_config_listener_list_t *listeners;

    snip_config_route_list_t *routes;
    snip_config_route_t *default_route;
} snip_config_t;

/**
 * Create a snip_config_t object.
 * @return
 */
snip_config_t *
snip_config_create();

/**
 * Maps the SNI hostname into a destination hostname based upon configuration.
 * @param sni_hostname[in]
 * @return
 */
char *
snip_get_target_hostname_from_sni_hostname(char *sni_hostname);

/**
 * Reload the configuration file asynchronously.
 * @param event_base[in,out]
 * @param argc[in] - argument count from the command line.  If this is being built into another package, this can be 0
 *      provided the default config location is sufficient.
 * @param argv[in] - argument strings from the command line.  If this is being build into another package, this can be NULL
 *      provided the default config location is sufficient.
 */
void
snip_reload_config(struct event_base *event_base, int argc, char **argv);

/**
 * Read the configuration file and apply it to the specified config structure.
 * @param config[in,out]
 */
SNIPROXY_BOOLEAN
snip_parse_config_file(snip_config_t *config);

/**
* Given a string of digits (ex. "12345") parse it into a port and set *port to the value.  It may NOT be prefaced or
*     suffixed by any extra characters, must be a valid 16-bit number, and must only contain digits.
* @param port_string[in] A NULL terminated string of at 1 to 5 digits.
* @param port[out] Pointer to a uint16_t where the port value should be stored.
* @return True if the port is valid and was parsed properly.  False otherwise.
*/
SNIPROXY_BOOLEAN
snip_parse_port(const char *port_string, uint16_t *port);

/**
 * Given a string of format "www.example.com:12345", parse the hostname and port, and allocate a new string for the
 * separated hostname.
 *
 * @param target[in] - A target string of the format "www.example.com:12345" or "www.example.com".
 * @param hostname[out] - A place where we can store a pointer to the hostname string.
 * @param port[out] - Address where we can store the port.  We set 0 if the port isn't specified.
 * @return true (1) if the parse was successful, false (0) otherwise.
 */
SNIPROXY_BOOLEAN
snip_parse_target(const char *target, char **hostname, uint16_t *port);

/**
 * Parse the command line arguments and drop them into a configuration.
 * @param config[in,out]
 * @param argc[in]
 * @param argv[in]
 */
void
snip_config_parse_args(snip_config_t *config, int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif //SNIPROXY_CONFIG_H
