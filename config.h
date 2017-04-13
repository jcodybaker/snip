//
// Created by Cody Baker on 3/27/17.
//

#ifndef SNIP_CONFIG_H
#define SNIP_CONFIG_H

#include <stdint.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/listener.h>

#include "compat.h"

#ifdef __cplusplus
extern "C" {
#endif

// We want to keep the context anonymous to the outside.

typedef struct snip_config_route {
    const char *sni_hostname;
    const char *dest_hostname;
    uint16_t port;
} snip_config_route_t;

typedef struct snip_config_route_list {
    snip_config_route_t value;
    struct snip_config_route_list *next;
} snip_config_route_list_t;

typedef struct snip_config_listener_e {
    int ipv4;
    int ipv6;
    char bind_address_string[INET6_ADDRSTRLEN_WITH_PORT];
    struct sockaddr_storage bind_address_4;
    int bind_address_length_4;
    struct sockaddr_storage bind_address_6;
    int bind_address_length_6;
    uint16_t bind_port;

    snip_config_route_list_t *routes;
    snip_config_route_t *default_route;

    struct evconnlistener *libevent_listener_4;
    struct evconnlistener *libevent_listener_6;

    SNIP_BOOLEAN socket_disabled;

    struct snip_config_e *config;
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

    pthread_mutex_t lock;
    int references;

    long user_id;
    long group_id;

    SNIP_BOOLEAN ipv6_disabled;
    SNIP_BOOLEAN ipv4_disabled;

    SNIP_BOOLEAN just_test_config;

    struct snip_context_e *context;
} snip_config_t;



/**
 * Create a snip_config_t object.
 * @return
 */
snip_config_t *
snip_config_create();

/**
 * Increase the reference count on the snip_config.
 * @param config
 * @return - config parameter passed back so the "x = snip_config_retain(config);" pattern can be implemented.
 */
snip_config_t *
snip_config_retain(snip_config_t *config);

/**
 * Release and possibly free the reference count on the snip_config.
 * @param config
 */
void
snip_config_release(snip_config_t *config);

/**
 * Maps the SNI hostname into a destination route based upon configuration.
 * @param listener
 * @param sni_hostname[in]
 * @return
 */
snip_config_route_t *
snip_find_route_for_sni_hostname(snip_config_listener_t *listener, char *sni_hostname);

/**
 * Given a route, get the hostname. We include the sni_hostname to help resolve regex parameters.
 * @param route
 * @param sni_hostname
 * @return
 */
char *
snip_route_and_sni_hostname_to_target_hostname(snip_config_route_t *route, const char *sni_hostname);


/**
 * Read the configuration file and apply it to the specified config structure.
 * @param config[in,out]
 */
SNIP_BOOLEAN
snip_parse_config_file(snip_config_t *config);

/**
* Given a string of digits (ex. "12345") parse it into a port and set *port to the value.  It may NOT be prefaced or
*     suffixed by any extra characters, must be a valid 16-bit number, and must only contain digits.
* @param port_string[in] A NULL terminated string of at 1 to 5 digits.
* @param port[out] Pointer to a uint16_t where the port value should be stored.
* @return True if the port is valid and was parsed properly.  False otherwise.
*/
SNIP_BOOLEAN
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
SNIP_BOOLEAN
snip_parse_target(const char *target, const char **hostname, uint16_t *port);

/**
 * Parse the command line arguments and drop them into a configuration.
 * @param config[in,out]
 * @param argc[in]
 * @param argv[in]
 */
void
snip_config_parse_args(snip_config_t *config, int argc, char **argv);

/**
 * Given a pointer to an old listener configuration object, and a new one, copy the already bound socket from the old
 * to the new.
 * @param old_listener
 * @param new_listener
 */
void
snip_listener_replace(snip_config_listener_t *old_listener, snip_config_listener_t *new_listener);

/**
 * Compare two listener configurations to see if they're equal.  Order does not matter.
 * @param a
 * @param b
 * @return - True if the listeners would result in the same socket configuration, false otherwise.
 */
SNIP_BOOLEAN
snip_listener_socket_is_equal(snip_config_listener_t *a, snip_config_listener_t *b);


#ifdef __cplusplus
}
#endif

#endif //SNIP_CONFIG_H
