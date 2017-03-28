//
// Created by Cody Baker on 3/27/17.
//

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char *
snip_get_target_hostname_from_sni_hostname(char *sni_hostname) {
    return "www.google.com";
}

struct snip_config *
snip_config_create() {
    struct snip_config *config = malloc(sizeof(struct snip_config));
    memset(config, '\0', sizeof(struct snip_config));
    return config;
}

void snip_config_parse_args(struct snip_config *config, int argc, char **argv) {

}

/**
 * Reload the configuration file asynchronously.
 * @param event_base
 * @param argc - argument count from the command line.  If this is being built into another package, this can be 0
 *      provided the default config location is sufficient.
 * @param argv - argument strings from the command line.  If this is being build into another package, this can be NULL
 *      provided the default config location is sufficient.
 */
void
snip_reload_config(struct event_base *event_base, int argc, char **argv) {
    struct snip_config *config = snip_config_create();
    if(argc && argv) {
        snip_config_parse_args(config, argc, argv);
    }
    if(!config->config_path) {
        config->config_path = SNIP_INSTALL_CONF_PATH;
    }


    //int evdns_base_clear_nameservers_and_suspend(struct evdns_base *base);
    //int evdns_base_resume(struct evdns_base *base);
}
