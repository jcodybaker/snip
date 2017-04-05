//
// Created by Cody Baker on 3/27/17.
//

#include "config.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <pthread.h>
#include <yaml.h>
#include <event2/util.h>


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

struct snip_config_listener_list *
snip_config_listener_list_create() {
    struct snip_config_listener_list *list = malloc(sizeof(struct snip_config_listener_list));
    memset(list, '\0', sizeof(struct snip_config_listener_list));
    return list;
}

/**
 * Recursively destroy a list of snip_config_listeners.
 * @param list
 */
void
snip_config_listener_list_destroy(struct snip_config_listener_list *list) {
    if(list->next) {
        snip_config_listener_list_destroy(list->next);
    }
    free(list);
}

/**
 * Allocate and initialize a new snip_config_route object.
 * @return The new struct snip_config_route_list *
 */
struct snip_config_route_list *
snip_config_route_list_create() {
    struct snip_config_route_list *route_list = malloc(sizeof(struct snip_config_route_list));
    memset(route_list, '\0', sizeof(struct snip_config_route_list));
    return route_list;
}

/**
 * Cleanup and free a struct snip_config_route_list object.
 * @param route_list
 */
void
snip_config_route_list_destroy(struct snip_config_route_list *route_list) {
    if(route_list->next) {
        snip_config_route_list_destroy(route_list->next);
    }
    free(route_list->value.dest_hostname);
    free(route_list->value.sni_hostname);
    free(route_list);
}

/**
 * Display the help information and exit the application.
 * @param name - The name of the command.
 */
void snip_config_display_help_and_exit(const char *name) {
    const char *better_name = strrchr(name, '/') == NULL ? name : strrchr(name, '/') + 1;
    printf(
            "snip - TLS SNI Proxy v%s\n"
                    "\n"
                    "usage: %s [arguments]\n"
                    "\n"
                    "Arguments:\n"
                    "   -c FILE, --conf FILE       Specify an alternative config file.\n"
                    "                              Default: %s\n"
                    "   -h, --help                 Display this help message.\n"
                    "\n",
            SNIP_VERSION,
            better_name,
            SNIP_INSTALL_CONF_PATH
    );
    exit(0);
}

void snip_config_parse_args(struct snip_config *config, int argc, char **argv) {
    int index = 0;
    int rv = 0;
    const struct option arguments[] = {
            {
                    "conf",
                    required_argument,
                    NULL,
                    'c'
            },
            {
                    "help",
                    no_argument,
                    NULL,
                    'h'
            },
            {
                    0,
                    0,
                    0,
                    0
            }
    };

    do {
        rv = getopt_long(argc, argv, "c:h", arguments, &index);
        const struct option *found = arguments + index;
        switch(rv) {
            case 'c':
                config->config_path = optarg;
                break;
            case 'h':
                snip_config_display_help_and_exit(argc ? argv[0] : "sniproxy");
                break;
            case -1:
                break;
            default:
                printf("Unknown parameter %d\n", rv);
                break;
        }
    } while (rv >= 0);
}

/**
 * Log a configuration event with location references within the configuration file.
 * @param config
 * @param event
 * @param level - Log severity level.  If SNIPROXY_LOG_LEVEL_FATAL, we will shutdown and exit.
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with variadic arguments provided in args.
 * @param ... - List of arguments for populating the format string msg_format.
 */
void
snip_log_config(struct snip_config *config, yaml_event_t *event, snip_log_level_t level, const char *msg_format, ...) {
    const char *config_error_msg = "%s in configuration file '%s' between %d:%d and %d:%d.";
    size_t buffer_max = 1 + (size_t) evutil_snprintf(NULL,
                                        0,
                                        config_error_msg,
                                        msg_format,
                                        config->config_path,
                                        event->start_mark.line,
                                        event->start_mark.column,
                                        event->end_mark.line,
                                        event->end_mark.column);
    char *buffer = malloc(buffer_max);
    evutil_snprintf(NULL,
                    0,
                    config_error_msg,
                    msg_format,
                    config->config_path,
                    event->start_mark.line,
                    event->start_mark.column,
                    event->end_mark.line,
                    event->end_mark.column);
    va_list args;
    va_start(args, msg_format);
    if(level == SNIPROXY_LOG_LEVEL_FATAL) {
        snip_vlog_fatal(SNIPROXY_EXIT_ERROR_INVALID_CONFIG, buffer, args);
    }
    else {
        snip_vlog(level, buffer, args);
    }
    va_end(args);
    free(buffer);
}

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
snip_parse_target(const char *target, size_t target_length, char **hostname, uint16_t *port) {
    *hostname = NULL;
    char *colon = strchr(target, ':');
    size_t hostname_length;
    if(colon) {
        hostname_length = colon - target;

        char *port_start = colon + 1;
        char *port_end = port_start;

        while(1) {
            if((port_end - port_start) > 5) {
                return 0;
            }
            if(*port_end == '\0') {
                break;
            }
            if((*port_end < '0') || (*port_end > '9')) {
                return 0; // Return false if the port contains a non-digit character.
            }
            port_end += 1;
        }
        if(port_start == port_end) {
            // A colon was found, but no port was found after it.
            return 0;
        }
        unsigned long port_ul = strtoul(port_start, NULL, 10);
        if(port_ul > 0xFFFF) { // port must be a 16-bit number.
            return 0;
        }
        *port = (uint16_t) port_ul;

        *hostname = malloc(hostname_length + 1);
        memset(*hostname, '\0', hostname_length + 1);
        memcpy(*hostname, target, hostname_length);
        return 1;
    }
    else {
        hostname_length = strlen(target) + 1;
        *hostname = malloc(hostname_length);
        strcpy(*hostname, target);
        *port = 0;
        return 1;
    }
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

    FILE *config_file = fopen(config->config_path, "r");
    if(!config_file) {
        snip_log_fatal(SNIPROXY_EXIT_ERROR_INVALID_CONFIG, "Could not read config file '%s'.", config->config_path);
        return;
    }

    yaml_parser_t parser;
    yaml_event_t event;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, config_file);


    typedef enum snip_config_parse_state_e {
        snip_config_parse_state_initial = 0,
        snip_config_parse_state_root_map,

        snip_config_parse_state_routes_rvalue,
        snip_config_parse_state_routes_list,
        snip_config_parse_state_routes_map,
        snip_config_parse_state_routes_map_value,

        snip_config_parse_state_skipping_unexpected_key_value,
        // Right now we always treat these as fatal errors, but we might change the behavior for SIGHUP config reloads.
        snip_config_parse_state_error,

        snip_config_parse_state_listener_rvalue,
        snip_config_parse_state_listener_in_list,
        snip_config_parse_state_listener_item_map
    } snip_config_parse_state_t;
    
    snip_config_parse_state_t state = snip_config_parse_state_initial;
    snip_config_parse_state_t state_after_skip;

    struct snip_config_listener_list *current_listener_item = NULL;
    struct snip_config_route_list *current_route_item = NULL;

    while(1) {
        switch(event.type) {
            case YAML_NO_EVENT:
                printf("YAML_NO_EVENT\n");
                break;
            case YAML_STREAM_START_EVENT:
                printf("YAML_STREAM_START_EVENT - %d\n", event.data.stream_start.encoding);
                break;
            case YAML_DOCUMENT_START_EVENT:
                printf("YAML_DOCUMENT_START_EVENT\n");
                break;
            case YAML_ALIAS_EVENT:
                printf("YAML_ALIAS_EVENT\n");
                break;
            case YAML_SCALAR_EVENT:
                printf("YAML_SCALAR_EVENT");
                if(event.data.scalar.tag) {
                    printf(" tag: '%s'", event.data.scalar.tag);
                }
                if(event.data.scalar.value) {
                    printf(" value: '%s'", event.data.scalar.value);
                }
                puts("");
                break;
            case YAML_SEQUENCE_START_EVENT:
                printf("YAML_SEQUENCE_START_EVENT\n");
                break;
            case YAML_SEQUENCE_END_EVENT:
                printf("YAML_SEQUENCE_END_EVENT\n");
                break;
            case YAML_MAPPING_START_EVENT:
                printf("YAML_MAPPING_START_EVENT\n");
                break;
            case YAML_MAPPING_END_EVENT:
                printf("YAML_MAPPING_END_EVENT\n");
                break;
            case YAML_DOCUMENT_END_EVENT:
                printf("YAML_DOCUMENT_END_EVENT\n");
                return;
            case YAML_STREAM_END_EVENT:
                printf("YAML_STREAM_END_EVENT\n");
                return;
        }

        // We skip unknown keys (though we do warn).  If the associated value is a map or sequence we need to discard
        // all children until we complete that value.
        int current_depth = 0;
        int skip_rvalue_depth = 0; // This gets set when we enter the skip state.
        if(event.type == YAML_SEQUENCE_START_EVENT || event.type == YAML_MAPPING_START_EVENT) {
            current_depth += 1;
        }
        else if (event.type == YAML_SEQUENCE_END_EVENT || event.type == YAML_MAPPING_END_EVENT) {
            current_depth -= 1;
        }

        if(state == snip_config_parse_state_initial)
        {
            if(event.type == YAML_MAPPING_START_EVENT) {
                state = snip_config_parse_state_root_map;
            }
            else if ((event.type == YAML_MAPPING_END_EVENT) ||
                     (event.type == YAML_SEQUENCE_START_EVENT) ||
                     (event.type == YAML_SEQUENCE_END_EVENT))
            {
                snip_log_config(config, &event, SNIPROXY_LOG_LEVEL_FATAL, "The root element must be a key/value map ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_root_map) {
            if(event.type == YAML_SCALAR_EVENT) {
                if(!strcmp((const char *) event.data.scalar.value, "listeners")) {
                    state = snip_config_parse_state_listener_rvalue;
                }
                else {
                    // We don't recognize this key. We log it as a warning, and make plans to skip the associated value.
                    state = snip_config_parse_state_skipping_unexpected_key_value;
                    skip_rvalue_depth = current_depth;
                    state_after_skip = state;
                    snip_log_config(config,
                                    &event,
                                    SNIPROXY_LOG_LEVEL_WARNING,
                                    "Unexpected key '%s' ",
                                    event.data.scalar.value
                    );
                }
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config, &event, SNIPROXY_LOG_LEVEL_FATAL, "Key had unexpected type ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listener_rvalue) {
            if(event.type == YAML_SEQUENCE_START_EVENT) {
                state = snip_config_parse_state_listener_in_list;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config, &event, SNIPROXY_LOG_LEVEL_FATAL, "'listeners' section was not a list ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listener_in_list) {
            if(event.type == YAML_MAPPING_START_EVENT) {
                // Ok, time to create a new listener.
                current_listener_item = snip_config_listener_list_create();
                if(!config->listeners) {
                    config->listeners = current_listener_item;
                }
                else {
                    // We want the new listener at the end;
                    struct snip_config_listener_list *listener_item = config->listeners;

                    while(listener_item->next) {
                        listener_item = listener_item->next;
                    }
                    listener_item->next = current_listener_item;
                }

                state = snip_config_parse_state_listener_item_map;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIPROXY_LOG_LEVEL_FATAL,
                                "The 'listeners' section must be a list of key/value dictionaries ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listener_item_map) {
            if(event.type == YAML_SCALAR_EVENT) {
                if(!strcmp((const char *) event.data.scalar.value, "routes")) {
                    state = snip_config_parse_state_routes_rvalue;
                }
                else {
                    // We don't recognize this key. We log it as a warning, and make plans to skip the associated value.
                    state = snip_config_parse_state_skipping_unexpected_key_value;
                    skip_rvalue_depth = current_depth;
                    state_after_skip = state;
                    snip_log_config(config,
                                    &event,
                                    SNIPROXY_LOG_LEVEL_WARNING,
                                    "Unexpected key '%s' ",
                                    event.data.scalar.value
                    );
                }
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIPROXY_LOG_LEVEL_FATAL,
                                "The 'listeners' section must be a list of key/value dictionaries ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_rvalue) {
            if(event.type == YAML_MAPPING_START_EVENT) {
                state = snip_config_parse_state_routes_map;
            }
            else if(event.type == YAML_SEQUENCE_START_EVENT) {
                state = snip_config_parse_state_routes_list;
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIPROXY_LOG_LEVEL_FATAL,
                                "The 'routes' section must be a list or dictionary ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_map) {
            // This is a shortcut for routes. The key is the pattern, the value the destination.
            if(event.type == YAML_SCALAR_EVENT) {
                state = snip_config_parse_state_routes_map_value;
                current_route_item = snip_config_route_list_create();
                current_route_item->value.sni_hostname = malloc(event.data.scalar.length);
                memcpy(current_route_item->value.sni_hostname, event.data.scalar.value, event.data.scalar.length);
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIPROXY_LOG_LEVEL_FATAL,
                                "The 'routes' section must be a list or dictionary ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_map_value) {
            // This is a shortcut for routes. The key is the pattern, the value the destination.
            if(event.type == YAML_SCALAR_EVENT) {
                state = snip_config_parse_state_routes_map;



                current_route_item->value.sni_hostname = malloc(event.data.scalar.length);
                memcpy(current_route_item->value.sni_hostname, event.data.scalar.value, event.data.scalar.length);
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIPROXY_LOG_LEVEL_FATAL,
                                "The 'routes' section must be a list or dictionary ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_list) {

        }
        else if(state == snip_config_parse_state_skipping_unexpected_key_value) {
            if((current_depth == skip_rvalue_depth) &&
                    (event.type == YAML_SCALAR_EVENT ||
                            event.type == YAML_MAPPING_END_EVENT ||
                            event.type == YAML_SEQUENCE_END_EVENT
                    ))
            {
                state = state_after_skip;
            }
        }

        yaml_event_delete(&event);
    }
    yaml_parser_delete(&parser);



    config->listeners = snip_config_listener_list_create();
    struct snip_config_listener *fake_listener = &(config->listeners->value);
    fake_listener->bind_port = 8080;

    //int evdns_base_clear_nameservers_and_suspend(struct evdns_base *base);
    //int evdns_base_resume(struct evdns_base *base);
}
