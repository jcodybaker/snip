//
// Created by Cody Baker on 3/27/17.
//

#include "config.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <yaml.h>

/**
 * Create a snip_config_t object.
 * @return
 */
snip_config_t *
snip_config_create() {
    snip_config_t *config = malloc(sizeof(snip_config_t));
    memset(config, '\0', sizeof(snip_config_t));
    return config;
}

/**
 * Create a listener linked-list item.
 * @return
 */
snip_config_listener_list_t *
snip_config_listener_list_create() {
    snip_config_listener_list_t *list = malloc(sizeof(snip_config_listener_list_t));
    memset(list, '\0', sizeof(snip_config_listener_list_t));
    return list;
}

/**
 * Recursively destroy a list of snip_config_listeners.
 * @param list[in,out]
 */
void
snip_config_listener_list_destroy(snip_config_listener_list_t *list) {
    if(list->next) {
        snip_config_listener_list_destroy(list->next);
    }
    free(list);
}

/**
 * Allocate and initialize a new snip_config_route object.
 * @return The new snip_config_route_list_t *
 */
snip_config_route_list_t *
snip_config_route_list_create() {
    snip_config_route_list_t *route_list = malloc(sizeof(snip_config_route_list_t));
    memset(route_list, '\0', sizeof(snip_config_route_list_t));
    return route_list;
}

/**
 * Cleanup and free a snip_config_route_list_t object.
 * @param route_list[in,out]
 */
void
snip_config_route_list_destroy(snip_config_route_list_t *route_list) {
    if(route_list->next) {
        snip_config_route_list_destroy(route_list->next);
    }
    free(route_list->value.dest_hostname);
    free(route_list->value.sni_hostname);
    free(route_list);
}

/**
 * Display the help information and exit the application.
 * @param name[in] - The name of the command.
 */
void
snip_config_display_help_and_exit(const char *name) {
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

/**
 * Parse the command line arguments and drop them into a configuration.
 * @param config[in,out]
 * @param argc[in]
 * @param argv[in]
 */
void
snip_config_parse_args(snip_config_t *config, int argc, char **argv) {
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
        switch(rv) {
            case 'c':
                config->config_path = optarg;
                break;
            case 'h':
                snip_config_display_help_and_exit(argc ? argv[0] : "snip");
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
 * @param level - Log severity level.  If SNIP_LOG_LEVEL_FATAL, we will shutdown and exit.
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with variadic arguments provided in args.
 * @param ... - List of arguments for populating the format string msg_format.
 */
void
snip_log_config(snip_config_t *config, yaml_event_t *event, snip_log_level_t level, const char *msg_format, ...) {
    const char *config_error_msg = "%sin configuration file '%s' between %d:%d and %d:%d.";
    size_t buffer_max = 1 + (size_t) snprintf(NULL,
                                        0,
                                        config_error_msg,
                                        msg_format,
                                        config->config_path,
                                        event->start_mark.line,
                                        event->start_mark.column,
                                        event->end_mark.line,
                                        event->end_mark.column);
    char *buffer = malloc(buffer_max);
    snprintf(buffer,
                    buffer_max,
                    config_error_msg,
                    msg_format,
                    config->config_path,
                    event->start_mark.line,
                    event->start_mark.column,
                    event->end_mark.line,
                    event->end_mark.column);
    va_list args;
    va_start(args, msg_format);
    if(level == SNIP_LOG_LEVEL_FATAL) {
        snip_vlog_fatal(SNIP_EXIT_ERROR_INVALID_CONFIG, buffer, args);
    }
    else {
        snip_vlog(level, buffer, args);
    }
    va_end(args);
    free(buffer);
}

/**
* Given a string of digits (ex. "12345") parse it into a port and set *port to the value.  It may NOT be prefaced or
*     suffixed by any extra characters, must be a valid 16-bit number, and must only contain digits.
* @param port_string[in] A NULL terminated string of at 1 to 5 digits.
* @param port[out] Pointer to a uint16_t where the port value should be stored.
* @return True if the port is valid and was parsed properly.  False otherwise.
*/
SNIP_BOOLEAN
snip_parse_port(const char *port_string, uint16_t *port) {
    const char *port_end = port_string;
    while(1) {
        if((port_end - port_string) > 5) {
            return FALSE;
        }
        if(*port_end == '\0') {
            break;
        }
        if((*port_end < '0') || (*port_end > '9')) {
            return FALSE; // Return false if the port contains a non-digit character.
        }
        port_end += 1;
    }
    if(port_string == port_end) {
        // A colon was found, but no port was found after it.
        return FALSE;
    }
    unsigned long port_ul = strtoul(port_string, NULL, 10);
    if(port_ul > 0xFFFF) { // port must be a 16-bit number.
        return FALSE;
    }
    *port = (uint16_t) port_ul;
    return TRUE;
}

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
snip_parse_target(const char *target, char **hostname, uint16_t *port) {
    *hostname = NULL;
    const char *colon = strchr(target, ':');
    size_t hostname_length;
    if(colon) {
        hostname_length = colon - target;
        if(!snip_parse_port(colon + 1, port)) {
            return 0;
        }
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
 * Read the configuration file and apply it to the specified config structure.
 * @param config[in,out]
 */
SNIP_BOOLEAN
snip_parse_config_file(snip_config_t *config) {
    FILE *config_file = fopen(config->config_path, "r");
    if(!config_file) {
        snip_log_fatal(SNIP_EXIT_ERROR_INVALID_CONFIG, "Could not read config file '%s'.", config->config_path);
        return FALSE;
    }

    yaml_parser_t parser;
    yaml_event_t event;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, config_file);


    typedef enum snip_config_parse_state_e {
        snip_config_parse_state_initial = 0,
        snip_config_parse_state_root_map,

        snip_config_parse_state_listener_port_rvalue,
        snip_config_parse_state_listener_bind_rvalue,
        snip_config_parse_state_routes_rvalue,

        snip_config_parse_state_routes_list,
        snip_config_parse_state_routes_list_map,
        snip_config_parse_state_routes_list_map_sni_hostname_value,
        snip_config_parse_state_routes_list_map_target_value,
        snip_config_parse_state_routes_list_map_target_port_value,

        snip_config_parse_state_routes_map,
        snip_config_parse_state_routes_map_value,

        snip_config_parse_state_skipping_unexpected_key_value,
        // Right now we always treat these as fatal errors, but we might change the behavior for SIGHUP config reloads.
        snip_config_parse_state_error,

        snip_config_parse_state_listeners_rvalue,
        snip_config_parse_state_listeners_in_list,
        snip_config_parse_state_listener_item_map,

        snip_config_parse_success
    } snip_config_parse_state_t;
    
    snip_config_parse_state_t state = snip_config_parse_state_initial;
    snip_config_parse_state_t state_after_skip = snip_config_parse_state_initial;

    snip_config_listener_list_t *current_listener_item = NULL;
    snip_config_route_list_t *current_route_item = NULL;

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

    while(1) {
        if (!yaml_parser_parse(&parser, &event)) {
            snip_log_config(config, &event, SNIP_LOG_LEVEL_FATAL, "Error parsing ");
        }
        /*
        switch(event.type) {
            case YAML_NO_EVENT:
                //printf("YAML_NO_EVENT\n");
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
                break;
            case YAML_STREAM_END_EVENT:
                printf("YAML_STREAM_END_EVENT\n");
                break;
        }
        */


        if(event.type == YAML_STREAM_END_EVENT) {
            if(state != snip_config_parse_success) {
                snip_log_config(config, &event, SNIP_LOG_LEVEL_FATAL, "Unexpected end of configuration ");
            }
            break;
        }
        else if(state == snip_config_parse_state_initial)
        {
            // New document. Make sure it starts with a map, but otherwise, nothing fancy.
            if(event.type == YAML_MAPPING_START_EVENT) {
                state = snip_config_parse_state_root_map;
            }
            else if ((event.type == YAML_MAPPING_END_EVENT) ||
                     (event.type == YAML_SEQUENCE_START_EVENT) ||
                     (event.type == YAML_SEQUENCE_END_EVENT))
            {
                snip_log_config(config, &event, SNIP_LOG_LEVEL_FATAL, "The root element must be a key/value map ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_root_map) {
            // We're parsing a new key in the root dictionary of the configuration file.
            if(event.type == YAML_SCALAR_EVENT) {
                if(!strcmp((const char *) event.data.scalar.value, "listeners")) {
                    state = snip_config_parse_state_listeners_rvalue;
                }
                else if(!strcmp((const char *) event.data.scalar.value, "routes")) {
                    state = snip_config_parse_state_routes_rvalue;
                }
                else {
                    // We don't recognize this key. We log it as a warning, and make plans to skip the associated value.
                    state_after_skip = state;
                    state = snip_config_parse_state_skipping_unexpected_key_value;
                    skip_rvalue_depth = current_depth;
                    snip_log_config(config,
                                    &event,
                                    SNIP_LOG_LEVEL_WARNING,
                                    "Unexpected key '%s' ",
                                    event.data.scalar.value
                    );
                }
            }
            else if(event.type == YAML_MAPPING_END_EVENT) {
                state = snip_config_parse_success;
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config, &event, SNIP_LOG_LEVEL_FATAL, "Key had unexpected type ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listeners_rvalue) {
            // We're in root dictionary, and we have the key "listeners".  The value MUST be a list.
            if(event.type == YAML_SEQUENCE_START_EVENT) {
                state = snip_config_parse_state_listeners_in_list;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config, &event, SNIP_LOG_LEVEL_FATAL, "'listeners' section was not a list ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listeners_in_list) {
            // We're in the list of listeners, ready to start parsing the next listener. That listener must be a map.
            if(event.type == YAML_MAPPING_START_EVENT) {
                // Ok, time to create a new listener.
                current_listener_item = snip_config_listener_list_create();
                if(!config->listeners) {
                    config->listeners = current_listener_item;
                }
                else {
                    // We want the new listener at the end;
                    snip_config_listener_list_t *listener_item = config->listeners;

                    while(listener_item->next) {
                        listener_item = listener_item->next;
                    }
                    listener_item->next = current_listener_item;
                }

                state = snip_config_parse_state_listener_item_map;
            }
            else if(event.type == YAML_SEQUENCE_END_EVENT) {
                current_listener_item = NULL;
                state = snip_config_parse_state_root_map;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "The 'listeners' section must be a list of key/value dictionaries ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listener_item_map) {
            // We are now parsing a specific listener, and are ready to examine a key.
            if(event.type == YAML_SCALAR_EVENT) {
                if(!strcmp((const char *) event.data.scalar.value, "routes")) {
                    state = snip_config_parse_state_routes_rvalue;
                }
                else if(!strcmp((const char *) event.data.scalar.value, "port")) {
                    state = snip_config_parse_state_listener_port_rvalue;
                }
                else if(!strcmp((const char *) event.data.scalar.value, "bind")) {
                    state = snip_config_parse_state_listener_bind_rvalue;
                }
                else {
                    // We don't recognize this key. We log it as a warning, and make plans to skip the associated value.
                    state_after_skip = state;
                    state = snip_config_parse_state_skipping_unexpected_key_value;
                    skip_rvalue_depth = current_depth;
                    snip_log_config(config,
                                    &event,
                                    SNIP_LOG_LEVEL_WARNING,
                                    "Unexpected key '%s' ",
                                    event.data.scalar.value
                    );
                }
            }
            else if(event.type == YAML_MAPPING_END_EVENT) {
                state = snip_config_parse_state_listeners_in_list;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "The 'listeners' section must be a list of key/value dictionaries ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_rvalue) {
            // The "routes" key is valid in both the root (as a global default) and within listener config objects.
            // With the key, we now need to parse the value. We accept two formats: a list of dictionaries, and a
            // shortcut dictionary format.  We figure out which format we have here.
            if(event.type == YAML_MAPPING_START_EVENT) {
                state = snip_config_parse_state_routes_map;
            }
            else if(event.type == YAML_SEQUENCE_START_EVENT) {
                state = snip_config_parse_state_routes_list;
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "The 'routes' section must be a list or dictionary ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_map) {
            // We're inside the value of a 'routes' configuration.  These routes are defined with the shortcut
            // dictionary format. The key is the pattern, the value the destination.  We're going to examine the key,
            // which should be the SNI-hostname-pattern we're trying to match.  We might also get an event indicating
            // the end of the list.
            if(event.type == YAML_SCALAR_EVENT) {
                state = snip_config_parse_state_routes_map_value;
                current_route_item = snip_config_route_list_create();

                // If we have a current_listener_item this route belongs to a listener, otherwise its global default.
                snip_config_route_list_t **routes_first = current_listener_item ?
                                                               &(current_listener_item->value.routes) :
                                                               &(config->routes);
                if(!(*(routes_first))) {
                    *(routes_first) = current_route_item;
                }
                else {
                    // skip to the end and add it there.
                    snip_config_route_list_t *route_item = *(routes_first);
                    while(route_item->next) {
                        route_item = route_item->next;
                    }
                    route_item->next = current_route_item;
                }
                current_route_item->value.sni_hostname = malloc(event.data.scalar.length);
                memcpy(current_route_item->value.sni_hostname, event.data.scalar.value, event.data.scalar.length);
            }
            else if(event.type == YAML_MAPPING_END_EVENT) {
                // End of the dictionary.
                current_route_item = NULL;
                state = current_listener_item ?
                        snip_config_parse_state_listener_item_map : snip_config_parse_state_root_map;
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "The 'routes' section must be a list or dictionary ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_map_value) {
            // We're in the shortcut dictionary version of a routes section.  We have the SNI-hostname key, and are now
            // looking at the value.  It must be a string.
            if(event.type == YAML_SCALAR_EVENT) {
                state = snip_config_parse_state_routes_map;
                snip_parse_target((const char *) event.data.scalar.value,
                                  &(current_route_item->value.dest_hostname),
                                  &(current_route_item->value.port));
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(
                        config,
                        &event,
                        SNIP_LOG_LEVEL_FATAL,
                        "The 'routes' section must either be a string:string dictionary, or a list of dictionaries ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_list) {
            // We're currently parsing a 'routes' section which is defined in the more verbose list-of-dictionaries
            // format.  We expect to find either the start of a new dictionary, or an end-of-list event.
            if(event.type == YAML_MAPPING_START_EVENT) {
                state = snip_config_parse_state_routes_list_map;
                current_route_item = snip_config_route_list_create();

                // If we have a current_listener_item this route belongs to a listener, otherwise its global default.
                snip_config_route_list_t **routes_first = current_listener_item ?
                                                               &(current_listener_item->value.routes) :
                                                               &(config->routes);
                if(!(*(routes_first))) {
                    *(routes_first) = current_route_item;
                }
                else {
                    // skip to the end and add it there.
                    snip_config_route_list_t *route_item = *(routes_first);
                    while(route_item->next) {
                        route_item = route_item->next;
                    }
                    route_item->next = current_route_item;
                }
            }
            else if(event.type == YAML_SEQUENCE_END_EVENT) {
                // End of the list.  If we were examining a listener, go back to parsing it, otherwise goto the root.
                state = current_listener_item ?
                        snip_config_parse_state_listener_item_map : snip_config_parse_state_root_map;
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(
                        config,
                        &event,
                        SNIP_LOG_LEVEL_FATAL,
                        "The 'routes' section must either be a string:string dictionary, or a list of dictionaries ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_routes_list_map) {
            // We're inside a route-definition that uses the more verbose list-of-dictionary format.  We're in that
            // dictionary looking at the key.
            if(event.type == YAML_SCALAR_EVENT) {
                if(!strcmp((const char *) event.data.scalar.value, "sni_hostname")) {
                    state = snip_config_parse_state_routes_list_map_sni_hostname_value;
                }
                else if(!strcmp((const char *) event.data.scalar.value, "target")) {
                    state = snip_config_parse_state_routes_list_map_target_value;
                }
                else if(!strcmp((const char *) event.data.scalar.value, "target_port")) {
                    state = snip_config_parse_state_routes_list_map_target_port_value;
                }
                else {
                    // We don't recognize this key. We log it as a warning, and make plans to skip the associated value.
                    state_after_skip = state;
                    state = snip_config_parse_state_skipping_unexpected_key_value;
                    skip_rvalue_depth = current_depth;
                    snip_log_config(config,
                                    &event,
                                    SNIP_LOG_LEVEL_WARNING,
                                    "Unexpected key '%s' ",
                                    event.data.scalar.value
                    );
                }
            }
            else if(event.type == YAML_MAPPING_END_EVENT) {
                state = snip_config_parse_state_routes_list;
            }
            else if(event.type != YAML_NO_EVENT) {
                snip_log_config(config, &event, SNIP_LOG_LEVEL_FATAL, "Key had unexpected type ");
                state = snip_config_parse_state_error;
            }
        }
        else if (state == snip_config_parse_state_routes_list_map_sni_hostname_value) {
            if(event.type == YAML_SCALAR_EVENT) {
                current_route_item->value.sni_hostname = malloc(event.data.scalar.length);
                memcpy(current_route_item->value.sni_hostname, event.data.scalar.value, event.data.scalar.length);
                state = snip_config_parse_state_routes_list_map;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "Route property 'sni_hostname' expects a string value ");
                state = snip_config_parse_state_error;
            }
        }
        else if (state == snip_config_parse_state_routes_list_map_target_value) {
            if(event.type == YAML_SCALAR_EVENT) {
                current_route_item->value.dest_hostname = malloc(event.data.scalar.length);
                memcpy(current_route_item->value.dest_hostname, event.data.scalar.value, event.data.scalar.length);
                state = snip_config_parse_state_routes_list_map;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "Route property 'target' expects a string value ");
                state = snip_config_parse_state_error;
            }
        }
        else if (state == snip_config_parse_state_routes_list_map_target_port_value) {
            if(event.type == YAML_SCALAR_EVENT) {
                if(!snip_parse_port((const char *) event.data.scalar.value, &(current_route_item->value.port))) {
                    snip_log_config(config,
                                    &event,
                                    SNIP_LOG_LEVEL_FATAL,
                                    "Invalid port specification '%s' for route ",
                                    event.data.scalar.value);
                    state = snip_config_parse_state_error;
                }
                else {
                    state = snip_config_parse_state_routes_list_map;
                }
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "Route property 'target_port' expects an integer between 0 and 65535 ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listener_port_rvalue) {
            if(event.type == YAML_SCALAR_EVENT) {
                if(!snip_parse_port((const char *) event.data.scalar.value, &(current_listener_item->value.bind_port)))
                {
                    snip_log_config(config,
                                    &event,
                                    SNIP_LOG_LEVEL_FATAL,
                                    "Invalid port specification '%s' for route ",
                                    event.data.scalar.value);
                    state = snip_config_parse_state_error;
                }
                else {
                    state = snip_config_parse_state_listener_item_map;
                }
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "'listener' property 'port' expects an integer between 0 and 65535 ");
                state = snip_config_parse_state_error;
            }
        }
        else if(state == snip_config_parse_state_listener_bind_rvalue) {
            if(event.type == YAML_SCALAR_EVENT) {
                current_listener_item->value.bind_addr = malloc(event.data.scalar.length);
                memcpy(current_listener_item->value.bind_addr, event.data.scalar.value, event.data.scalar.length);
                state = snip_config_parse_state_listener_item_map;
            }
            else if (event.type != YAML_NO_EVENT) {
                snip_log_config(config,
                                &event,
                                SNIP_LOG_LEVEL_FATAL,
                                "'listener' property 'bind' expects a string value ");
                state = snip_config_parse_state_error;
            }
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
        else if(state == snip_config_parse_success) {
            if(event.type != YAML_DOCUMENT_END_EVENT && event.type != YAML_NO_EVENT) {
                snip_log_config(config, &event, SNIP_LOG_LEVEL_FATAL, "Unexpected content after configuration ");
            }
        }
        yaml_event_delete(&event);
    }
    yaml_parser_delete(&parser);

    return TRUE;
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
    snip_config_t *config = snip_config_create();
    if(argc && argv) {
        snip_config_parse_args(config, argc, argv);
    }
    if(!config->config_path) {
        config->config_path = SNIP_INSTALL_CONF_PATH;
    }
    if(!snip_parse_config_file(config)) {

    }
    //int evdns_base_clear_nameservers_and_suspend(struct evdns_base *base);
    //int evdns_base_resume(struct evdns_base *base);
}