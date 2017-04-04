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
 * Log a fatal configuration error with location references within the configuration file.
 * @param config
 * @param event
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with variadic arguments provided in args.
 * @param ... - List of arguments for populating the format string msg_format.
 */
void
snip_log_fatal_config_error(struct snip_config *config, yaml_event_t *event, const char *msg_format, ...) {
    const char *config_error_msg = "Error in configuration file '%s' between %d:%d and %d:%d: %s";
    size_t buffer_max = 1 + (size_t) evutil_snprintf(NULL,
                                        0,
                                        config_error_msg,
                                        config->config_path,
                                        event->start_mark.line,
                                        event->start_mark.column,
                                        event->end_mark.line,
                                        event->end_mark.column,
                                        msg_format
    );
    char *buffer = malloc(buffer_max);
    evutil_snprintf(buffer,
                    buffer_max,
                    config_error_msg,
                    config->config_path,
                    event->start_mark.line,
                    event->start_mark.column,
                    event->end_mark.line,
                    event->end_mark.column,
                    msg_format
    );
    va_list args;
    va_start(args, msg_format);
    snip_vlog_fatal(SNIPROXY_EXIT_ERROR_INVALID_CONFIG, buffer, args);
    va_end(args);
    free(buffer);
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

    }

    yaml_parser_t parser;
    yaml_event_t event;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, config_file);

    typedef enum snip_config_parse_state_e {
        snip_config_parse_state_initial = 0,
        snip_config_parse_state_root_map,
        snip_config_parse_state_root_map_have_key
    } snip_config_parse_state_t;
    
    snip_config_parse_state_t state = snip_config_parse_state_initial;
    yaml_mark_t last_good_position;

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

        if(state == snip_config_parse_state_initial)
        {
            if(event.type == YAML_MAPPING_START_EVENT) {
                state = snip_config_parse_state_root_map;
            }
            else if ((event.type == YAML_MAPPING_END_EVENT) ||
                     (event.type == YAML_SEQUENCE_START_EVENT) ||
                     (event.type == YAML_SEQUENCE_END_EVENT))
            {
                snip_log_fatal_config_error(config, &event, "The root element must be a key/value map.");
            }
        }
        else if(state == snip_config_parse_state_root_map) {

        }


        last_good_position = event.end_mark;
    }
    yaml_parser_delete(&parser);



    config->listeners = snip_config_listener_list_create();
    struct snip_config_listener *fake_listener = &(config->listeners->value);
    fake_listener->bind_port = 8080;

    //int evdns_base_clear_nameservers_and_suspend(struct evdns_base *base);
    //int evdns_base_resume(struct evdns_base *base);
}
