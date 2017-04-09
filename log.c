//
// Created by Cody Baker on 4/3/17.
//

#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

/**
 * Convert a snip_log_level_t to a string describing the severity level.
 * @param level
 * @return - String describing the severity level.
 */
const char *
snip_log_level_to_string(snip_log_level_t level) {
    switch(level) {
        case SNIP_LOG_LEVEL_FATAL:
            return SNIP_LOG_LEVEL_FATAL_STRING;
        case SNIP_LOG_LEVEL_ALERT:
            return SNIP_LOG_LEVEL_ALERT_STRING;
        case SNIP_LOG_LEVEL_CRITICAL:
            return SNIP_LOG_LEVEL_CRITICAL_STRING;
        case SNIP_LOG_LEVEL_ERROR:
            return SNIP_LOG_LEVEL_ERROR_STRING;
        case SNIP_LOG_LEVEL_WARNING:
            return SNIP_LOG_LEVEL_WARNING_STRING;
        case SNIP_LOG_LEVEL_NOTICE:
            return SNIP_LOG_LEVEL_NOTICE_STRING;
        case SNIP_LOG_LEVEL_INFO:
            return SNIP_LOG_LEVEL_INFO_STRING;
        case SNIP_LOG_LEVEL_DEBUG:
            return SNIP_LOG_LEVEL_DEBUG_STRING;
        default:
            return  "UNKNOWN";
    }
}

/**
 * Log a message.
 * @param level - Severity level for the log message.  See https://en.wikipedia.org/wiki/Syslog#Severity_level
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with variadic arguments provided in args.
 * @param args - List of variadic arguments for populating in the format string.
 */
void snip_vlog(snip_log_level_t level, const char *msg_format, va_list args) {
    fprintf(stderr, "%s: ", snip_log_level_to_string(level));
    vfprintf(stderr, msg_format, args);
    fputs("\n", stderr);
}

/**
 * Log a message.
 * @param level - Severity level for the log message.  See https://en.wikipedia.org/wiki/Syslog#Severity_level
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with remaining variadic arguments.
 * @param ... - List of arguments for populating the format string msg_format.
 */
void snip_log(snip_log_level_t level, const char *msg_format, ...) {
    va_list args;
    va_start(args, msg_format);
    snip_vlog(level, msg_format, args);
    va_end(args);
}

/**
 * Log a message with the SNIP_LOG_LEVEL_FATAL severity and then exit.
 * @param exit_code Process exit code.  Use SNIP_EXIT_ERROR_GENERAL for undefined errors.
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with variadic arguments provided in args.
 * @param ... - List of arguments for populating the format string msg_format.
 */
void snip_log_fatal(int code, const char *msg_format, ...) {
    va_list args;
    va_start(args, msg_format);
    snip_vlog(SNIP_LOG_LEVEL_FATAL, msg_format, args);
    va_end(args);
}

/**
 * Log a message with the SNIP_LOG_LEVEL_FATAL severity and then exit.
 * @param exit_code Process exit code.  Use SNIP_EXIT_ERROR_GENERAL for undefined errors.
 * @param msg_format - Single-line string description which should be logged on error.
 * @param args - List of variadic arguments for populating in the format string msg_format.
 */
void snip_vlog_fatal(int code, const char *msg_format, va_list args) {
    snip_vlog(SNIP_LOG_LEVEL_FATAL, msg_format, args);
    // TODO - Clean-shutdown or gentle failure if this happens on a SIGHUP reload.
    exit(code);
}