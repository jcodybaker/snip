//
// Created by Cody Baker on 4/3/17.
//

#ifndef SNIP_LOG_H
#define SNIP_LOG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SNIP_EXIT_ERROR_GENERAL 1
#define SNIP_EXIT_ERROR_INVALID_CONFIG 64
#define SNIP_EXIT_ERROR_SOCKET 65
#define SNIP_EXIT_ERROR_ASSERTION_FAILED 66

// These are roughly borrowed from syslog, though we call it FATAL to avoid any confusion.
// Goal is to make life easier if we want to switch to a logging library that implements a syslog style interface.
#define SNIP_LOG_LEVEL_FATAL_STRING      "FATAL"
#define SNIP_LOG_LEVEL_ALERT_STRING      "ALERT"
#define SNIP_LOG_LEVEL_CRITICAL_STRING   "CRITICAL"
#define SNIP_LOG_LEVEL_ERROR_STRING      "ERROR"
#define SNIP_LOG_LEVEL_WARNING_STRING    "WARNING"
#define SNIP_LOG_LEVEL_NOTICE_STRING     "NOTICE"
#define SNIP_LOG_LEVEL_INFO_STRING       "INFO"
#define SNIP_LOG_LEVEL_DEBUG_STRING      "DEBUG"

typedef enum snip_log_level_e {
    SNIP_LOG_LEVEL_FATAL = 0, // Values borrowed from syslog.h
    SNIP_LOG_LEVEL_ALERT = 1,
    SNIP_LOG_LEVEL_CRITICAL = 2,
    SNIP_LOG_LEVEL_ERROR = 3,
    SNIP_LOG_LEVEL_WARNING = 4,
    SNIP_LOG_LEVEL_NOTICE = 5,
    SNIP_LOG_LEVEL_INFO = 6,
    SNIP_LOG_LEVEL_DEBUG = 7
} snip_log_level_t;

/**
 * Convert a snip_log_level_t to a string describing the severity level.
 * @param level
 * @return - String describing the severity level.
 */
const char *
snip_log_level_to_string(snip_log_level_t level);

/**
 * Log a message.
 * @param level - Severity level for the log message.  See https://en.wikipedia.org/wiki/Syslog#Severity_level
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with variadic arguments provided in args.
 * @param args - List of variadic arguments for populating in the format string.
 */
void snip_vlog(snip_log_level_t level, const char *msg_format, va_list args);


/**
 * Log a message.
 * @param level - Severity level for the log message.  See https://en.wikipedia.org/wiki/Syslog#Severity_level
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with remaining variadic arguments.
 * @param ... - List of arguments for populating the format string msg_format.
 */
void snip_log(snip_log_level_t level, const char *msg_format, ...);

/**
 * Log a message with the SNIP_LOG_LEVEL_FATAL severity and then exit.
 * @param exit_code Process exit code.  Use SNIP_EXIT_ERROR_GENERAL for undefined errors.
 * @param msg_format - Single-line description of the condition we want to log.  printf style format string populated
 *      with variadic arguments provided in args.
 * @param ... - List of arguments for populating the format string msg_format.
 */
void snip_log_fatal(int code, const char *msg_format, ...);

/**
 * Log a message with the SNIP_LOG_LEVEL_FATAL severity and then exit.
 * @param exit_code Process exit code.  Use SNIP_EXIT_ERROR_GENERAL for undefined errors.
 * @param msg_format - Single-line string description which should be logged on error.
 * @param args - List of variadic arguments for populating in the format string msg_format.
 */
void snip_vlog_fatal(int code, const char *msg_format, va_list args);

#ifdef __cplusplus
}
#endif

#endif //SNIP_LOG_H
