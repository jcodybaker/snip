// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#include "sys_util.h"
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "log.h"

#include <string.h>


/**
 * Find the uid (user id) and gid (group id) for the given username.
 * @param username
 * @param uid - pointer to long value where we should store the uid.  NULL is OK. Will be set -1 if none is found.
 * @param gid - pointer to long value where we should store the gid.  NULL is OK. Will be set -1 if none is found.
 * @return - TRUE if a user was found, FALSE if not.
 */
SNIP_BOOLEAN
get_uid_gid_for_username(const char *username, long *uid, long *gid)
{
    // See http://man7.org/linux/man-pages/man3/getpwnam.3.html
    struct passwd pwd;
    struct passwd *result;
    char *buffer;
    ssize_t buffer_size;
    int s;

    buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buffer_size == -1)          /* Value was indeterminate */
        buffer_size = 16384;        /* Should be more than enough */

    buffer = malloc((size_t) buffer_size);
    memset(buffer, '\0', buffer_size);
    if (buffer == NULL) {
        snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED, "Unable to allocate buffer.");
    }

    s = getpwnam_r(username, &pwd, buffer, (size_t) buffer_size, &result);
    if (result == NULL) {
        if (s == 0) {
            // Not found.
            if (uid) {
                *uid = -1;
            }
            if (gid) {
                *gid = -1;
            }
            return FALSE;
        }
        else {
            snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED,
                           "Failed to resolve username '%s': (%d) %s",
                           username,
                           strerror(s)
            );
            return FALSE;
        }
    }

    if(uid){
        *uid = pwd.pw_uid;
    }
    if(gid){
        *gid = pwd.pw_gid;
    }

    free(buffer);
    return TRUE;
}

/**
 * Find the gid (group id) for the given group name.
 * @param group_name
 * @return The gid, or -1 if the group could not be found.
 */
long
get_gid_for_group_name(const char *group_name) {
    // See http://man7.org/linux/man-pages/man3/getpwnam.3.html
    struct group group;
    struct group *result;
    char *buffer;
    ssize_t buffer_size;
    int s;

    buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buffer_size == -1)          /* Value was indeterminate */
        buffer_size = 16384;        /* Should be more than enough */

    buffer = malloc((size_t) buffer_size);
    memset(buffer, '\0', buffer_size);
    if (buffer == NULL) {
        snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED, "Unable to allocate buffer.");
        return -1;
    }

    s = getgrnam_r(group_name, &group, buffer, (size_t) buffer_size, &result);
    if (result == NULL) {
        if (s == 0) {
            // Not found.
            return -1;
        }
        else {
            snip_log_fatal(SNIP_EXIT_ERROR_ASSERTION_FAILED,
                           "Failed to resolve username '%s': (%d) %s",
                           group_name,
                           strerror(s)
            );
            return -1;
        }
    }

    long gid = group.gr_gid;
    free(buffer);
    return gid;
}

/**
 * Drop privileges so we can execute more safely.
 * @param uid
 * @param gid
 * @return TRUE if the drop was successful.  FALSE if any errors happened.  We should quit IMMEDIATELY if we run into
 *      any problem because the state is undefined.
 */
SNIP_BOOLEAN
drop_privileges(uid_t uid, gid_t gid) {
    // Loosely based on https://www.safaribooksonline.com/library/view/secure-programming-cookbook/0596003943/ch01s03.html
    uid_t current_uid = getuid();
    gid_t current_gid = getgid();

    // We drop ancillary groups either way.
    if(setgroups(1, &gid) == -1) {
        return FALSE;
    }

    if (gid != current_gid) {
#ifdef __linux__
        if (setregid(gid, gid) == -1) {
            return FALSE;
        }
#else
        if (setegid(gid) == -1) {
            return FALSE;
        }
        if (setgid(gid) == -1) {
            return FALSE;
        };
#endif
    }

    if(uid != current_uid) {
#ifdef __linux__
        if (setreuid(uid, uid) == -1) {
            return FALSE;
        };
#else
        if (seteuid(uid) == -1) {
            return FALSE;
        }
        if (setuid(uid) == -1) {
            // On OS-X it seems we can't setuid if we've already dropped with seteuid.  Set it back, then drop and
            // verify.
            seteuid(current_uid);
            if (setuid(uid) == -1 || geteuid() != uid) {
                return FALSE;
            }

        }
#endif
    }

    // Check to make sure this is actually different. Try to change again. We can only change if we're privileged.  That
    // means we can't change twice in a row.
    if (gid != current_gid && (setegid(current_gid) != -1 || getegid() != gid)) {
        return FALSE;
    }
    if (uid != current_uid && (seteuid(current_uid) != -1 || geteuid() != uid)) {
        return FALSE;
    }
    return TRUE;
}