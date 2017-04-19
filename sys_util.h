// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#ifndef SNIP_SYS_UTIL_H
#define SNIP_SYS_UTIL_H

#include "compat.h"
#include <unistd.h>

/**
 * Find the uid (user id) and gid (group id) for the given username.
 * @param username
 * @param uid - pointer to long value where we should store the uid.  NULL is OK. Will be set -1 if none is found.
 * @param gid - pointer to long value where we should store the gid.  NULL is OK. Will be set -1 if none is found.
 * @return - TRUE if a user was found, FALSE if not.
 */
SNIP_BOOLEAN
get_uid_gid_for_username(const char *username, long *uid, long *gid);

/**
 * Find the gid (group id) for the given group name.
 * @param group_name
 * @return The gid, or -1 if the group could not be found.
 */
long
get_gid_for_group_name(const char *group_name);

/**
 * Drop privileges so we can execute more safely.
 * @param uid
 * @param gid
 * @return TRUE if the drop was successful.  FALSE if any errors happened.  We should quit IMMEDIATELY if we run into
 *      any problem because the state is undefined.
 */
SNIP_BOOLEAN
drop_privileges(uid_t uid, gid_t gid);

#endif //SNIP_SYS_UTIL_H
