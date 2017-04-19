// Copyright (c) 2017 J Cody Baker. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include "snip.h"

int main(int argc, char **argv) {
    snip_context_ref_t context = snip_context_create();
    snip_context_init(context, argc, argv);
    snip_run(context);
    return 0;
}

