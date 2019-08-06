/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import com.intel.kms.user.User;

/**
 *
 * @author jbuhacoff
 */
public class RetrieveUserResponse extends FindUsersResponse {

    public RetrieveUserResponse() {
        super();
    }

    public RetrieveUserResponse(User user) {
        super();
        getData().add(user);
    }
}
