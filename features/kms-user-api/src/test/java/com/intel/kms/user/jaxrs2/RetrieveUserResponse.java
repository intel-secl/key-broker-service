/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
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
