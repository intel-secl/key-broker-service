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
public class CreateUserResponse extends FindUsersResponse {

    public CreateUserResponse() {
        super();
    }

    public CreateUserResponse(User created) {
        super();
        getData().add(created);
    }
}
