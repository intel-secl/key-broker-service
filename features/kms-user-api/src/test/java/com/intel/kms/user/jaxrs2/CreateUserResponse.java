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
public class CreateUserResponse extends FindUsersResponse {

    public CreateUserResponse() {
        super();
    }

    public CreateUserResponse(User created) {
        super();
        getData().add(created);
    }
}
