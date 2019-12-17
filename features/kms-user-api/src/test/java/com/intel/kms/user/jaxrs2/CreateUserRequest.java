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
public class CreateUserRequest extends AbstractRequest {
    private User create;
    public CreateUserRequest() {
        super();
    }
    public CreateUserRequest(User create) {
        super();
        this.create = create;
    }

    
}
