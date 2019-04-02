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
public class EditUserResponse extends FindUsersResponse {

    public EditUserResponse() {
        super();
    }

    public EditUserResponse(User edited) {
        super();
        getData().add(edited);
    }
}
