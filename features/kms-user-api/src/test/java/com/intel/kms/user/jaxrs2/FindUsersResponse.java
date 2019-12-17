/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.kms.user.User;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public class FindUsersResponse extends AbstractResponse {

    public FindUsersResponse() {
        super();
    }
    private final ArrayList<User> data = new ArrayList<>();

    @JsonInclude(value = JsonInclude.Include.ALWAYS)
    public List<User> getData() {
        return data;
    }
}
