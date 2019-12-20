/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonUnwrapped;

/**
 *
 * @author jbuhacoff
 */
public class CreateResponse<T> extends AbstractResponse {
    @JsonUnwrapped
    private T item;
    
    public CreateResponse() {
        super();
    }

    public CreateResponse(T item) {
        super();
        this.item = item;
    }
    
    @JsonIgnore
    public T getCreated() {
        return item;
    }

}
