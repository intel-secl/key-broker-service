/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonUnwrapped;

/**
 *
 * @author jbuhacoff
 */
public class CreateRequest<T> extends AbstractRequest {
    
    private T item;
    
    public CreateRequest() {
        super();
    }

    public CreateRequest(T item) {
        super();
        this.item = item;
    }
    
    @JsonUnwrapped
    public T getItem() {
        return item;
    }


}
