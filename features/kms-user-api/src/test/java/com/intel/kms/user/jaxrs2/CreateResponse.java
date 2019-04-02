/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.intel.mtwilson.jaxrs2.AbstractDocument;

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
