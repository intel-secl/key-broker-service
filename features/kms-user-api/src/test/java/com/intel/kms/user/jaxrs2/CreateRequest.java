/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.intel.dcsg.cpg.io.Attributes;
import com.intel.mtwilson.jaxrs2.AbstractDocument;

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
