/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.intel.mtwilson.jaxrs2.AbstractDocument;

/**
 *
 * @author jbuhacoff
 */
public class EditRequest<T extends AbstractDocument> extends AbstractRequest {

    @JsonUnwrapped
    private T item;
    
    public EditRequest() {
        super();
    }

    public EditRequest(T item) {
        super();
        this.item = item;
    }
    
    @JsonIgnore
    public T getItem() {
        return item;
    }

    
}
