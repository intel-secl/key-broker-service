/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.jaxrs2.AbstractDocument;

/**
 *
 * @author jbuhacoff
 */
public class DeleteRequest<T extends AbstractDocument> extends AbstractRequest {
    private T item;
    
    public DeleteRequest() {
        super();
    }

    public DeleteRequest(T item) {
        super();
        this.item = item;
    }

    public UUID getId() { 
        return item.getId();
    }
}
