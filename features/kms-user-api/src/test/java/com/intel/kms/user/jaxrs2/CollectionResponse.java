/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;

/**
 *
 * @author jbuhacoff
 */
public class CollectionResponse<T> extends AbstractResponse {
    private final ArrayList<T> data = new ArrayList<>();

    public CollectionResponse() {
        super();
    }

    @JsonInclude(value = JsonInclude.Include.ALWAYS)
    public final ArrayList<T> getData() {
        return data;
    }
    
    
}
