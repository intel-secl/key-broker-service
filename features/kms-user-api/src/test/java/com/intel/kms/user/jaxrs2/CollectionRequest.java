/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;

/**
 *
 * @author jbuhacoff
 */
public class CollectionRequest<T> extends AbstractRequest {
    
    private final ArrayList<T> data = new ArrayList<>();

    public CollectionRequest() {
        super();
    }
    
    @JsonInclude(value = JsonInclude.Include.ALWAYS)
    public final ArrayList<T> getData() {
        return data;
    }
    
}
