/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonUnwrapped;

/**
 *
 * @author jbuhacoff
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY) // jackson 2.0
public abstract class AbstractRequest<T> {
    private T data;
    

    @JsonUnwrapped
    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    
}
