/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.intel.dcsg.cpg.io.Attributes;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author jbuhacoff
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY) // jackson 2.0
public abstract class AbstractRequest<T> {
    private T data;
    
/*
    private final Attributes extensions = new Attributes();

    public AbstractRequest() {
        super();
    }

    @JsonIgnore
    public Attributes getExtensions() {
        return extensions;
    }
*/

    @JsonUnwrapped
    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    
}
