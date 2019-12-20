/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.api;

import com.intel.kms.api.util.AbstractResponse;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.List;


public class SearchKeyAttributesResponse extends AbstractResponse {
    public SearchKeyAttributesResponse() {
        super();
    }
    
    private final ArrayList<KeyAttributes> data = new ArrayList<>();
    private String operation;
    private String status;
    
    @JsonInclude(value = JsonInclude.Include.ALWAYS)
    public final List<KeyAttributes> getData() { return data; }

    @JsonInclude(value = JsonInclude.Include.ALWAYS)
    public final String getOperation() { return operation; }

    @JsonInclude(value = JsonInclude.Include.ALWAYS)
    public final String getStatus() { return status; }

    public final void setOperation(String operation) {
       this.operation = operation;
    }
    
    public final void setStatus(String status) {
        this.status = status;
    } 
}
