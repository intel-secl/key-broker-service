/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.intel.kms.api.util.AbstractResponse;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.List;

//    @JacksonXmlRootElement(localName="host_attestation_collection")

public class SearchKeyAttributesResponse extends AbstractResponse {
    public SearchKeyAttributesResponse() {
        super();
    }
    
    private final ArrayList<KeyAttributes> data = new ArrayList<>();
    
    @JsonInclude(value = JsonInclude.Include.ALWAYS)
    public final List<KeyAttributes> getData() { return data; }
}
