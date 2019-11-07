/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.usage.policy;

import com.fasterxml.jackson.annotation.JsonInclude;
/**
 * The CreateKeyUsagePolicyResponse contains either key Usage Policy
 * attributes or any faults that prevented the key usage policy from
 * being created. 
 *
 * @author rbhat
 */
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class CreateKeyUsagePolicyResponse extends ReadKeyUsagePolicyResponse {

    public CreateKeyUsagePolicyResponse() {
        super();
    }

    public CreateKeyUsagePolicyResponse(KeyUsagePolicyAttributes created) {
        super();
        getData().add(created);
    }
}
