/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author kchinnax
 */
public class PolicyUri {

    @JsonProperty("uri")
    private String policyUri;

    public String getPolicyUri() {
        return policyUri;
    }

    public void setPolicyUri(String policyUri) {
        this.policyUri = policyUri;
    }

}
