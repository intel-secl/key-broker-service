/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
