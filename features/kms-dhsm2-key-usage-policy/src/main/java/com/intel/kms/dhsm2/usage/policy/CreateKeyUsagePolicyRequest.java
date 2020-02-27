/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.usage.policy;

/**
 * To request the key server to create a new key Usage Policy, the key request
 * is essentially the set of key usage policy attributes that the key should
 * have. 
 * 
 * @author rbhat
 */
public class CreateKeyUsagePolicyRequest extends KeyUsagePolicyAttributes {

    public CreateKeyUsagePolicyRequest() {
        super();
    }
}
