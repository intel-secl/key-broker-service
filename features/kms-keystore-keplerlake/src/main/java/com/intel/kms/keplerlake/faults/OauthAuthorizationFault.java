/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake.faults;

import com.intel.dcsg.cpg.validation.Fault;

/**
 *
 * @author SSHEKHEX
 */
public class OauthAuthorizationFault extends Fault {
    
    private String parameter;
    private Fault cause;
    
    public OauthAuthorizationFault(String description) {
        super(description);
    }

    public OauthAuthorizationFault(String parameter, Fault cause) {
        super(parameter);
        this.parameter = parameter;
        this.cause = cause;
    }

    /**
     * @return the parameter
     */
    public String getParameter() {
        return parameter;
    }

    /**
     * @return the cause
     */
    public Fault getCause() {
        return cause;
    }

}
