/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.api.fault;

import com.intel.dcsg.cpg.validation.Fault;

/**
 *
 * @author jbuhacoff
 */
public class InvalidParameter extends Fault {
    private String parameter;
    private Fault cause;

    public InvalidParameter(String parameter) {
        super(parameter);
        this.parameter = parameter;
    }

    public InvalidParameter(String parameter, Fault cause) {
        super(parameter);
        this.parameter = parameter;
        this.cause = cause;
    }
    
    public String getParameter() {
        return parameter;
    }

    public Fault getCause() {
        return cause;
    }
    
}
