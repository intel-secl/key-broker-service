/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api.fault;

import com.intel.dcsg.cpg.validation.Fault;

/**
 * This fault represents not being able to obtain the configuration, when
 * {@code ConfigurationFactory.getConfiguration()} throws an IOException.
 * 
 * @author jbuhacoff
 */
public class ConfigurationUnavailable extends Fault {
    private Throwable cause;

    public ConfigurationUnavailable(Throwable cause) {
        super(cause.getMessage());
        this.cause = cause;
    }

    public Throwable getCause() {
        return cause;
    }
    
    
}
