/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
