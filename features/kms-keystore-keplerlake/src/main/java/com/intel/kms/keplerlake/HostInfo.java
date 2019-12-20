/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake;

import java.security.PublicKey;

/**
 *
 * @author SSHEKHEX
 */
public class HostInfo {
    
    private String sessionToken;
    private String hostname;
    private String callbackToken;
    private String flavor;
    private PublicKey bindingKey;
    private String aikpublickey;

    public String getAikpublickey() {
        return aikpublickey;
    }

    public void setAikpublickey(String aikpublickey) {
        this.aikpublickey = aikpublickey;
    }
                    

    /**
     * @return the sessionToken
     */
    public String getSessionToken() {
        return sessionToken;
    }

    /**
     * @param sessionToken the sessionToken to set
     */
    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }

    /**
     * @return the hostname
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * @param hostname the hostname to set
     */
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    /**
     * @return the callbackToken
     */
    public String getCallbackToken() {
        return callbackToken;
    }

    /**
     * @param callbackToken the callbackToken to set
     */
    public void setCallbackToken(String callbackToken) {
        this.callbackToken = callbackToken;
    }

    /**
     * @return the flavor
     */
    public String getFlavor() {
        return flavor;
    }

    /**
     * @param flavor the flavor to set
     */
    public void setFlavor(String flavor) {
        this.flavor = flavor;
    }

    /**
     * @return the bindingKey
     */
    public PublicKey getBindingKey() {
        return bindingKey;
    }

    /**
     * @param bindingKey the bindingKey to set
     */
    public void setBindingKey(PublicKey bindingKey) {
        this.bindingKey = bindingKey;
    }
    
}
