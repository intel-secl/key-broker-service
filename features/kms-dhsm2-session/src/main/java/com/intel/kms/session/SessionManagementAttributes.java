/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.sessionManagement;

import com.intel.dcsg.cpg.io.Attributes;
import com.intel.dcsg.cpg.io.Copyable;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.ArrayList;

/**
 *
 * @author shefalik 
 */

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class SessionManagementAttributes extends Attributes implements Copyable {

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SessionManagementAttributes.class);
    private String challengeType;
    private String challenge;
    private String quote;
    private String certificateChain;
    private byte[] SWK;
    private String algoType;

    protected void setChallengeType(String challengeType) {
        this.challengeType = challengeType;
    }

    public String getChallengeType() {
        return challengeType;
    }

    protected void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getChallenge() {
        return challenge;
    }

    protected void setQuote(String quote) {
        this.quote = quote;
    }

    public String getQuote() {
        return quote;
    }

    protected void setCertificateChain(String certificateChain) {
        this.certificateChain = certificateChain;
    }

    public String getCertificateChain() {
        return certificateChain;
    }

    protected void setSWK(byte[] SWKKey) {
        this.SWK = SWKKey;
    }

    public byte[] getSWK() {
        return SWK;
    }

    protected void setAlgoType(String algoType) {
        this.algoType = algoType;
    }

    @JsonProperty("type")
    public String getAlgoType() {
        return algoType;
    }

    public void copyFrom(SessionManagementAttributes source) {
        super.copyFrom(source);
        this.setQuote(source.getQuote());
        this.setCertificateChain(source.getCertificateChain());
        this.setChallengeType(source.getChallengeType());
        this.setChallenge(source.getChallenge());
    }
}
