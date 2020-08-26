/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.kms.dhsm2.sessionManagement;

import com.intel.dcsg.cpg.io.Attributes;
import com.intel.dcsg.cpg.io.Copyable;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 *
 * @author srajen4x
 */

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class QuoteVerifyResponseAttributes extends Attributes implements Copyable {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(QuoteVerifyResponseAttributes.class);
    private String status;
    private String message;
    private String challengeKeyType;
    private String challengeRsaPublicKey;
    private String enclaveIssuer;   
    private String enclaveIssuerProdID;
    private String enclaveIssuerExtProdID;
    private String enclaveMeasurement;
    private String configSvn;
    private String isvSvn;               
    private String configId;
    private String tcbLevel;

    public void setStatus(String status) {
	this.status = status;
    }

    public String getStatus() {
	return status;
    }

    public void setMessage(String message) {
	this.message = message;
    }

    public String getMessage() {
	return message;
    }

    public void setChallengeKeyType(String challengeKeyType) {
	this.challengeKeyType = challengeKeyType;
    }

    public String getChallengeKeyType() {
	return challengeKeyType;
    }

    public void setChallengeRsaPublicKey(String challengeRsaPublicKey) {
	this.challengeRsaPublicKey = challengeRsaPublicKey;
    }

    public String getChallengeRsaPublicKey() {
	return challengeRsaPublicKey;
    }

    public void setEnclaveIssuer(String enclaveIssuer) {
	this.enclaveIssuer = enclaveIssuer;
    }

    public String getEnclaveIssuer() {
	return enclaveIssuer;
    }

    public void setEnclaveIssuerProdID(String enclaveIssuerProdID) {
	this.enclaveIssuerProdID = enclaveIssuerProdID;
    }

    public String getEnclaveIssuerProdID() {
	return enclaveIssuerProdID;
    }

    public void setEnclaveIssuerExtProdID(String enclaveIssuerExtProdID) {
	this.enclaveIssuerExtProdID = enclaveIssuerExtProdID;
    }

    public String getEnclaveIssuerExtProdID() {
	return enclaveIssuerExtProdID;
    }

    public void setEnclaveMeasurement(String enclaveMeasurement) {
	this.enclaveMeasurement = enclaveMeasurement;
    }

    public String getEnclaveMeasurement() {
	return enclaveMeasurement;
    }

    public void setConfigSvn(String configSvn) {
	this.configSvn = configSvn;
    }

    public String getConfigSvn() {
	return configSvn;
    }

    public void setIsvSvn(String isvSvn) {
	this.isvSvn = isvSvn;
    }

    public String getIsvSvn() {
	return isvSvn;
    }

    public void setConfigId(String configId) {
	this.configId = configId;
    }

    public String getConfigId() {
	return configId;
    }

    public void setTcbLevel(String tcbLevel) {
	this.tcbLevel = tcbLevel;
    }

    public String getTcbLevel() {
	return tcbLevel;
    }

    public void copyFrom(QuoteVerifyResponseAttributes source) {
        super.copyFrom(source);
	this.setStatus(source.getStatus());
	this.setMessage(source.getMessage());
	this.setChallengeKeyType(source.getChallengeKeyType());
	this.setChallengeRsaPublicKey(source.getChallengeRsaPublicKey());
	this.setEnclaveIssuer(source.getEnclaveIssuer());
	this.setEnclaveIssuerProdID(source.getEnclaveIssuerProdID());
	this.setEnclaveIssuerExtProdID(source.getEnclaveIssuerExtProdID());
	this.setEnclaveMeasurement(source.getEnclaveMeasurement());
	this.setConfigSvn(source.getConfigSvn());
	this.setIsvSvn(source.getIsvSvn());
	this.setConfigId(source.getConfigId());
	this.setTcbLevel(source.getTcbLevel());
    }
}
