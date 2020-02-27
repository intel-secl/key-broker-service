/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.key.transfer;

import com.intel.dcsg.cpg.io.Attributes;
import com.intel.dcsg.cpg.io.Copyable;
import com.intel.dcsg.cpg.iso8601.Iso8601Date;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonRawValue;
import java.util.List;
import java.util.ArrayList;

/**
 *
 * @author rbhat
 */

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class KeyTransferAttributes extends Attributes implements Copyable {

    private List<String> acceptChallenge = new ArrayList<>();
    private List<String> sessionId = new ArrayList<>();
    private String keyId;
    private String keyData;
    private String keyAlgorithm;
    private Integer keyLength;
    private String policy;

    @JsonFormat(shape=JsonFormat.Shape.STRING, pattern="yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private Iso8601Date createdAt;

    public KeyTransferAttributes() {
    }

    public KeyTransferAttributes(String keyId) {
	this.keyId = keyId;
    }

    public ArrayList<String> getAcceptChallenge()
    {
        ArrayList<String> acceptChallenge = new ArrayList<String>();
	for (String obj : this.acceptChallenge)
	    acceptChallenge.add(obj);
	return acceptChallenge;
    }

    protected void setAcceptChallenge(ArrayList<String> acceptChallenge)
    {
	for (String obj : acceptChallenge)
	    this.acceptChallenge.add(obj);
    }

    public ArrayList<String> getSessionId()
    {
    	ArrayList<String> sessionId = new ArrayList<String>();
	for (String obj : this.sessionId)
	    sessionId.add(obj);
	return sessionId;
    }

    protected void setSessionId(ArrayList<String> sessionId)
    {
	for (String obj : sessionId)
	    this.sessionId.add(obj);
    }

    protected void setKeyId(String keyId)
    {
	this.keyId = keyId;
    }

    @JsonProperty("id")
    public String getKeyId()
    {
	return this.keyId;
    }

    @JsonProperty("payload")
    public String getKeyData() {
	return keyData;
    }
    
    protected void setKeyData(String keyData) {
        this.keyData = keyData;
    }

    @JsonProperty("algorithm")
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }
    
    protected void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }
 
    @JsonProperty("key_length")
    public Integer getKeyLength() {
        return keyLength;
    }
    
    protected void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    @JsonRawValue
    public String getPolicy()
    {
	return this.policy;
    }

    protected void setPolicy(String policy)
    {
	this.policy = policy;
    }

    protected void setCreatedAt(Iso8601Date createdAt)
    {
	this.createdAt = createdAt;
    }

    public Iso8601Date getCreatedAt()
    {
	return this.createdAt;
    }
}
