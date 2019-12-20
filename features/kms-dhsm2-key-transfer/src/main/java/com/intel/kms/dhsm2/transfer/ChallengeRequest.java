/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.key.transfer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonRawValue;

/**
 * ChallenegeRequest class is responsible for challenge
 * generation request for a new session with keyagent
 * @author rbhat
 */

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class ChallengeRequest extends KeyTransferResponse {

    private String challenge;
    private String challengeType;
    private String link;

    protected void setChallenge(String challenge)
    {
	this.challenge = challenge;
    }

    public String getChallenge()
    {
	return this.challenge;
    }

    protected void setChallengeType(String challengeType)
    {
	this.challengeType = challengeType;
    }

    public String getChallengeType()
    {
	return this.challengeType;
    }
    
    protected void setLink(String link)
    {
	this.link = link;
    }

    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    @JsonRawValue
    public String getLink()
    {
	return this.link;
    }
}
