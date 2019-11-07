/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.stmlib;

import com.sun.jna.ptr.PointerByReference;

/**
 * StmChallenge class sends a challenge request to KMS STM to get a session ID
 * @author rbhat
 */

public class StmChallenge {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StmChallenge.class);
    private String sessionId;
 
    protected void setSessionId(String sessionId)
    {
	this.sessionId = sessionId;
    }

    public String getSessionId()
    {
	return this.sessionId;
    }

    /**
     * StmChallengeGenerateRequest method returns true if KMS STM generated a session id
     * @param placeholder where the session id will be returned back
     * @return true if challenge generated an session id. else false
     */
    public boolean StmChallengeGenerateRequest(String stmLabel) {
	boolean stmResponse = false;
	final PointerByReference requestSessionId = new PointerByReference();
	final PointerByReference errPtrRef = new PointerByReference();

	log.debug("Requesting for a new session id from STM");
	StmLoadLibrary stmLoadLib = new StmLoadLibrary();
	StmLibrary stmLib = stmLoadLib.getActiveStmLibInstance(stmLabel);

	if (stmLib == null) {
	    log.error("no stm libs were found.");
	    return stmResponse;
	}
	// invoke KMS STM challenge_request api to get a session id
	stmResponse = stmLib.stm_challenge_generate_request(requestSessionId, errPtrRef);

	if(stmResponse) {
	   // Call was succesful, extract the session id from the response
	    String sessionId = requestSessionId.getValue().getString(0);
	    setSessionId(sessionId);
	    log.debug("StmChallengeGenerate returned session id as {}", getSessionId());
	}
	else {
	    log.error("StmChallengeGenerate failed with error {}", errPtrRef.getValue().getString(0));
	}
	return stmResponse;
    }
}
