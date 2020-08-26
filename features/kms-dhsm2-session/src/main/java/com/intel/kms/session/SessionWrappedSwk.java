/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.sessionManagement;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * StmWrappedSwk class is used to create an AES SWK and wrap it with
 * the Public key obtained from workload as part of verify challenge
 * response. The resulting Wrapped SWK is sent to workload in
 * session create response
 *
 * @author rbhat
 */

public class SessionWrappedSwk {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SessionWrappedSwk.class);
    private byte[] swkKey;
    private byte[] wrappedSwkKey;
    private static final int AESKEYBITSIZE = 256;
 
    protected void setSwkKey(byte[] swkKey)
    {
	this.swkKey = swkKey;
    }

    public byte[] getSwkKey()
    {
	return this.swkKey;
    }

    protected void setWrappedSwkKey(byte[] wrappedSwkKey)
    {
	this.wrappedSwkKey = wrappedSwkKey;
    }

    public byte[] getWrappedSwkKey()
    {
	return this.wrappedSwkKey;
    }

    public String getSwkKeyType(String activeStmLabel)
    {
        String keyType;
        switch(activeStmLabel.toUpperCase()) {
            case "SW":
                keyType = String.format("AES%s-WRAP", AESKEYBITSIZE);
                break;
            case "SGX":
                keyType = String.format("AES%s-GCM", AESKEYBITSIZE);
                break;
            default:
                log.error("no active stm label set in kms");
                keyType = null;
                break;
        }
        return keyType;
    }

    public boolean SessionCreateSwk() {
	boolean createSwkResponse = false;
	try {
	    // create an AES key of 256 bit length 
	    final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    SecureRandom secureRandom = new SecureRandom();
	    keyGenerator.init(AESKEYBITSIZE, secureRandom);

	    SecretKey swkKey = keyGenerator.generateKey();
	    setSwkKey(swkKey.getEncoded());
	    log.debug("created AES SWK {}", getSwkKey());
	    createSwkResponse = true;
	} catch (NoSuchAlgorithmException ex) {
	    log.error("Exception during SWK creation. {}", ex.getMessage());
	}
	return createSwkResponse;
    }

    /**
     * SessionCreateAndWrapSwk creates an 256 bit AES Symmetric Wrapping key and
     * wraps it with the Public Key received as part of STM attestation Report
     * The wrapped SWK Key can be accessed through getWrappedSwkKey method
     * @param DER Encoded Public Key received from workload STM
     *
     * @return true if creation/wrapping of SWK key is successful. false otherwise
     */
    public boolean SessionCreateAndWrapSwk(String wrapKeyType, String wrapPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException {
	boolean createandWrapSwkResponse = false;
	createandWrapSwkResponse = SessionCreateSwk();
	if (createandWrapSwkResponse) {
	    if(wrapKeyType.equalsIgnoreCase("RSA")) {
		createandWrapSwkResponse = SessionWrapSwkWithRSAKey(wrapKeyType, wrapPublicKey);
	    }
	    else {
		log.error("Currently only RSA key support is available");
	    }
	}
	else {
	    log.error("unable to create SWK");
	}
	return createandWrapSwkResponse;
    }

    protected boolean SessionWrapSwkWithRSAKey(String wrapKeyType, String publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException {

	boolean sessionSWkResponse = false;

	log.debug("Got Request to create SWK key and wrap with workload Public Key");
	try {
	    // convert the DER Encoded Input raw public Key to Java PublicKey Format
	    Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA-1AndMGF1Padding");
	    if( cipher== null ){
		log.error("cipher object is null");
		return sessionSWkResponse;
	    }
	    String publicKeyContent = publicKey.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);

	    PublicKey pubKey = KeyFactory.getInstance(wrapKeyType).generatePublic(new X509EncodedKeySpec(publicKeyBytes));

	    byte[] swk = getSwkKey();
	    // SWK Key is always AES 256 bit key
	    SecretKey swkKey = new SecretKeySpec(swk, 0, swk.length, "AES");
	    // wrap the AES Swk with workload RSA Public Key
	    cipher.init(Cipher.WRAP_MODE, pubKey);
	    setWrappedSwkKey(cipher.wrap(swkKey));

	    sessionSWkResponse = true;
	    log.debug("SessionWrapSwkWithRSAKey completed");
	    
	} catch (NullPointerException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidKeySpecException ex) {
                log.error("Error during SWK creation and wrapping. {}", ex.getMessage());
                throw ex;
	}
	return sessionSWkResponse;
    }
}
