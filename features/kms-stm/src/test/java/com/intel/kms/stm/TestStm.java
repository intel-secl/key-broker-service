/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.stmlib;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author rbhat
 */
public class TestStm {
    private Logger log = LoggerFactory.getLogger(getClass());
    
    @Test
    public void testStmChallenge() {
	StmChallenge stmChallenge = new StmChallenge();
	assertTrue(stmChallenge.StmChallengeGenerateRequest("SW"));
    }

    @Test
    public void testStmChallengeResponseVerify() {
	StmChallengeResponseVerify stmChallengeResponseVerify = new StmChallengeResponseVerify();

	/**
	 * Pass an Valid Challenge quote response from key agent consisting of SW issuer name
	 * with STM_ISSUER_SIZE=100 and the public key in pem format
	 */
	String validQuoteRequest = "Intel-SGX                                                                                           -----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzM6ujJ8EUrlyP/7DO6PH\nOqG7QFz49zs/TF3mzPBZziZ3fjmw9oqzYzp2zhYOLFZefaH0z+42g5ebUrwjdgUJ\nNkhzFxSWmK3ZU1qpWIE9soPfmQSGdR63gP/wydRAB3oal8lMSmJGqNc7PdToyaZl\nipC8eSvB5kA5tx4efpEr+8D17J43CNxE4ylP1kAOO7MMOzlzRFbBFsoCg3mHelGf\nJXn9D7AO3YWDPofXADvjcYmjT/F90lLBULaMpWtqUHTlI+yJfcGDNRdvniD4bj2Y\nQByg4rM7OE4AgqsWcsI4aJ5f0+JTAoauHe5gSrY6WrjA54jHRELZZvEJL0x6YLYt\n4wIDAQAB\n-----END PUBLIC KEY-----";
	assertTrue(stmChallengeResponseVerify.StmChallengeVerifyResponse(validQuoteRequest.getBytes(), "SW"));

	 /**
	 *  pass an invalid quote request which contains only valid keyagent public key without Sw Issuer String
	 */
	String invalidQuoteRequest = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzM6ujJ8EUrlyP/7DO6PH\nOqG7QFz49zs/TF3mzPBZziZ3fjmw9oqzYzp2zhYOLFZefaH0z+42g5ebUrwjdgUJ\nNkhzFxSWmK3ZU1qpWIE9soPfmQSGdR63gP/wydRAB3oal8lMSmJGqNc7PdToyaZl\nipC8eSvB5kA5tx4efpEr+8D17J43CNxE4ylP1kAOO7MMOzlzRFbBFsoCg3mHelGf\nJXn9D7AO3YWDPofXADvjcYmjT/F90lLBULaMpWtqUHTlI+yJfcGDNRdvniD4bj2Y\nQByg4rM7OE4AgqsWcsI4aJ5f0+JTAoauHe5gSrY6WrjA54jHRELZZvEJL0x6YLYt\n4wIDAQAB\n-----END PUBLIC KEY-----";
	assertFalse(stmChallengeResponseVerify.StmChallengeVerifyResponse(validQuoteRequest.getBytes(), "SW"));
	
	/** 
	 * pass an invalid quote request which contains valid SW Issuer String of STM_ISSUER_SIZe=100
	 * and without Key Agent Public Key
	 */
	invalidQuoteRequest = "Intel-SGX                                                                                           ";
	assertFalse(stmChallengeResponseVerify.StmChallengeVerifyResponse(validQuoteRequest.getBytes(), "SW"));
	
	/**
	 * pass an invalid quote request which contains SW Issuer String less the STM_ISSUER_SIZE (default 100)
	 * and valid PEM encoded public key
	 */
	invalidQuoteRequest = "Intel-SGX-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzM6ujJ8EUrlyP/7DO6PH\nOqG7QFz49zs/TF3mzPBZziZ3fjmw9oqzYzp2zhYOLFZefaH0z+42g5ebUrwjdgUJ\nNkhzFxSWmK3ZU1qpWIE9soPfmQSGdR63gP/wydRAB3oal8lMSmJGqNc7PdToyaZl\nipC8eSvB5kA5tx4efpEr+8D17J43CNxE4ylP1kAOO7MMOzlzRFbBFsoCg3mHelGf\nJXn9D7AO3YWDPofXADvjcYmjT/F90lLBULaMpWtqUHTlI+yJfcGDNRdvniD4bj2Y\nQByg4rM7OE4AgqsWcsI4aJ5f0+JTAoauHe5gSrY6WrjA54jHRELZZvEJL0x6YLYt\n4wIDAQAB\n-----END PUBLIC KEY-----";
	assertFalse(stmChallengeResponseVerify.StmChallengeVerifyResponse(validQuoteRequest.getBytes(), "SW"));

	/**
	 * pass an invalid quote request which contains Valid SW Issuer String less the STM_ISSUER_SIZE (default 100)
	 * and invalid PEM encoded public key
	 */
	invalidQuoteRequest = "Intel-SGX                                                                                           MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzM6ujJ8EUrlyP/7DO6PH\nOqG7QFz49zs/TF3mzPBZziZ3fjmw9oqzYzp2zhYOLFZefaH0z+42g5ebUrwjdgUJ\nNkhzFxSWmK3ZU1qpWIE9soPfmQSGdR63gP/wydRAB3oal8lMSmJGqNc7PdToyaZl\nipC8eSvB5kA5tx4efpEr+8D17J43CNxE4ylP1kAOO7MMOzlzRFbBFsoCg3mHelGf\nJXn9D7AO3YWDPofXADvjcYmjT/F90lLBULaMpWtqUHTlI+yJfcGDNRdvniD4bj2Y\nQByg4rM7OE4AgqsWcsI4aJ5f0+JTAoauHe5gSrY6WrjA54jHRELZZvEJL0x6YLYt\n4wIDAQAB";
	assertFalse(stmChallengeResponseVerify.StmChallengeVerifyResponse(validQuoteRequest.getBytes(), "SW"));
    }
    
    @Test
    public void testStmWrapSwk() {
	try {
	    /**
	     * Create an RSA Public/Private KeyPair of 2048 bit length and
	     * extract the public/private key as raw DER encoded bytestream
	     * Pass the valid Public Key to StmCreateAndWrapSwk
	     */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.genKeyPair();
            byte[] pri = keyPair.getPrivate().getEncoded();
            byte[] pub = keyPair.getPublic().getEncoded();

	    StmWrappedSwk stmWrappedSwk = new StmWrappedSwk();
	    assertTrue(stmWrappedSwk.StmCreateAndWrapSwk("RSA", pub));

	    /**
	     * Pass an invalid public key byte stream
	     */
	    byte[] invalidPub = new byte[] { (byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF };
	    assertFalse(stmWrappedSwk.StmCreateAndWrapSwk("RSA", invalidPub));
	}
	catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidKeySpecException ex) {
	    log.debug("Exception while creating and wrapping SWK: {}", ex.getMessage());
	}
    }
}
