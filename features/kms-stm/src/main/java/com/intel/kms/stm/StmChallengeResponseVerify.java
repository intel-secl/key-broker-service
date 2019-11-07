/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.stmlib;

import static com.intel.mtwilson.configuration.ConfigurationFactory.getConfiguration;
import com.sun.jna.Memory;
import com.sun.jna.ptr.PointerByReference;
import java.util.Map;
import java.util.HashMap;

/**
 * StmChallengeResponseVerify class is used to verify challenge response received by Keyagent STM
 *
 * @author rbhat
 */
public class StmChallengeResponseVerify {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StmChallengeResponseVerify.class);

    private String keyType;
    private byte[] publicKey;
    static final private Map<String, byte[]> stmAttributes = new HashMap<String, byte[]>();

    protected void setKeyType(String keyType)
    {
	this.keyType = keyType;
    }

    public String getKeyType()
    {
	return this.keyType;
    }

    protected void setPublicKey(byte[] publicKey)
    {
	this.publicKey = publicKey;
    }

    public byte[] getPublicKey()
    {
	return this.publicKey;
    }

    public static Map<String, byte[]> getMap() {
	return stmAttributes;
    }

    protected void storeKeyValue(String key, byte[] value) {
	if (key.equalsIgnoreCase("CHALLENGE_KEYTYPE")) {
	    setKeyType(new String(value).trim());
	}
	if (key.equalsIgnoreCase("CHALLENGE_RSA_PUBLIC_KEY")) {
	    setPublicKey(value);
	}
	else {
	    stmAttributes.put(key, value);
	}
    }

    protected StmLibrary.StmChallengeQuote.ByReference prepareStmQuote(byte[] quote) {
	// prepare STM challenge quote to be sent to STM
	StmLibrary.StmByteArray.ByReference stmByteArray = new StmLibrary.StmByteArray.ByReference();
	stmByteArray.data = new Memory(quote.length + 1);
	stmByteArray.data.clear(quote.length + 1);
	stmByteArray.length = quote.length;
	stmByteArray.data.write(0L, quote, 0, quote.length);
	StmLibrary.StmChallengeQuote.ByReference Quote = new StmLibrary.StmChallengeQuote.ByReference();
	Quote.bytes = stmByteArray;
	return Quote;
    }

    protected StmLibrary.StmChallengeGetAttrRes.ByReference prepareStmResponse() {
	// prepare the STM Challenge response structure to be received from STM
	StmLibrary.StmByteArray.ByReference bytes = new StmLibrary.StmByteArray.ByReference();

	StmLibrary.StmBufferPtr.ByReference bufferPtr = new StmLibrary.StmBufferPtr.ByReference();
	bufferPtr.bytes = bytes;

	StmLibrary.StmGetAttrs.ByReference attrs = new StmLibrary.StmGetAttrs.ByReference();
	attrs.value = bufferPtr;

	StmLibrary.StmGetAttrSet.ByReference attrSet = new StmLibrary.StmGetAttrSet.ByReference();
	attrSet.attrs = attrs;

	StmLibrary.StmChallengeGetAttrRes.ByReference challengeAttr = new StmLibrary.StmChallengeGetAttrRes.ByReference();
	challengeAttr.refPtr = attrSet;
	return challengeAttr;
    }

    /**
     * StmChallengeVerifyResponse class sends a challenge quote consisting of Public key and other
     * attributes received from Keyagent STM to Keyserver STM for verification.
     * Once the verification is successful, the keytype, public key and other attributes are stored
     * for subsequent use by session/transfer apis.
     *
     * @param Challenge quote buffer received from Keyagent STM
     *
     * @return true if the respose is verified successfully and attributes retrieved. false otherwise
     */
 
    public boolean StmChallengeVerifyResponse(byte[] quoteRes, String activeStmLabel) {
	boolean stmVerifyResponse = false;
	PointerByReference errPtrRef = new PointerByReference();
	// stm lib has dependency on libssl.so
	SslLibrary sslLib = SslLibrary.SSL_INSTANCE;

	StmLoadLibrary stmLoadLib = new StmLoadLibrary();
	StmLibrary stmLib = stmLoadLib.getActiveStmLibInstance(activeStmLabel);

	if (sslLib == null || stmLib == null) {
	    log.error("no openssl/stm libs were found.");
	    return stmVerifyResponse;
	}

	// prepare quote to be sent to stm as per JNA structure
	StmLibrary.StmChallengeQuote.ByReference Quote = prepareStmQuote(quoteRes);
	// prepare stm challenge response to be received from stm as per JNA structure
	StmLibrary.StmChallengeGetAttrRes.ByReference challengeAttr = prepareStmResponse();

	// invoke STM library stm_challenge_verify function to get stm attestation report
	stmVerifyResponse = stmLib.stm_challenge_verify(Quote, challengeAttr, errPtrRef);

	if(stmVerifyResponse) {
	    // challengeAttr buffer will have STM attestation report
	    // extract and store the stm attestation report attrributes like keytype, public key
	    int attrCount = challengeAttr.refPtr.count;

	    // read attrCount number of attributes (Key,value Pair)
	    StmLibrary.StmGetAttrs.ByReference attrsArray[] = (StmLibrary.StmGetAttrs.ByReference[])challengeAttr.refPtr.attrs.toArray(attrCount);

	    // for sw stm, expect keytype, rsa/ecc public key and sw issuer string in response
	    // for sgx stm, expect keytype, sgx enclave rsa/ecc public key and sgx attributes
	    // iterate through the response and store each attribute from attestation report
	    for (StmLibrary.StmGetAttrs.ByReference attr: attrsArray) {
		String keyName = attr.name;
		byte[] attrValue = attr.value.bytes.data.getByteArray(0, attr.value.bytes.length);
		log.debug("KeyName {} : Value {}", keyName, attrValue);
		storeKeyValue(keyName, attrValue);
	    }
	}
	else {
	    log.error("stm_challenge_verify failed with error {}", errPtrRef.getValue().getString(0));
	}

	Memory.disposeAll();
	return stmVerifyResponse;
    }
}
