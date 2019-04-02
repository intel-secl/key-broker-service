/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.mtwilson.util.crypto;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.dcsg.cpg.http.MutableQuery;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class DeriveKeyTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DeriveKeyTest.class);
    
    @Test
    public void testDeriveEncryptionKeyFromMasterKey() throws NoSuchAlgorithmException, InvalidKeyException {
        // inputs for derived key
        int keyLengthBits = 128;
        
        MutableQuery query = new MutableQuery();
        query.add("keyuse", "encryption");
        query.add("context", "dm-crypt");
        query.add("algorithm", "AES");
        query.add("mode", "XTS");
        query.add("length", String.valueOf(keyLengthBits));
        log.debug("derived key info: {}", query.toString());
        
        // simulated input master key
        byte [] masterKey = RandomUtil.randomByteArray(32);
        
        int keyLengthBytes = keyLengthBits / 8;
        HKDF hkdf = new HKDF("HmacSHA256"); // throws NoSuchAlgorithmException
        byte[] salt = RandomUtil.randomByteArray(128);
        byte[] info = query.toString().getBytes(Charset.forName("UTF-8"));
        byte[] derivedKey = hkdf.deriveKey(salt, masterKey, keyLengthBytes, info); // throws InvalidKeyException
            
        log.debug("derived key length: {}", derivedKey.length);
        
    }
}
