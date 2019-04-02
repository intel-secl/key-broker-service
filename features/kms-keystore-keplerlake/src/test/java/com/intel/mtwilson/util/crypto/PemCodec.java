/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.util.crypto;

import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.keystore.SecretKeyStore;

/**
 *
 * @author jbuhacoff
 */
public class PemCodec {
    /**
     * The SecretKeyStore is used to lookup cipher keys for 
     * decrypting input Pem files
     */
    private SecretKeyStore secretKeyStore;
    
    /**
     * The CipherKey is used to encrypt output data
     */
    private CipherKey encryptionKey;
    
//    private CipherKeyRepository decryptionKeyRepository;
    
    public String encode(byte[] data) {
        return null;
    }
    
    public byte[] decode(String pem) {
        return null;
    }    
}
