/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.cipher;

import com.intel.dcsg.cpg.crypto.RsaUtil;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jbuhacof
 */
public class TransferPublicKeyCipherTest {
    @Test
    public void testPermittedKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = RsaUtil.generateRsaKeyPair(2048);
        assertTrue(TransferPublicKeyCipher.isPermitted(keyPair.getPublic()));
    }
    
    @Test
    public void testRelatedKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = RsaUtil.generateRsaKeyPair(2048);
        assertTrue(TransferPublicKeyCipher.isRelated(keyPair.getPrivate(), keyPair.getPublic()));
    }
    
    @Test
    public void testUnrelatedKey() throws NoSuchAlgorithmException {
        KeyPair keyPair1 = RsaUtil.generateRsaKeyPair(2048);
        KeyPair keyPair2 = RsaUtil.generateRsaKeyPair(2048);
        assertFalse(TransferPublicKeyCipher.isRelated(keyPair1.getPrivate(), keyPair2.getPublic()));
    }
}
