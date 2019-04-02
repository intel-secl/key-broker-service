/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.cipher;

import com.intel.dcsg.cpg.crypto.Aes;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.digest.Digest;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeFactory;
import com.intel.kms.cipher.cmd.SecretKeyEnvelope;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.SecretKey;
import org.junit.Test;

/**
 *
 * @author jbuhacof
 */
public class TransferKeyTest {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransferKeyTest.class);

    /**
     * 
     * <pre>
     * -----BEGIN ENCRYPTED KEY----- 
     * Content-Algorithm: AES
     * Encryption-Algorithm: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
     * Encryption-Key-Id:
     * f41ab1c9d07bf5e0159ffe6091c325782a7e083de588c1934643b72102e63718
     *
     * ayR8NvkjS3GC1j8VpYs/WL3gRYWSLvlRDGeSFafjNyhUfjz3EcCFuXpaqsLX7zTw/zgF74e3oo/3
     * nI0APHl/ENrxMRcUTkwDbcbHjwY9RjPu2f+udC+Y2aYEaFhrb92tQ64+Frrv5476pEZ1WVM+/yu0
     * lw2u4mA+GVeDld/YOoVF2gHSrhbwlvH3iQ0FXpwXXjEt0B/Tc1dJbzzGb9sNHm0DH1qFtBfIb4l0
     * VlNr364miGq9Bp1CHLBPxdvQ0hiEaCWdKJGajcHVQWqweSsFxpabZMVYRTjEfUzb/nJouOL6a1h3
     * d3uMM76F3KBGAo5EVt1fnudTLnJiIZJ5Abbwng== 
     * -----END ENCRYPTED KEY-----
     * </pre>
     *
     * @throws NoSuchAlgorithmException
     * @throws CryptographyException
     */
    @Test
    public void wrapSecretKeyWithEnvelopePublicKey() throws NoSuchAlgorithmException, CryptographyException {
        SecretKey secretKey = Aes.generateKey(128);
        KeyPair keyPair = RsaUtil.generateRsaKeyPair(2048);
        String pem = SecretKeyEnvelope.encryptSecretKeyWithEnvelopePublicKey(secretKey, (RSAPublicKey) keyPair.getPublic());
        log.debug("wrapped key:\n{}\n", pem);
    }


}
