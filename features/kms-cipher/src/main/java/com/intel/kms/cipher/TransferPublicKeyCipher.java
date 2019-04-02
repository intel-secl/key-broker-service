/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.cipher;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeOpener;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author jbuhacof
 */
public class TransferPublicKeyCipher {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransferPublicKeyCipher.class);
    
    /**
     * 
     * @param publicKey
     * @return true if the public key is permitted
     */
    public static boolean isPermitted(PublicKey publicKey) {
        PublicKeyReport report = new PublicKeyReport(publicKey);
        return report.isPermitted();
    }
    
    public static boolean isPermitted(String algorithm, Integer keyLength) {
        PublicKeyReport report = new PublicKeyReport(algorithm, keyLength);
        return report.isPermitted();
    }
    
    public static boolean isRelated(PrivateKey privateKey, PublicKey publicKey) {
        String algorithm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        byte[] data = RandomUtil.randomByteArray(16);
        
        try {
            Cipher cipher = Cipher.getInstance(algorithm); // NoSuchAlgorithmException, NoSuchPaddingException
            // encrypt with public key
            cipher.init(Cipher.ENCRYPT_MODE, publicKey); // InvalidKeyException
            byte[] encrypted = cipher.doFinal(data);
            // decrypt with private key
            cipher.init(Cipher.DECRYPT_MODE, privateKey); // InvalidKeyException
            byte[] decrypted = cipher.doFinal(encrypted);
            // check data == decrypted
            return Arrays.equals(data, decrypted);
        }
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            log.debug("Cannot validate key pair relationship", e);
            return false;
        }
        
    }
}
