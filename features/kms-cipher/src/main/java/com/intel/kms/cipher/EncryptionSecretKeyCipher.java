/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.cipher;

import javax.crypto.SecretKey;

/**
 *
 * @author jbuhacof
 */
public class EncryptionSecretKeyCipher {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(EncryptionSecretKeyCipher.class);
    
    /**
     * 
     * @param secretKey
     * @return true if the secret key is permitted
     */
    public static boolean isPermitted(SecretKey secretKey) {
        SecretKeyReport report = new SecretKeyReport(secretKey);
        return report.isPermitted();
    }
    
    public static boolean isPermitted(String algorithm, Integer keyLength) {
        SecretKeyReport report = new SecretKeyReport(algorithm, keyLength);
        return report.isPermitted();
    }

    
}
