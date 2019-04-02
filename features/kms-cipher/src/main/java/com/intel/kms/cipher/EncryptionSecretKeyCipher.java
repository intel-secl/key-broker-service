/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.cipher;

import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.kms.cipher.faults.Algorithm;
import com.intel.kms.cipher.faults.KeyLength;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import org.apache.commons.lang3.ArrayUtils;

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
