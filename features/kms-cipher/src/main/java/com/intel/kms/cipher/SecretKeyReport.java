/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.cipher;

import com.intel.dcsg.cpg.validation.Faults;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.cipher.faults.Algorithm;
import com.intel.kms.cipher.faults.KeyLength;
import java.util.ArrayList;
import java.util.Collection;
import javax.crypto.SecretKey;
import org.apache.commons.lang3.ArrayUtils;

/**
 *
 * @author jbuhacof
 */
public class SecretKeyReport implements Faults {
    private final ArrayList<Fault> faults = new ArrayList<>();
    private final String format;
    private final String algorithm;
    private final Integer keyLength; // bits

    public SecretKeyReport(SecretKey secretKey) {
        this.algorithm = secretKey.getAlgorithm();
        byte[] bytes = secretKey.getEncoded();
        if( bytes == null ) {
            this.keyLength = 0;
        }
        else {
            this.keyLength = bytes.length * 8;
        }
        this.format = secretKey.getFormat(); // may be null
        validate();
    }

    public SecretKeyReport(String algorithm, Integer keyLength) {
        this(algorithm, keyLength, null);
    }
    
    public SecretKeyReport(String algorithm, Integer keyLength, String format) {
        this.algorithm = algorithm;
        if( keyLength == null ) {
            this.keyLength = 0;
        }
        else {
            this.keyLength = keyLength;
        }
        this.format = format;
        validate();
    }
    
    private void validate() {
        faults.clear();
        // check for missing parameters
        if (algorithm == null) {
            faults.add(new MissingRequiredParameter("algorithm"));
        }
        if (keyLength == null) {
            faults.add(new MissingRequiredParameter("keyLength")); // TODO: the "parameter" field of the MissingRequiredParameter class needs to be annotated so a filter can automatically convert it's VALUE from keyLength to key_length (javascript) or keep it as keyLength (xml) or KeyLength (SAML) etc.  ... that's something the jackson mapper doesn't do so we have to ipmlement a custom filter for VALUES taht represent key names.
        }
        if( !faults.isEmpty() ) { return; }
        // check for known algorithms
        if (algorithm != null) {
            if (algorithm.equalsIgnoreCase("AES") && (keyLength != null)) {
                validateAES();
            }
            else {
                faults.add(new InvalidParameter("algorithm", new Algorithm(algorithm)));
            }
        }
    }
    
    private void validateAES() {
        if (!ArrayUtils.contains(new int[]{128, 192, 256}, keyLength)) {
            faults.add(new InvalidParameter("keyLength", new KeyLength(keyLength)));
        }
    }
    
    public String getAlgorithm() {
        return algorithm;
    }

    public Integer getKeyLength() {
        return keyLength;
    }

    public String getFormat() {
        return format;
    }

    public boolean isPermitted() { return faults.isEmpty(); }

    @Override
    public Collection<Fault> getFaults() {
        return faults;
    }
    
    
}
