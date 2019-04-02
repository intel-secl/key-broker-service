/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.cipher;

import com.intel.dcsg.cpg.validation.Faults;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.kms.cipher.faults.Algorithm;
import com.intel.kms.cipher.faults.KeyLength;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.commons.lang3.ArrayUtils;

/**
 *
 * @author jbuhacof
 */
public class PublicKeyReport implements Faults {
    private final ArrayList<Fault> faults = new ArrayList<>();
    private final String algorithm;
    private final Integer keyLength;

    public PublicKeyReport(PublicKey publicKey) {
        this.algorithm = publicKey.getAlgorithm();
        if( publicKey instanceof RSAPublicKey ) { // "RSA"
            RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
            this.keyLength = rsaPublicKey.getModulus().bitLength();
        }
        else {
            this.keyLength = null;
        }
    }
    
    public PublicKeyReport(String algorithm, Integer keyLength) {
        this.algorithm = algorithm;
        this.keyLength = keyLength;
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
        if (algorithm != null) {
            // check for known algorithms        
            if (algorithm.equalsIgnoreCase("RSA") && (keyLength != null)) {
                validateRSA();
            }
            else {
                faults.add(new InvalidParameter("algorithm", new Algorithm(algorithm)));
            }
        }
    }
    
    private void validateRSA() {
        // note:  512 and 1024 bit RSA keys are not allowed by policy even though
        // they are valid RSA key lengths
        if (!ArrayUtils.contains(new int[]{2048, 3072, 4096}, keyLength)) {
            faults.add(new InvalidParameter("keyLength", new KeyLength(keyLength)));
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Integer getKeyLength() {
        return keyLength;
    }

    public boolean isPermitted() { return faults.isEmpty(); }

    @Override
    public Collection<Fault> getFaults() {
        return faults;
    }
    
    
}
