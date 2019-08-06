/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.api.util;

import com.intel.dcsg.cpg.crypto.file.KeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.KeyEnvelopeV1;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.kms.api.KeyDescriptor;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.IntegrityKeyAttributes;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

/**
 * An adapter KeyDescriptor that wraps a PemKeyEncryption object
 * 
 * @author jbuhacoff
 */
public class PemKeyEncryptionKeyDescriptor extends KeyDescriptor {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PemKeyEncryptionKeyDescriptor.class);
    
    public PemKeyEncryptionKeyDescriptor(PemKeyEncryption keyEnvelope) {
        CipherKeyAttributes contentAttributes = new CipherKeyAttributes();
        contentAttributes.setKeyId(keyEnvelope.getContentKeyId());
        contentAttributes.setAlgorithm(keyEnvelope.getContentAlgorithm());
        contentAttributes.setKeyLength(keyEnvelope.getContentKeyLength());
        contentAttributes.setMode(keyEnvelope.getContentMode());
        contentAttributes.setPaddingMode(keyEnvelope.getContentPaddingMode());
        
        // copy user-defined content attributes
        Map<String,String> headers = keyEnvelope.getDocument().getHeaders();
        if( headers != null ) {
            HashSet<String> knownHeaders = new HashSet<>();
            // current headers
            knownHeaders.addAll(Arrays.asList(new String[] { KeyEnvelope.CONTENT_KEY_ID_HEADER, KeyEnvelope.CONTENT_ALGORITHM_HEADER, KeyEnvelope.CONTENT_KEY_LENGTH_HEADER, KeyEnvelope.CONTENT_MODE_HEADER, KeyEnvelope.CONTENT_PADDING_MODE_HEADER }));
            knownHeaders.addAll(Arrays.asList(new String[] { KeyEnvelope.ENCRYPTION_KEY_ID_HEADER, KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER, KeyEnvelope.ENCRYPTION_KEY_LENGTH_HEADER, KeyEnvelope.ENCRYPTION_MODE_HEADER, KeyEnvelope.ENCRYPTION_PADDING_MODE_HEADER }));
            knownHeaders.addAll(Arrays.asList(new String[] { KeyEnvelope.INTEGRITY_KEY_ID_HEADER, KeyEnvelope.INTEGRITY_ALGORITHM_HEADER, KeyEnvelope.INTEGRITY_KEY_LENGTH_HEADER, KeyEnvelope.INTEGRITY_MANIFEST_HEADER }));
            // older header names
            knownHeaders.addAll(Arrays.asList(new String[] { KeyEnvelopeV1.CONTENT_KEY_ID_HEADER, KeyEnvelopeV1.CONTENT_ALGORITHM_HEADER, KeyEnvelopeV1.CONTENT_KEY_LENGTH_HEADER, KeyEnvelopeV1.CONTENT_MODE_HEADER, KeyEnvelopeV1.CONTENT_PADDING_MODE_HEADER }));
            knownHeaders.addAll(Arrays.asList(new String[] { KeyEnvelopeV1.ENVELOPE_KEY_ID_HEADER, KeyEnvelopeV1.ENVELOPE_ALGORITHM_HEADER, KeyEnvelopeV1.ENVELOPE_MODE_HEADER, KeyEnvelopeV1.ENVELOPE_PADDING_MODE_HEADER }));
            // the user defined headers are anything other than the well known headers
            HashSet<String> userDefinedHeaders = new HashSet<>();
            userDefinedHeaders.addAll(headers.keySet());
            userDefinedHeaders.removeAll(knownHeaders);
            // copy each one
            for(String headerName : userDefinedHeaders) {
                log.debug("Copying header {} to content attributes", headerName);
                contentAttributes.set(headerName, headers.get(headerName));
            }
        }

        CipherKeyAttributes encryptionAttributes = new CipherKeyAttributes();
        encryptionAttributes.setAlgorithm(keyEnvelope.getEncryptionAlgorithm());
        encryptionAttributes.setKeyId(keyEnvelope.getEncryptionKeyId());

        IntegrityKeyAttributes integrityAttributes = new IntegrityKeyAttributes();

        setContent(contentAttributes);
        setEncryption(encryptionAttributes);
        setIntegrity(integrityAttributes);
    }
}
