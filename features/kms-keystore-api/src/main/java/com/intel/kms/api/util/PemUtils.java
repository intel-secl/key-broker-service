/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api.util;

import com.intel.dcsg.cpg.crypto.file.KeyEnvelope;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.KeyDescriptor;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author jbuhacoff
 */
public class PemUtils {
    public static Pem fromTransferKeyResponse(byte[] key, KeyDescriptor descriptor) {
        // encrypted or plain?
        Pem pem;
        if( descriptor.getEncryption() != null && descriptor.getEncryption().getAlgorithm() != null ) {
            pem = new Pem("ENCRYPTED KEY", key);
        }
        else {
            pem = new Pem("KEY", key);
        }
        // add metadata
        if( descriptor.getContent() != null ) {
            pem.setHeader(KeyEnvelope.CONTENT_ALGORITHM_HEADER, descriptor.getContent().getAlgorithm());
            pem.setHeader(KeyEnvelope.CONTENT_KEY_ID_HEADER, descriptor.getContent().getKeyId());
            pem.setHeader(KeyEnvelope.CONTENT_KEY_LENGTH_HEADER, descriptor.getContent().getKeyLength() == null ? null : descriptor.getContent().getKeyLength().toString());
            pem.setHeader(KeyEnvelope.CONTENT_MODE_HEADER, descriptor.getContent().getMode());
            pem.setHeader(KeyEnvelope.CONTENT_PADDING_MODE_HEADER, descriptor.getContent().getPaddingMode());
        }
        if( descriptor.getEncryption() != null ) {
            pem.setHeader(KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER, descriptor.getEncryption().getAlgorithm());
            pem.setHeader(KeyEnvelope.ENCRYPTION_KEY_ID_HEADER, descriptor.getEncryption().getKeyId());
            pem.setHeader(KeyEnvelope.ENCRYPTION_KEY_LENGTH_HEADER, descriptor.getEncryption().getKeyLength() == null ? null : descriptor.getEncryption().getKeyLength().toString());
        }
        if( descriptor.getIntegrity() != null ) {
            pem.setHeader(KeyEnvelope.INTEGRITY_ALGORITHM_HEADER, descriptor.getIntegrity().getAlgorithm());
            pem.setHeader(KeyEnvelope.INTEGRITY_KEY_ID_HEADER, descriptor.getIntegrity().getKeyId());
            pem.setHeader(KeyEnvelope.INTEGRITY_KEY_LENGTH_HEADER, descriptor.getIntegrity().getKeyLength() == null ? null : descriptor.getIntegrity().getKeyLength().toString());
            pem.setHeader(KeyEnvelope.INTEGRITY_MANIFEST_HEADER,  descriptor.getIntegrity().getManifest() == null ? null : StringUtils.join(descriptor.getIntegrity().getManifest(), ", "));
        }
        return pem;
    }
}
