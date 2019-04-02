/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.intel.dcsg.cpg.io.Attributes;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.IntegrityKeyAttributes;

/**
 * An envelope is used to store or transport encrypted content. The content is
 * encrypted using a key described in the envelope's protection field. The data
 * may also be authenticated (integrity) using a key described in the envelope's
 * protection field. The content may be data or it may be a secret key or
 * private key.
 *
 * If we support multiple envelope types (KMIP supports encrypt, MAC/sign,
 * encrypt then MAC/sign, MAC/sign then encrypt, and TR-31) we could have an
 * envelope type attribute here. Currently, the envelopes we use are sign then
 * encrypt or just encrypt.
 *
 * @author jbuhacoff
 */
public class KeyDescriptor extends Attributes {

    /**
     * Describes data being transmitted - may be encrypted data or an encrypted key. If
     * it's encrypted, the encryption field will be set indicating the method
     * used to encrypt the content.
     * NOTE this field does not contain the key itself. It is only a descriptor.
     */
    private CipherKeyAttributes content;
    /**
     * Describes how the key was encrypted. Systems supporting more than one key
     * wrapping method need this information in order to select the right code
     * for parsing and decrypting the key.
     *
     * If protection is null, then content is a plaintext. If protection is
     * defined, then content must be unwrapped in accordance with the protection
     * instructions in order to obtain the content in its plaintext form.
     * 
     * NOTE this field does not contain the encryption key itself. It is only a descriptor.
     */
    private CipherKeyAttributes encryption;
    /**
     * Describes how to check the integrity of the content. Typically this would
     * be via an algorithm such as RSA-SHA256 or HMAC-SHA256 using a key
     * identified by the integrity section.
     * 
     * NOTE this field does not contain the integrity key itself. It is only a descriptor.
     */
    private IntegrityKeyAttributes integrity;

    public void setContent(CipherKeyAttributes content) {
        this.content = content;
    }

    public CipherKeyAttributes getContent() {
        return content;
    }

    public CipherKeyAttributes getEncryption() {
        return encryption;
    }

    public void setEncryption(CipherKeyAttributes encryption) {
        this.encryption = encryption;
    }

    public IntegrityKeyAttributes getIntegrity() {
        return integrity;
    }

    public void setIntegrity(IntegrityKeyAttributes integrity) {
        this.integrity = integrity;
    }
}
