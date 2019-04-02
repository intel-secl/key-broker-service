/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * Note the similarity between TransferKeyResponse and RegisterKeyRequest - the
 * difference is outgoing vs incoming.
 *
 * @author jbuhacoff
 */
public class RegisterKeyRequest {

    private byte[] key;
    /**
     * Complete set of attributes for the registered key in the descriptor's
     * "content" section.
     */
    private KeyDescriptor descriptor;

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public KeyDescriptor getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(KeyDescriptor descriptor) {
        this.descriptor = descriptor;
    }
}
