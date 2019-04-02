/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * Implementations of KeyManager are responsible for enforcing key transfer
 * policies and wrapping keys before storing them in any repository in order
 * to prevent an attacker from retrieving a key directly from the repository
 * and bypassing the KeyManager.
 * 
 * @author jbuhacoff
 */
public interface KeyManager {
    CreateKeyResponse createKey(CreateKeyRequest createKeyRequest);
    RegisterKeyResponse registerKey(RegisterKeyRequest registerKeyRequest);
    DeleteKeyResponse deleteKey(DeleteKeyRequest deleteKeyRequest);
    TransferKeyResponse transferKey(TransferKeyRequest keyRequest);
    GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest keyAttributesRequest);
    SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest);
}
