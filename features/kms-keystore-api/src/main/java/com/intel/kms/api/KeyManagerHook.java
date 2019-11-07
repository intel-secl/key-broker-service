/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import java.util.List;
import com.intel.dcsg.cpg.validation.Fault;

/**
 * Implementations of KeyManagerHook are responsible for enforcing additional validations
 * needed for specificaly DHSM module
 * 
 * @author shefalik
 */

public interface KeyManagerHook {
    List<Fault> beforeCreateKey(CreateKeyRequest createKeyRequest);
    void afterCreateKey(CreateKeyRequest createKeyRequest, CreateKeyResponse createKeyResponse);

    List<Fault> beforeRegisterKey(RegisterKeyRequest registerKeyRequest);
    List<Fault> beforeRegisterKey(RegisterAsymmetricKeyRequest registerKeyRequest);
    void afterRegisterKey(RegisterKeyRequest registerKeyRequest, RegisterKeyResponse registerKeyResponse);
     void afterRegisterKey(RegisterAsymmetricKeyRequest registerKeyRequest, RegisterKeyResponse registerKeyResponse);

    List<Fault> beforeDeleteKey(DeleteKeyRequest deleteKeyRequest);
    void afterDeleteKey(DeleteKeyRequest deleteKeyRequest, DeleteKeyResponse deleteKeyResponse);

    List<Fault> beforeTransferKey(TransferKeyRequest transferKeyRequest);
    void afterTransferKey(TransferKeyRequest transferKeyRequest, TransferKeyResponse transferKeyResponse);

    void afterGetKeyAttributes(GetKeyAttributesRequest getKeyAttributesRequest, GetKeyAttributesResponse getKeyAttributesResponse);

    void afterSearchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest, KeyAttributes searchKeyAttributesResponse);
    String getDescriptorUri();
}

