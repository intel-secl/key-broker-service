/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.util;

import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.barbican.api.CreateOrderRequest;
import com.intel.kms.barbican.api.DeleteSecretResponse;
import com.intel.kms.barbican.api.GetSecretResponse;
import com.intel.kms.barbican.api.ListSecretsRequest;
import com.intel.kms.barbican.api.ListSecretsResponse;
import com.intel.kms.barbican.api.RegisterSecretRequest;
import com.intel.kms.barbican.api.RegisterSecretResponse;
import com.intel.kms.barbican.api.TransferSecretRequest;
import com.intel.kms.barbican.api.TransferSecretResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.mtwilson.jaxrs2.Link;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author soakx
 */
public class BarbicanApiUtil {

    /**
     * Method to map the generic create request object to the barbican specific
     * request object
     *
     * Barbican create order request:
     *
     * POST v1/orders
     *
     * Header: content-type=application/json X-Project-Id: {project_id} {
     * "type": "key", "meta": { "name": "secretname", "algorithm": "AES",
     * "bit_length": 256, "mode": "cbc", "payload_content_type":
     * "application/octet-stream" } }
     *
     *
     *
     *
     * @param createKeyRequest
     * @return CreateOrderRequest
     * @throws BarbicanClientException
     */
    public static CreateOrderRequest mapCreateKeyRequestToCreateOrderRequest(CreateKeyRequest createKeyRequest) throws BarbicanClientException {
        if (createKeyRequest == null) {
            throw new BarbicanClientException(new NullPointerException("mapCreateKeyRequestToCreateOrderRequest: The CreateKeyRequest is null"));
        }
        CreateOrderRequest createOrderRequest = new CreateOrderRequest();
        RegisterSecretRequest registerSecretRequest = new RegisterSecretRequest();
        createOrderRequest.type = "key";
        createOrderRequest.meta = registerSecretRequest;
        registerSecretRequest.name = "BarbicanKMSKey";
        registerSecretRequest.algorithm = createKeyRequest.getAlgorithm();
        registerSecretRequest.bit_length = createKeyRequest.getKeyLength();
        registerSecretRequest.mode = createKeyRequest.getMode();
        registerSecretRequest.payload_content_type = MediaType.APPLICATION_OCTET_STREAM;
        return createOrderRequest;
    }

    /**
     * Map the Barbican Transfer object to the generic transfer object
     *
     * @param transferSecretResponse
     * @param transferKeyRequest
     * @return TransferKeyResponse
     * @throws BarbicanClientException
     */
    public static TransferKeyResponse mapTransferSecretResponseToTransferKeyResponse(TransferSecretResponse transferSecretResponse, TransferKeyRequest transferKeyRequest) throws BarbicanClientException {
        if (transferSecretResponse == null) {
            throw new BarbicanClientException(new NullPointerException("mapTransferSecretResponseToTransferKeyResponse: The transferSecretResponse is null"));
        }
        TransferKeyResponse transferKeyResponse = new TransferKeyResponse();
        transferKeyResponse.setKey(transferSecretResponse.secret);
        KeyDescriptor descriptor = new KeyDescriptor();
        CipherKeyAttributes contentAttributes = new CipherKeyAttributes();
        contentAttributes.setKeyId(transferKeyRequest.getKeyId());
        descriptor.setContent(contentAttributes);
        transferKeyResponse.setDescriptor(descriptor);
        return transferKeyResponse;
    }

    /**
     * Map the Barbican delete object to the generic delete object
     *
     * @param deleteSecretRequest
     * @return DeleteKeyResponse
     * @throws BarbicanClientException
     */
    public static DeleteKeyResponse mapDeleteSecretResponseToDeleteKeyResponse(DeleteSecretResponse deleteSecretResponse) throws BarbicanClientException {
        if (deleteSecretResponse == null) {
            throw new BarbicanClientException(new NullPointerException("mapDeleteSecretResponseToDeleteKeyResponse: The deleteSecretResponse is null"));
        }
        DeleteKeyResponse deleteKeyResponse = new DeleteKeyResponse();

        deleteKeyResponse.getHttpResponse().setStatusCode(200);
        return deleteKeyResponse;
    }

    public static RegisterSecretRequest mapRegisterKeyRequestToRegisterSecretRequest(RegisterKeyRequest registerKeyRequest) throws BarbicanClientException {
        if (registerKeyRequest == null) {
            throw new BarbicanClientException(new NullPointerException("mapRegisterKeyRequestToRegisterSecretRequest: The registerKeyRequest is null"));
        }
        if (registerKeyRequest.getKey() == null) {
            throw new BarbicanClientException(new NullPointerException("mapRegisterKeyRequestToRegisterSecretRequest: The key data is null"));
        }
        RegisterSecretRequest registerSecretRequest = new RegisterSecretRequest();
        registerSecretRequest.algorithm = registerKeyRequest.getDescriptor().getEncryption().getAlgorithm();
        registerSecretRequest.bit_length = registerKeyRequest.getDescriptor().getEncryption().getKeyLength();
        registerSecretRequest.mode = registerKeyRequest.getDescriptor().getEncryption().getMode();
        registerSecretRequest.payload_content_type = MediaType.APPLICATION_OCTET_STREAM;
        registerSecretRequest.secretType = "symmetric";
        registerSecretRequest.payload_content_encoding = "base64";
        registerSecretRequest.payload = Base64.encodeBase64String(registerKeyRequest.getKey());
        //TODO: Store the storage key alias and the "iv" in custom attributes
        return registerSecretRequest;
    }

    public static RegisterKeyResponse mapRegisterSecretResponseToRegisterKeyResponse(RegisterSecretResponse registerSecretResponse, RegisterKeyRequest registerKeyRequest) throws BarbicanClientException {
        if (registerSecretResponse == null) {
            throw new BarbicanClientException(new NullPointerException("mapRegisterSecretResponseToRegisterKeyResponse: The registerSecretResponse is null"));
        }
        Link link = new Link("secret_ref", registerSecretResponse.secret_ref);
        KeyAttributes attributes = new KeyAttributes();
        CipherKeyAttributes encryption = registerKeyRequest.getDescriptor().getEncryption();
        attributes.setAlgorithm(encryption.getAlgorithm());
        attributes.setKeyLength(encryption.getKeyLength());
        String keyId = registerSecretResponse.secret_ref.substring(registerSecretResponse.secret_ref.lastIndexOf("/") + 1);
        attributes.setKeyId(keyId);
        RegisterKeyResponse registerKeyResponse = new RegisterKeyResponse(attributes);
        registerKeyResponse.getLinks().add(link);
        return registerKeyResponse;
    }

    public static TransferSecretRequest mapTransferKeyRequestToTransferSecretRequest(TransferKeyRequest transferKeyRequest) throws BarbicanClientException {
        if (transferKeyRequest == null) {
            throw new BarbicanClientException(new NullPointerException("mapTransferKeyRequestToTransferSecretRequest: The transferKeyRequest is null"));
        }
        TransferSecretRequest transferSecretRequest = new TransferSecretRequest();
        transferSecretRequest.accept = MediaType.APPLICATION_OCTET_STREAM;
        transferSecretRequest.id = transferKeyRequest.getKeyId();
        return transferSecretRequest;

    }

    public static CreateKeyResponse mapRegisterKeyResponseToCreateKeyResponse(RegisterKeyResponse registerKeyResponse) throws BarbicanClientException {
        if (registerKeyResponse == null) {
            throw new BarbicanClientException(new NullPointerException("mapRegisterKeyResponseToCreateKeyResponse: The registerKeyResponse is null"));
        }

        CreateKeyResponse createKeyResponse = new CreateKeyResponse(registerKeyResponse.getData().get(0));
        return createKeyResponse;
    }

    public static ListSecretsRequest mapSearchKeyAttributesRequestToListSecretsRequest(SearchKeyAttributesRequest request) throws BarbicanClientException {
        if (request == null) {
            throw new BarbicanClientException(new NullPointerException("mapSearchKeyAttributesRequestToListSecretsRequest: The SearchKeyAttributesRequest is null"));
        }
        ListSecretsRequest listSecretsRequest = new ListSecretsRequest();
        if( request.limit != null && request.limit > 0 ) {
            listSecretsRequest.limit= request.limit;
        }
        else {
            listSecretsRequest.limit = 10;
        }
        if( request.page != null && request.page > 0 ) {
            listSecretsRequest.offset = request.page*10-10;
        }
        else {
            listSecretsRequest.offset = 0;
        }

        return listSecretsRequest;
    }

    public static SearchKeyAttributesResponse mapListSecretsResponseToSearchKeyAttributesResponse(ListSecretsResponse searchSecrets) throws BarbicanClientException {
        if (searchSecrets == null) {
            throw new BarbicanClientException(new NullPointerException("mapListSecretsResponseToSearchKeyAttributesResponse: The ListSecretsResponse is null"));
        }
        SearchKeyAttributesResponse attributesResponse = new SearchKeyAttributesResponse();
        for(GetSecretResponse key : searchSecrets.secrets){
            KeyAttributes keyAttributes = new KeyAttributes();
            keyAttributes.setAlgorithm(key.algorithm);
			keyAttributes.setKeyId(key.secret_ref.substring(key.secret_ref.lastIndexOf("/") + 1));
            keyAttributes.setKeyLength(key.bit_length);
            keyAttributes.setMode(key.mode);
            attributesResponse.getData().add(keyAttributes);
        }
        return attributesResponse;
    }

}
