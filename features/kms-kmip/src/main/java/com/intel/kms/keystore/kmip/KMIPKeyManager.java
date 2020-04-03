/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.kmip;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.KeyLogMarkers;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.RegisterAsymmetricKeyRequest;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.KeyNotFound;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.kms.keystore.directory.JacksonFileRepository;
import com.intel.kms.keystore.kmip.exception.KMIPClientException;
import com.intel.kms.repository.Repository;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;

import javax.ws.rs.WebApplicationException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;

public class KMIPKeyManager implements KeyManager {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KMIPKeyManager.class);
    private Configuration configuration; // non-final to accomodate configure() method
    final private ObjectMapper mapper;
    final protected Repository repository;
    private static KMIPClient kmipClient;

    public KMIPKeyManager() throws IOException {
        this(getUserKeyRepository());
        try {
            if (kmipClient == null){
                kmipClient = KMIPClient.getKMIPClient(configuration);
            }
        } catch (KMIPClientException ex){
            throw new WebApplicationException("Internal Server Error: " + ex.getMessage(), 500);
        }
    }

    private static Repository getUserKeyRepository() throws FileNotFoundException {
        File keysDirectory = new File(Folders.repository("keys"));
        if (!keysDirectory.exists()) {
            if (!keysDirectory.mkdirs()) {
                log.error("Cannot create keys directory");
            }
        }
        return new JacksonFileRepository(keysDirectory);
    }

    public KMIPKeyManager(Repository repository) throws IOException {
        this.configuration = ConfigurationFactory.getConfiguration();
        this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
        this.repository = repository;
    }

    /**
     * Currently supports creating only AES keys
     *
     * @param createKeyRequest
     * @return
     */
    @Override
    public CreateKeyResponse createKey(CreateKeyRequest createKeyRequest) {
        log.debug("createKey called");

        ArrayList<Fault> faults = new ArrayList<>();

        CipherKey cipherKey = new CipherKey();
        if (!createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            throw new UnsupportedOperationException("Algorithm " + createKeyRequest.getAlgorithm() + " not supported");
        }

        try {
            log.debug("createKeyRequest input: {}", mapper.writeValueAsString(createKeyRequest));
            // prepare a response with all the input attributes,
            // a new key id, and the default transfer policy
            KeyAttributes created = new KeyAttributes();
            created.copyFrom(createKeyRequest);
            ///This is added for ISECL Usecase. Rest all is covered in setcommonAttributes() API.
            if (!(created.map().containsKey("descriptor_uri"))) {
                cipherKey.setMode(created.getMode());
                cipherKey.set("digest_algorithm", "SHA-384");
                created.setDigestAlgorithm("SHA-384");
            }
            String keyId = kmipClient.createKey(created.getAlgorithm(), created.getKeyLength());
            created.setKmipId(keyId);
            setcommonAttributes(created, cipherKey);

            log.debug("cipherKey : {}", mapper.writeValueAsString(cipherKey));
            log.debug("Storing cipher key {}", cipherKey.getKeyId());
            repository.store(cipherKey);
            log.info(KeyLogMarkers.CREATE_KEY, "Created key id: {}", cipherKey.getKeyId());
            CreateKeyResponse response = new CreateKeyResponse(created);
            return response;
        } catch (KMIPClientException k){
            throw new WebApplicationException("Internal Server Error: " + k.getMessage(), 500);
        } catch (Exception e) {
            log.debug("GenerateKey failed {}", e.getMessage());
            cipherKey.clear();
            faults.add(new InvalidParameter("algorithm", new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
            CreateKeyResponse response = new CreateKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }
    }

    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest registerKeyRequest) {
        ArrayList<Fault> faults = new ArrayList<>();
        faults.add(new Fault("Register key operation is not supported"));
        RegisterKeyResponse response = new RegisterKeyResponse();
        response.getFaults().addAll(faults);
        return response;
    }

    @Override
    public RegisterKeyResponse registerAsymmetricKey(RegisterAsymmetricKeyRequest registerKeyRequest) {
        ArrayList<Fault> faults = new ArrayList<>();
        faults.add(new Fault("Register Asymmetric key operation is not supported"));
        RegisterKeyResponse response = new RegisterKeyResponse();
        response.getFaults().addAll(faults);
        return response;
    }

    public void setcommonAttributes(KeyAttributes created, CipherKeyAttributes attributes) {
        attributes.setAlgorithm(created.getAlgorithm());
        attributes.setKeyLength(created.getKeyLength());
        attributes.setKeyId(created.getKeyId());
        attributes.setPaddingMode(created.getPaddingMode());
        attributes.set("transferPolicy", created.getTransferPolicy());
        attributes.set("transferLink", created.getTransferLink().toExternalForm());
        attributes.set("kmip_id", created.getKmipId());

        if (created.map().containsKey("descriptor_uri")) {
            attributes.set("descriptor_uri", created.get("descriptor_uri"));
        }
        if (created.map().containsKey("path")) {
            attributes.set("path", created.get("path"));
        }
        if (created.map().containsKey("policy_uri")) {
            attributes.set("policy_uri", created.get("policy_uri"));
        }
        if (created.map().containsKey("realm")) {
            attributes.set("realm", created.get("realm"));
        }
        String usagePolicy = created.getUsagePolicyID();
        if ((usagePolicy != null) && (!usagePolicy.isEmpty())) {
            attributes.set("usage_policy", created.getUsagePolicyID());
        }
        String ckaLabel = created.getCkaLabel();
        if ((ckaLabel != null) && (!ckaLabel.isEmpty())) {
            attributes.set("cka_label", created.getCkaLabel());
        }
        String createdDate = created.getCreatedDate();
        if ((createdDate != null) && (!createdDate.isEmpty())) {
            attributes.set("created_at", created.getCreatedDate());
        }
    }

    @Override
    public DeleteKeyResponse deleteKey(DeleteKeyRequest deleteKeyRequest) {
        log.debug("deleteKey called");
        DeleteKeyResponse response = new DeleteKeyResponse();

        CipherKey cipherKey = (CipherKey) repository.retrieve(deleteKeyRequest.getKeyId());
        if (cipherKey == null){
            response.getFaults().add(new KeyNotFound(deleteKeyRequest.getKeyId()));
            return response;
        }

        Object kmipIdObject = cipherKey.get("kmip_id");
        if (kmipIdObject == null) {
            response.getFaults().add(new InvalidParameter("Key is not created with KMIP key manager."));
            return response;
        }

        log.debug("deleteKey kmip_id {}", cipherKey.get("kmip_id"));
        try {
            kmipClient.deleteKey((String) cipherKey.get("kmip_id"));
        } catch (KMIPClientException ex){
            throw new WebApplicationException("Internal Server Error: " + ex.getMessage(), 500);
        }
        repository.delete(deleteKeyRequest.getKeyId());
        log.info(KeyLogMarkers.DELETE_KEY, "Deleted key id: {}", deleteKeyRequest.getKeyId());
        return response;
    }

    /**
     * NOTE: RETURNS PLAINTEXT KEY - CALLER MUST WRAP IT AS APPROPRIATE FOR THE
     * CURRENT CONTEXT.
     *
     * @param keyRequest
     * @return
     */
    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest keyRequest) {
        log.debug("transferKey called");
        TransferKeyResponse response = new TransferKeyResponse();

        // load secret key from store
        CipherKey cipherKey = (CipherKey)repository.retrieve(keyRequest.getKeyId());
        if (cipherKey == null){
            response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
            return response;
        }

        Object kmipIdObject = cipherKey.get("kmip_id");
        if (kmipIdObject == null) {
            response.getFaults().add(new InvalidParameter("Key is not created with KMIP key manager."));
            return response;
        }

        log.debug("transferKey kmip_id {}", cipherKey.get("kmip_id"));
        String secret;
        try {
            secret = kmipClient.retrieveKey((String) cipherKey.get("kmip_id"));
        } catch (KMIPClientException k){
            throw new WebApplicationException("Internal server error" + k.getMessage(), 500);
        }
        if (secret == null || secret.isEmpty()) {
            response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
            return response;
        }
        cipherKey.setEncoded(secret.getBytes());

        try {
            log.debug("transferKey loaded key with attributes: {}", mapper.writeValueAsString(cipherKey.map()));
        } catch (Exception e) {
            log.error("transferKey loaded key but cannot serialize", e);
        }

        CipherKeyAttributes keyAttributes = new CipherKeyAttributes();
        keyAttributes.copyFrom(cipherKey);
        response.setKey(cipherKey.getEncoded());
        response.setDescriptor(new KeyDescriptor());
        response.getDescriptor().setContent(keyAttributes);
        return response;
    }

    @Override
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        log.debug("searchKeyAttributes");
        SearchKeyAttributesResponse response = new SearchKeyAttributesResponse();
        File directory = new File(Folders.repository("keys"));
        String[] keyIds = directory.list();
        if (keyIds == null) {
            log.warn("Unable to read keys directory");
        } else {
            for (String keyId : keyIds) {
                try {
                    CipherKeyAttributes key = repository.retrieve(keyId);
                    log.debug("retrieved key : {}", mapper.writeValueAsString(key));
                    KeyAttributes keyAttributes = new KeyAttributes();
                    keyAttributes.copyFrom(key);
                    response.getData().add(keyAttributes);
                } catch (JsonProcessingException ex) {
                    log.warn("unable to retrieve key from repository.", ex);
                }
            }
        }
        return response;
    }

    @Override
    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest keyAttributesRequest) {
        log.debug("getKeyAttributes");
        try {
            CipherKeyAttributes cipherKey = repository.retrieve(keyAttributesRequest.getKeyId());
            GetKeyAttributesResponse keyAttributesResponse = new GetKeyAttributesResponse();
            log.debug("getKeyAttributes fetched in KKM : {}", mapper.writeValueAsString(cipherKey));
            if (cipherKey == null) {
                keyAttributesResponse.getFaults().add(new KeyNotFound(keyAttributesRequest.getKeyId()));
                return keyAttributesResponse;
            }
            KeyAttributes attributes = new KeyAttributes();
            attributes.copyFrom(cipherKey);
            keyAttributesResponse.setData(attributes);
            log.debug("Returning GetKeyAttributesResponse : {}", mapper.writeValueAsString(keyAttributesResponse));
            return keyAttributesResponse;
        } catch (JsonProcessingException ex) {
            log.error("Error while fetching key from repository", ex);
        }
        return null;
    }
}
