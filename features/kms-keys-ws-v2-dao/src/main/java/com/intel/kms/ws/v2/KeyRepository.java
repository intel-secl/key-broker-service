/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.ws.v2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryptionUtil;
import com.intel.dcsg.cpg.crypto.key.KeyNotFoundException;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.RegisterAsymmetricKeyRequest;
import com.intel.kms.api.util.PemKeyEncryptionKeyDescriptor;
import com.intel.kms.keystore.KeyManagerFactory;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.kms.ws.v2.api.KeyFilterCriteria;
import com.intel.mtwilson.jaxrs2.server.resource.DocumentRepository;
import com.intel.mtwilson.repository.RepositoryCreateException;
import com.intel.mtwilson.repository.RepositoryDeleteException;
import com.intel.mtwilson.repository.RepositoryException;
import com.intel.mtwilson.repository.RepositoryRetrieveException;
import com.intel.mtwilson.repository.RepositorySearchException;
import com.intel.mtwilson.repository.RepositoryStoreException;
import java.io.IOException;
import java.util.Map;
import org.apache.shiro.authz.annotation.RequiresPermissions;

import javax.ws.rs.WebApplicationException;

/**
 *
 * @author jbuhacoff
 */
public class KeyRepository implements DocumentRepository<Key, KeyCollection, KeyFilterCriteria, KeyLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyRepository.class);
    private final ObjectMapper mapper;
    private KeyManager keyManager;

    public KeyRepository() {
        super();
        mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public KeyManager getKeyManager() throws IOException, ReflectiveOperationException {
        if (keyManager == null) {
            keyManager = KeyManagerFactory.getKeyManager();
        }
        return keyManager;
    }

    @Override
    @RequiresPermissions("keys:search")
    public KeyCollection search(KeyFilterCriteria criteria) {
        log.debug("Key:Search - Key:Got request to search for the Keys.");
        try {
            log.debug("with criteria {}", mapper.writeValueAsString(criteria));
        } catch (JsonProcessingException ex) {
            log.debug("Json parse exception {}", ex.getMessage());
        }
        KeyCollection keyCollection = new KeyCollection();
        try {
            SearchKeyAttributesRequest searchKeyAttributesRequest = new SearchKeyAttributesRequest();
            copy(criteria, searchKeyAttributesRequest);
            SearchKeyAttributesResponse searchKeyAttributes = getKeyManager().searchKeyAttributes(searchKeyAttributesRequest);
            log.debug("search response from delegate : {}", mapper.writeValueAsString(searchKeyAttributes));
            
            for (KeyAttributes keyAttributes : searchKeyAttributes.getData()) {
                boolean foundKey = false;
                if (criteria.extensions == null) {
                    log.debug("Searching all keys");
                    foundKey = true;
                } else {
                    if (criteria.extensions != null) {
                        log.debug("Extensions from the filter value:{}", criteria.extensions);
                        Object pathObject = keyAttributes.map().get("path");
                        if (pathObject != null && pathObject instanceof String) {
                            String path = (String) pathObject;
                            if (criteria.extensions.equals(path)) {
                                foundKey = true;
                            }
                        }

                    }
                }
                
                if (foundKey) {
                    Key key = new Key();
                    copy(keyAttributes, key);
		    		copyMetaData(keyAttributes, key);
                    log.debug("Adding key to search keys {}", mapper.writeValueAsString(key));

                    keyCollection.getKeys().add(key);
                }
            }
        } catch (Exception ex) {
            log.error("Key:Search - Error during Key search.", ex);
            throw new RepositorySearchException(ex, criteria);
        }
        log.debug("Key:Search - Returning back {} of results.", keyCollection.getKeys().size());
        return keyCollection;
    }

    @Override
    //@RequiresPermissions("keys:retrieve") // note the "retrieve" is FOR METADATA ONLY;  to get the actual key you need "transfer" permission
    /**
     *  brief: This API gets the key attributes for a given Key ID.Following of the thre cases may occur:
     *  1) Response in NULL- Exception is thrown
     *  2) Returned key object has faults: if given key id is not found then a fault will be returned
     *  3) Succesfully fetched key attributes.In this case Key attributes are returned via Key object.
     *  4) locator == null or locator.id == null: return null.
     */
    public Key retrieve(KeyLocator locator) {
        if (locator == null || locator.id == null) {
            return null;
        }
        log.debug("Key:Retrieve - Got request to retrieve Key with id {}.", locator.id);
        try {
            GetKeyAttributesRequest getKeyAttributesRequest = new GetKeyAttributesRequest();
            getKeyAttributesRequest.setKeyId(locator.id.toString());
            GetKeyAttributesResponse getKeyAttributeResponse = getKeyManager().getKeyAttributes(getKeyAttributesRequest);
            Key key = new Key();
            if (getKeyAttributeResponse == null) {
                throw new KeyNotFoundException(locator.id.toString());
            } else if (!getKeyAttributeResponse.getFaults().isEmpty()) {
                log.debug("Key {} not found.", locator.id.toString());
                copyMetaData(getKeyAttributeResponse.getData(), key);
                key.getMeta().getFaults().addAll(getKeyAttributeResponse.getFaults());
            } else if(getKeyAttributeResponse.getData() != null) {
	        KeyAttributes attributes = getKeyAttributeResponse.getData();
	        copyMetaData(attributes, key);
                log.debug("key attributes: {}", mapper.writeValueAsString(attributes));
                copy(attributes, key);
            } else {
                throw new KeyNotFoundException(locator.id.toString());
            }
            return key;
        } catch(KeyNotFoundException ex) {
            log.error("Error during Key retrieval.", ex);
            throw new KeyNotFoundException("Unable to retrieve key " + ex.getMessage());
        } catch (Exception ex) {
            log.error("Key:Retrieve - Error during Key retrieval.", ex);
            throw new RepositoryRetrieveException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("keys:store")
    public void store(Key item) {
        throw new UnsupportedOperationException(); // we don't allow clients to replace keys or metadata... if they have permission they can delete & recreate/reregister
    }

    @Override
    @RequiresPermissions("keys:create")
    public void create(Key item) {
        log.debug("Key:Create - Got request to create a new Key.");
        KeyLocator locator = new KeyLocator();
        locator.id = item.getId();
        try {
            if (item.getPrivateKey() != null) {
            RegisterAsymmetricKeyRequest registerKeyRequest = new RegisterAsymmetricKeyRequest();
            copy(item, registerKeyRequest);
            RegisterKeyResponse registerKeyResponse = registerKey(registerKeyRequest);
            item.setPrivateKey("");///This is set to be blank as we dont want to give private key in output.

	    try {
		if (registerKeyResponse == null) {
		    throw new KeyNotFoundException(registerKeyRequest.getKeyId());
		} else if (!registerKeyResponse.getFaults().isEmpty()) {
		    log.debug("Key {} not found.", registerKeyRequest.getKeyId());
		    clearItem(item);
		    item.getMeta().getFaults().addAll(registerKeyResponse.getFaults());
		} else if(registerKeyResponse.getData().size() > 0) {
		    KeyAttributes attributes = registerKeyResponse.getData().get(0);
		    log.debug("register key attributes: {}", mapper.writeValueAsString(attributes));
		    copy(attributes, item);
		} else {
		    throw new KeyNotFoundException(registerKeyRequest.getKeyId());
		}
		copyMetaData(registerKeyResponse, item);
        } catch (IOException e) {
            throw new RepositoryStoreException(e);
        } 
         } else {
	        CreateKeyRequest createKeyRequest = new CreateKeyRequest();
                copy(item, createKeyRequest);
                CreateKeyResponse createKeyResponse = getKeyManager().createKey(createKeyRequest);
            if (createKeyResponse == null) {
                throw new KeyNotFoundException(createKeyRequest.getKeyId());
            } else if (!createKeyResponse.getFaults().isEmpty()) {
                log.debug("createKeyResponse: {}", mapper.writeValueAsString(createKeyResponse));
                clearItem(item);
                item.getMeta().getFaults().addAll(createKeyResponse.getFaults());
            } else if (createKeyResponse.getData().size() > 0) {
                copy(createKeyResponse.getData().get(0), item);
                log.debug("createKey response: {}", mapper.writeValueAsString(createKeyResponse));
                log.debug("Key:Create - Created the Key {} successfully.", item.getId().toString());
            } else {
                throw new KeyNotFoundException(createKeyRequest.getKeyId());
            }
            copyMetaData(createKeyResponse, item);
         }
        }
        catch (WebApplicationException ex){
            throw new WebApplicationException(ex.getMessage());
        } catch (Exception ex) {
            log.error("Key:Create - Error during key creation.", ex);
            throw new RepositoryCreateException(ex, locator);
        }
    }

    private void clearItem(Key item) {
    item.setAlgorithm("");
    item.setCreatedDate("");
    item.setKeyLength(null);
    item.setId(null);
    item.setTransferPolicy("");
    item.setUsagePolicy("");
    item.setCkaLabel("");
    item.setPaddingMode("");
    item.setDigestAlgorithm("");
    item.setPrivateKey("");
    item.getExtensions().remove("cipher_mode");
    }
   
    private void copyMetaData(SearchKeyAttributesResponse from, Key to) {
        to.getMeta().setOperation(from.getOperation());
        to.getMeta().setStatus(from.getStatus());
    }

    private void copyMetaData(KeyAttributes from, Key to) {
        to.getMeta().setOperation(from.getOperation());
        to.getMeta().setStatus(from.getStatus());
    }

    private void copy(Key from, CreateKeyRequest to) {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setKmipId(from.getKmipId());
        to.setKeyId(from.getId().toString());
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setUsagePolicyID(from.getUsagePolicy());
        to.setTransferLink(from.getTransferLink());
        to.setUsageLink(from.getUsageLink());
        to.setUsername(from.getUsername());
        to.setCkaLabel(from.getCkaLabel());
        to.setCreatedDate(from.getCreatedDate());
        to.setCurveType(from.getCurveType());
        if(from.getExtensions().map().containsKey("descriptor_uri")){
            for(Map.Entry<String, Object> map : from.getExtensions().map().entrySet()){
                to.set(map.getKey(), map.getValue());
        }
        from.getExtensions().remove("descriptor_uri");
        }
    }

    private void copy(Key from, RegisterAsymmetricKeyRequest to) {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setKmipId(from.getKmipId());
        to.setKeyId(from.getId().toString());
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setUsagePolicyID(from.getUsagePolicy());
        to.setTransferLink(from.getTransferLink());
        to.setUsageLink(from.getUsageLink());
        to.setUsername(from.getUsername());
        to.setCkaLabel(from.getCkaLabel());
        to.setCreatedDate(from.getCreatedDate());
        to.setCurveType(from.getCurveType());
        to.setPrivateKey(from.getPrivateKey());
        if(from.getExtensions().map().containsKey("descriptor_uri")){
            for(Map.Entry<String, Object> map : from.getExtensions().map().entrySet()){
                to.set(map.getKey(), map.getValue());
        }
        from.getExtensions().remove("descriptor_uri");
        }
    }

    private void copy(KeyAttributes from, Key to) {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setKmipId(from.getKmipId());
        to.setId(UUID.valueOf(from.getKeyId()));
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setTransferLink(from.getTransferLink());
        to.setUsername(from.getUsername());
        to.setCreatedDate(from.getCreatedDate());
        to.setPublicKey(from.getPublicKey());
        to.setCurveType(from.getCurveType());
        to.setUsagePolicy(from.getUsagePolicyID());
        if(from.map().containsKey("descriptor_uri")){
            to.getExtensions().copyFrom(from);
        }
    }

    private void copy(KeyFilterCriteria from, SearchKeyAttributesRequest to) {
        log.debug("in KeyFilterCriteria");
        to.algorithm = from.algorithmEqualTo;
        to.cipherMode = from.modeEqualTo;
        to.filter = true;
        to.id = (from.id == null ? null : from.id.toString());
        to.keyLength = (from.keyLengthEqualTo == null ? null : from.keyLengthEqualTo.toString());
        log.debug("keyLengthEqualTo: {}", to.keyLength);
        to.limit = from.limit;
        to.paddingMode = from.paddingModeEqualTo;
        to.page = from.page;
    }

    @Override
    @RequiresPermissions("keys:delete")
    public void delete(KeyLocator locator) {
        if (locator == null || locator.id == null) {
            return;
        }
        log.debug("Key:Delete - Got request to delete Key with id {}.", locator.id.toString());
        try {
            DeleteKeyResponse response = getKeyManager().deleteKey(new DeleteKeyRequest(locator.id.toString()));
            log.debug("deleteKey response: {}", mapper.writeValueAsString(response));
            log.debug("Key:Delete - Deleted the Key with id {} successfully.", locator.id.toString());
        } catch (WebApplicationException ex){
           throw new WebApplicationException(ex.getMessage());
        } catch (Exception ex) {
            log.error("Key:Delete - Error during Key deletion.", ex);
            throw new RepositoryDeleteException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("keys:delete,search")
    public void delete(KeyFilterCriteria criteria) {
        log.debug("Key:Delete - Got request to delete Key by search criteria.");
        KeyCollection objCollection = search(criteria);
        try {
            for (Key obj : objCollection.getKeys()) {
                KeyLocator locator = new KeyLocator();
                locator.id = obj.getId();
                delete(locator);
            }
        } catch (RepositoryException re) {
            throw re;
        } catch (Exception ex) {
            log.error("Key:Delete - Error during Key deletion.", ex);
            throw new RepositoryDeleteException(ex);
        }
    }

    @RequiresPermissions("keys:register")
    public KeyCollection registerFromPEM(String pemText)  {
        Pem pem = Pem.valueOf(pemText);
        PemKeyEncryption keyEnvelope = PemKeyEncryptionUtil.getEnvelope(pem);
        if (keyEnvelope == null) {
            log.error("registerFromPEM input: {}", pemText);
            // in later versions if the response format implements Faults we could calmly explain the PEM format is not recognized
            throw new RepositoryStoreException("Unsupported format");
        }

        KeyDescriptor descriptor = new PemKeyEncryptionKeyDescriptor(keyEnvelope);

        RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
        registerKeyRequest.setKey(pem.getContent());
        registerKeyRequest.setDescriptor(descriptor);
        try {
            RegisterKeyResponse registerKeyResponse = getKeyManager().registerKey(registerKeyRequest);
            try {log.debug("key manager registerKey response: {}", mapper.writeValueAsString(registerKeyResponse));}catch(Exception e) {log.error("Cannot serialize key manager registerKey response", e);}

            KeyCollection keyCollection = new KeyCollection();
            // copy key info, if available
            for (KeyAttributes keyAttributes : registerKeyResponse.getData()) {
                log.debug("copying keyAttributes to key: {}", mapper.writeValueAsString(keyAttributes));
                Key key = new Key();
                copy(keyAttributes, key);
                keyCollection.getKeys().add(key);
            }
            // copy faults, if available
            keyCollection.getFaults().addAll(registerKeyResponse.getFaults());
            return keyCollection;
        } catch (IOException | ReflectiveOperationException e) {
            throw new RepositoryStoreException(e);
        }
    }

    @RequiresPermissions("keys:register")
    public RegisterKeyResponse registerKey(RegisterAsymmetricKeyRequest registerKeyRequest)  {
        log.debug("register asymmetric key");
        try {
            RegisterKeyResponse registerKeyResponse = getKeyManager().registerAsymmetricKey(registerKeyRequest);
	        return registerKeyResponse;
        }
        catch (IOException | ReflectiveOperationException e) {
            throw new RepositoryStoreException(e);
        }
    }
}
