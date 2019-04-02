/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
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
import com.intel.dcsg.cpg.validation.ValidationException;
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

    public KeyManager getKeyManager() throws IOException  {
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
            //Logger.getLogger(KeyRepository.class.getName()).log(Level.SEVERE, null, ex);
            log.debug("Json parse exception {}", ex.getMessage());
        }
        KeyCollection keyCollection = new KeyCollection();
        try {
            SearchKeyAttributesRequest searchKeyAttributesRequest = new SearchKeyAttributesRequest();
            copy(criteria, searchKeyAttributesRequest);
            SearchKeyAttributesResponse searchKeyAttributes = getKeyManager().searchKeyAttributes(searchKeyAttributesRequest);
            log.debug("search response from delegate : {}", mapper.writeValueAsString(searchKeyAttributes));
//            for (UUID keyId : list) {
            
            for (KeyAttributes keyAttributes : searchKeyAttributes.getData()) {
                boolean foundKey = false;
                if (criteria.extensions == null) {
                    log.debug("Searching all keys");
                    foundKey = true;
                } else {
                    if (criteria.extensions != null /*&& !criteria.extensions.isEmpty()i*/) {
//                    foundKey = false;
                        //for (Map.Entry<String, String> entry : criteria.extensions.entrySet()) {
                        log.debug("Extensions from the filter value:{}", criteria.extensions);
                        Object pathObject = keyAttributes.map().get("path");
                        if (pathObject != null && pathObject instanceof String) {
                            String path = (String) pathObject;
                            if (criteria.extensions.equals(path)) {
                                foundKey = true;
                            }
                        }
                        //}

                    }
                }
                
                if (foundKey) {
                    Key key = new Key();
                    copy(keyAttributes, key);
                    log.debug("Adding key to search keys {}", mapper.writeValueAsString(key));

                    // apply filter criteria
                    /*
                 if (criteria.keynameEqualTo != null && !(criteria.keynameEqualTo.equals(key.getKeyname()))) {
                 continue;
                 }
                 if (criteria.firstNameEqualTo != null && !(key.getContact() != null && criteria.firstNameEqualTo.equals(key.getContact().getFirstName()))) {
                 continue;
                 }
                 if (criteria.lastNameEqualTo != null && !(key.getContact() != null && criteria.lastNameEqualTo.equals(key.getContact().getLastName()))) {
                 continue;
                 }
                 if (criteria.nameContains != null && !(key.getContact() != null
                 && (key.getContact().getFirstName() != null && key.getContact().getFirstName().contains(criteria.nameContains))
                 || (key.getContact().getLastName() != null && key.getContact().getLastName().contains(criteria.nameContains)))) {
                 continue;
                 }
                 if (criteria.emailAddressEqualTo != null && !(key.getContact() != null && criteria.emailAddressEqualTo.equals(key.getContact().getEmailAddress()))) {
                 continue;
                 }
                 if (criteria.emailAddressContains != null && !(key.getContact() != null && key.getContact().getEmailAddress().contains(criteria.emailAddressContains))) {
                 continue;
                 }
                     */
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
    @RequiresPermissions("keys:retrieve") // note the "retrieve" is FOR METADATA ONLY;  to get the actual key you need "transfer" permission
    public Key retrieve(KeyLocator locator) throws RepositoryRetrieveException{
        if (locator == null || locator.id == null) {
            return null;
        }
        Key key = new Key();
        log.debug("Key:Retrieve - Got request to retrieve Key with id {}.", locator.id);
        try {
//            Key key = readKeyProfile(locator.id);
            GetKeyAttributesRequest getKeyAttributesRequest = new GetKeyAttributesRequest();
            getKeyAttributesRequest.setKeyId(locator.id.toString());
            GetKeyAttributesResponse getKeyAttributeResponse = getKeyManager().getKeyAttributes(getKeyAttributesRequest);
            if (getKeyAttributeResponse == null) {
                log.debug("Key {} not found.", locator.id.toString());
                throw new KeyNotFoundException(locator.id.toString());
            }
            KeyAttributes attributes = getKeyAttributeResponse.getData();
            log.debug("key attributes: {}", mapper.writeValueAsString(attributes));
            copy(attributes, key);
        } catch(KeyNotFoundException ex) {
            log.error("Error during Key retrieval.", ex);
            //TO DO KeyNotFoundException needs to thrown
            throw new RuntimeException("Unable to retrieve key " + ex.getMessage());
        } catch (Exception ex) {
            log.error("Key:Retrieve - Error during Key retrieval.", ex);
            throw new RepositoryRetrieveException(ex, locator);
        }
        return key;
    }

    @Override
    @RequiresPermissions("keys:store")
    public void store(Key item) {
        /*
         if (item == null || item.getId() == null) {
         throw new RepositoryInvalidInputException();
         }
         log.debug("Key:Store - Got request to update Key with id {}.", item.getId().toString());
         KeyLocator locator = new KeyLocator();
         locator.id = item.getId();

         try {
         writeKeyProfile(item);
         log.debug("Key:Store - Updated the Key with id {} successfully.", item.getId().toString());
         } catch (Exception ex) {
         log.error("Key:Store - Error during Key update.", ex);
         throw new RepositoryStoreException(ex, locator);
         }
         */
        throw new UnsupportedOperationException(); // we don't allow clients to replace keys or metadata... if they have permission they can delete & recreate/reregister
    }

    @Override
    @RequiresPermissions("keys:create")
    public void create(Key item) {
        log.debug("Key:Create - Got request to create a new Key.");
        KeyLocator locator = new KeyLocator();
        locator.id = item.getId();
        try {
            CreateKeyRequest createKeyRequest = new CreateKeyRequest();
            copy(item, createKeyRequest);
            CreateKeyResponse createKeyResponse = getKeyManager().createKey(createKeyRequest);
            if (!createKeyResponse.getFaults().isEmpty()) {
                log.debug("createKeyResponse: {}", mapper.writeValueAsString(createKeyResponse));
                throw new ValidationException(createKeyResponse.getFaults());
            }
            if (createKeyResponse.getData().size() > 0) {
                copy(createKeyResponse.getData().get(0), item);
                log.debug("createKey response: {}", mapper.writeValueAsString(createKeyResponse));
                log.debug("Key:Create - Created the Key {} successfully.", item.getId().toString());
            }
        } catch (Exception ex) {
            log.error("Key:Create - Error during key creation.", ex);
            throw new RepositoryCreateException(ex, locator);
        }
    }

    private void copy(Key from, CreateKeyRequest to) {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setKeyId(from.getId().toString());
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setTransferLink(from.getTransferLink());
        to.setUsername(from.getUsername());
        if(from.getExtensions().map().containsKey("descriptor_uri")){
            for(Map.Entry<String, Object> map : from.getExtensions().map().entrySet()){
                to.set(map.getKey(), map.getValue());
        }
        }
    }

    private void copy(KeyAttributes from, Key to) {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setId(UUID.valueOf(from.getKeyId()));
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setTransferLink(from.getTransferLink());
        to.setUsername(from.getUsername());
        if(from.map().containsKey("descriptor_uri")){
            to.getExtensions().copyFrom(from);   
        }
    }

    private void copy(KeyFilterCriteria from, SearchKeyAttributesRequest to) {
        to.algorithm = from.algorithmEqualTo;
        to.cipherMode = from.modeEqualTo;
        to.filter = true;
        to.id = (from.id == null ? null : from.id.toString());
        to.keyLength = (from.keyLengthEqualTo == null ? null : from.keyLengthEqualTo.toString());
        to.limit = from.limit;
//        to.name = from.name
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
            // commenting below line as the 5.0 version of common java DoccumenetCollection.java is not having the method getFaults
            // keyCollection.getFaults().addAll(registerKeyResponse.getFaults());
            return keyCollection;
        } catch (IOException e) {
            throw new RepositoryStoreException(e);
        }

    }
    
}
