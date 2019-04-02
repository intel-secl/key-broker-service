/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client;

import com.intel.dcsg.cpg.configuration.CommonsConfiguration;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import static com.intel.kms.barbican.client.BarbicanKeyManager.KMS_STORAGE_KEYSTORE_FILE_PROPERTY;
import static com.intel.kms.barbican.client.BarbicanKeyManager.KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_FILE_PROPERTY;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_KEY_PROPERTY;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_KEY_PROVIDER_PROPERTY;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_TYPE_PROPERTY;
import org.apache.commons.configuration.BaseConfiguration;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author GS-0681
 */
public class BarbicanKeyManagerIntegrationTest {

    BarbicanKeyManager barbicanKeyManager = null;

    String createdId = null;
    String registerId = null;

    @Before
    public void setup() throws Exception {
        org.apache.commons.configuration.Configuration apacheConfig = new BaseConfiguration();
        Configuration configuration = new CommonsConfiguration(apacheConfig);
        configuration.set("barbican.endpoint.url", "http://10.35.35.107:9311/");
        configuration.set("barbican.project.id", "12345");
        configuration.set(KMS_STORAGE_KEYSTORE_FILE_PROPERTY, "C:\\Temp\\kms_storage.jck");
        configuration.set(KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY, "mykey");
        configuration.set(PASSWORD_VAULT_FILE_PROPERTY, "C:\\Temp\\storage.jck");
        configuration.set(PASSWORD_VAULT_TYPE_PROPERTY, "JCEKS");
        configuration.set(PASSWORD_VAULT_KEY_PROPERTY, "password");
        configuration.set(PASSWORD_VAULT_KEY_PROVIDER_PROPERTY, "environment");
        barbicanKeyManager = new BarbicanKeyManager(configuration);
    }

    @Test
    public void testCreateAndRetrieve() throws BarbicanClientException {
        testCreate();
        testRetrieve();
        testDelete(createdId);
        testRegister();
        testDelete(registerId);
        testSearch();

    }

    public void testCreate() throws BarbicanClientException {
        CreateKeyRequest ckr = new CreateKeyRequest();
        ckr.setAlgorithm("AES");
        ckr.setDescription("Test");
        ckr.setKeyLength(256);
        ckr.setMode("CBC");
        CreateKeyResponse createKeyResponse = barbicanKeyManager.createKey(ckr);
        createdId = createKeyResponse.getData().get(0).getKeyId();
        Assert.assertTrue(createKeyResponse.getData() != null);

    }

    public void testRetrieve() {
        //createdId = "d440ec2b-4251-42c0-8a29-bcf729e4dc91";
        TransferKeyRequest transferKeyRequest = new TransferKeyRequest(createdId);
        TransferKeyResponse transferKeyResponse = barbicanKeyManager.transferKey(transferKeyRequest);
        Assert.assertTrue(transferKeyResponse.getKey() != null);
    }

    public void testDelete(String keyID) {
        DeleteKeyRequest deleteKeyRequest = new DeleteKeyRequest(keyID);
        DeleteKeyResponse response = barbicanKeyManager.deleteKey(deleteKeyRequest);
        assertTrue(response.getHttpResponse().getStatusCode() == 200);
    }

    public void testRegister() {
        RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
        registerKeyRequest.setKey("1111111111111111".getBytes());
        RegisterKeyResponse response = barbicanKeyManager.registerKey(registerKeyRequest);
        registerId = response.getData().get(0).getKeyId();
        assertTrue(response.getData().get(0).getKeyId() != null);
    }

    private void testSearch() {
        SearchKeyAttributesRequest searchKeyAttributesRequest = new SearchKeyAttributesRequest();
        searchKeyAttributesRequest.limit = 10;
        searchKeyAttributesRequest.page = 1;
        SearchKeyAttributesResponse searchKeyAttributesResponse = barbicanKeyManager.searchKeyAttributes(searchKeyAttributesRequest);
        assertTrue(searchKeyAttributesResponse.getData().size() >= 0);
    }
}
