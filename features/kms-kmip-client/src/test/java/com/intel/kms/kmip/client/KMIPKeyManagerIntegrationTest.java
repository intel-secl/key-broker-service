/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.kmip.client;

import static com.intel.kms.kmip.client.KMIPKeyManager.DECODER;
import static com.intel.kms.kmip.client.KMIPKeyManager.ENCODER;
import static com.intel.kms.kmip.client.KMIPKeyManager.KEYSTORELOCATION;
import static com.intel.kms.kmip.client.KMIPKeyManager.KEYSTOREPW;
import static com.intel.kms.kmip.client.KMIPKeyManager.KMS_STORAGE_KEYSTORE_FILE_PROPERTY;
import static com.intel.kms.kmip.client.KMIPKeyManager.KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY;
import static com.intel.kms.kmip.client.KMIPKeyManager.ENDPOINT;
import static com.intel.kms.kmip.client.KMIPKeyManager.TRANSPORTLAYER;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_FILE_PROPERTY;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_KEY_PROPERTY;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_KEY_PROVIDER_PROPERTY;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_TYPE_PROPERTY;
import static org.junit.Assert.assertTrue;

import org.apache.commons.configuration.BaseConfiguration;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.intel.dcsg.cpg.configuration.CommonsConfiguration;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.kmip.client.exception.KMIPClientException;

/**
 * 
 * @author aakashmX
 */
public class KMIPKeyManagerIntegrationTest {

	KMIPKeyManager kmipKeyManager = null;

	String createdId = null;
	String registerId = null;

	@Before
	public void setup() throws Exception {
		org.apache.commons.configuration.Configuration apacheConfig = new BaseConfiguration();
		Configuration configuration = new CommonsConfiguration(apacheConfig);
		configuration.set(ENCODER,
				"ch.ntb.inf.kmip.process.encoder.KMIPEncoder");
		configuration.set(DECODER,
				"ch.ntb.inf.kmip.process.decoder.KMIPDecoder");
		configuration.set(TRANSPORTLAYER,
				"ch.ntb.inf.kmip.stub.transport.KMIPStubTransportLayerHTTP");
		configuration.set(ENDPOINT,
				"http://localhost:8090/KMIPWebAppServer/KMIPServlet");
		configuration.set(KEYSTORELOCATION, "D:\\keystore\\keystore.jks");
		configuration.set(KEYSTOREPW, "password");
		configuration.set(KMS_STORAGE_KEYSTORE_FILE_PROPERTY,
				"C:\\temp\\kms_storage.jck");
		configuration.set(KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY, "mykey");
		configuration
				.set(PASSWORD_VAULT_FILE_PROPERTY, "C:\\temp\\storage.jck");
		configuration.set(PASSWORD_VAULT_TYPE_PROPERTY, "JCEKS");
		configuration.set(PASSWORD_VAULT_KEY_PROPERTY, "password");
		configuration.set(PASSWORD_VAULT_KEY_PROVIDER_PROPERTY, "environment");
		kmipKeyManager = new KMIPKeyManager(configuration);
	}

	@Test
	public void testCreateAndRetrieve() throws KMIPClientException {
		testCreate();
		testRetrieve();
		testDelete(createdId);
		testRegister();
		testDelete(registerId);
	}

	public void testCreate() throws KMIPClientException {
		CreateKeyRequest ckr = new CreateKeyRequest();
		ckr.setAlgorithm("AES");
		ckr.setDescription("Test");
		ckr.setKeyLength(256);
		ckr.setMode("CBC");
		CreateKeyResponse createKeyResponse = kmipKeyManager.createKey(ckr);
		createdId = createKeyResponse.getData().get(0).getKeyId();
		Assert.assertTrue(createKeyResponse.getData() != null);

	}

	public void testRetrieve() {
		System.out.println("testRetrieve::");
		TransferKeyRequest transferKeyRequest = new TransferKeyRequest(
				createdId);
		TransferKeyResponse transferKeyResponse = kmipKeyManager
				.transferKey(transferKeyRequest);
		Assert.assertTrue(transferKeyResponse.getKey() != null);
	}

	public void testDelete(String keyID) {
		System.out.println("testDelete::");
		DeleteKeyRequest deleteKeyRequest = new DeleteKeyRequest(keyID);
		DeleteKeyResponse response = kmipKeyManager.deleteKey(deleteKeyRequest);
		assertTrue(response.getHttpResponse().getStatusCode() == 200);
	}

	public void testRegister() {
		System.out.println("testRegister::");
		RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
		registerKeyRequest.setKey("1111111111111111".getBytes());
		RegisterKeyResponse response = kmipKeyManager
				.registerKey(registerKeyRequest);
		registerId = response.getData().get(0).getKeyId();
		assertTrue(response.getData().get(0).getKeyId() != null);
	}
}
