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
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.configuration.BaseConfiguration;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.intel.dcsg.cpg.configuration.CommonsConfiguration;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;

/**
 * 
 * @author aakashmX
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ KMIPKeyManager.class, KMIPClient.class, RandomUtil.class })
public class KMIPKeyManagerTest {

	@Mock
	KMIPClient mockBHC;

	Configuration config;
	CreateKeyRequest mockCreateKeyRequest;
	CreateKeyResponse mockCreateKeyReponse;
	TransferKeyRequest mockTransferKeyRequest;
	TransferKeyResponse mockTransferKeyResponse;
	RegisterKeyRequest mockRegisterKeyRequest;
	RegisterKeyResponse mockRegisterKeyResponse;
	DeleteKeyRequest mockDeleteKeyRequest;
	DeleteKeyResponse mockDeleteKeyResponse;

	@Before
	public void setup() throws Exception {
		org.apache.commons.configuration.Configuration apacheConfig = new BaseConfiguration();
		config = new CommonsConfiguration(apacheConfig);
		config.set(ENCODER, "ch.ntb.inf.kmip.process.encoder.KMIPEncoder");
		config.set(DECODER, "ch.ntb.inf.kmip.process.decoder.KMIPDecoder");
		config.set(TRANSPORTLAYER,
				"ch.ntb.inf.kmip.stub.transport.KMIPStubTransportLayerHTTPSLocalHost");
		config.set(ENDPOINT,
				"https://localhost:8443/KMIPWebAppServer/KMIPServlet");
		config.set(KEYSTORELOCATION, "D:\\keystore\\keystore.jks");
		config.set(KEYSTOREPW, "password");
		config.set(KMS_STORAGE_KEYSTORE_FILE_PROPERTY,
				"C:\\Temp\\kms_storage.jck");
		config.set(KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY, "password");
		mockBHC = Mockito.mock(KMIPClient.class);
		PowerMockito.mockStatic(KMIPClient.class);
		PowerMockito.mockStatic(RandomUtil.class);
		mockTransferKeyResponse = Mockito.mock(TransferKeyResponse.class);
	}

	@Test
	public void testCreateInvalidRequest() throws Exception {
		CreateKeyRequest ckr = new CreateKeyRequest();
		KMIPKeyManager kmipKeyManager = new KMIPKeyManager();
		CreateKeyResponse createKey = kmipKeyManager.createKey(ckr);
		Assert.assertTrue("Response has faults in it", createKey.getFaults()
				.size() > 0);
		Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
		Assert.assertEquals("Missing argument exception",
				new MissingRequiredParameter("algorithm").getClass(), createKey
						.getFaults().get(0).getClass());

		ckr.setAlgorithm("AESA");
		createKey = kmipKeyManager.createKey(ckr);
		Assert.assertTrue("Response has faults in it", createKey.getFaults()
				.size() > 0);
		Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
		Assert.assertEquals("Missing argument exception",
				InvalidParameter.class, createKey.getFaults().get(0).getClass());

		ckr.setAlgorithm("AES");
		createKey = kmipKeyManager.createKey(ckr);
		Assert.assertTrue("Response has faults in it", createKey.getFaults()
				.size() > 0);
		Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
		Assert.assertEquals("Missing argument exception",
				MissingRequiredParameter.class, createKey.getFaults().get(0)
						.getClass());

		ckr.setKeyLength(999);
		createKey = kmipKeyManager.createKey(ckr);
		Assert.assertTrue("Response has faults in it", createKey.getFaults()
				.size() > 0);
		Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
		Assert.assertEquals("Missing argument exception",
				InvalidParameter.class, createKey.getFaults().get(0).getClass());

	}

	@Test
	public void testCreateWithErrorOnKeyGenerationFromBarbicanKey()
			throws Exception {
		CreateKeyRequest ckr = new CreateKeyRequest();// mock(CreateKeyRequest.class);
		ckr.setAlgorithm("AES");
		ckr.setKeyLength(256);
		KMIPKeyManager kmipKeyManager = new KMIPKeyManager();
		Mockito.when(KMIPClient.getKMIPClient(config)).thenReturn(mockBHC);
		Mockito.when(mockBHC.createSecret(ckr)).thenReturn(
				mockTransferKeyResponse);
		byte[] bytes = "111".getBytes();
		PowerMockito.whenNew(HKDF.class).withAnyArguments()
				.thenThrow(new NoSuchAlgorithmException());
		kmipKeyManager.configuration = config;
		CreateKeyResponse createKeyResponse = kmipKeyManager.createKey(ckr);
		Assert.assertTrue("Response has faults in it", createKeyResponse
				.getFaults().size() > 0);
		Assert.assertEquals("1 error ", 1, createKeyResponse.getFaults().size());
		Assert.assertTrue(
				"deriveKeyFromBarbican exception",
				createKeyResponse.getFaults().get(0).getDescription()
						.contains("Unable to deriveKeyFromkmip with algorithm"));

		// the storagekey call gives an error
		// HKDF mockHkdf = Mockito.mock(HKDF.class);
		// try {
		// PowerMockito.whenNew(HKDF.class).withAnyArguments().thenReturn(mockHkdf);
		// } catch (Exception e) {
		// }
		// when(mockHkdf.deriveKey(bytes, bytes, 321, bytes)).thenReturn(bytes);
		// mock(HKDF.class);
		// when(RandomUtil.randomByteArray(anyInt())).thenReturn(bytes);
		KMIPKeyManager spy = PowerMockito.spy(new KMIPKeyManager());
		try {
			PowerMockito
					.when(spy,
							PowerMockito.method(KMIPKeyManager.class,
									"deriveKeyFromKmip", byte[].class,
									String.class, int.class))
					.withArguments(Matchers.anyString().getBytes(),
							anyString(), anyInt()).thenReturn(bytes);
		} catch (Exception e) {
		}

		// Method method = PowerMockito.method(BarbicanKeyManager.class,
		// "deriveKeyFromBarbican", byte[].class, String.class, int.class);
		// PowerMockito.stub(method).toReturn(bytes);
		// PowerMockito.when(BarbicanKeyManager.class,
		// method).withArguments(bytes, "", 1).thenReturn(bytes);
		PowerMockito
				.when(spy,
						PowerMockito.method(KMIPKeyManager.class,
								"getCurrentStorageKey")).withNoArguments()
				.thenThrow(new KeyStoreException());

		createKeyResponse = kmipKeyManager.createKey(ckr);
		Assert.assertTrue("Response has faults in it", createKeyResponse
				.getFaults().size() > 0);
		Assert.assertEquals("1 error ", 1, createKeyResponse.getFaults().size());
		Assert.assertTrue(
				"getCurrentStorageKey exception",
				createKeyResponse.getFaults().get(0).getDescription()
						.contains("Unable to deriveKeyFromkmip with algorithm"));

	}

}
