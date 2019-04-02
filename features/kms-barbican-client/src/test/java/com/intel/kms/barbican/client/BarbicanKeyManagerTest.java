/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client;

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
import com.intel.kms.barbican.api.CreateOrderRequest;
import com.intel.kms.barbican.api.CreateOrderResponse;
import com.intel.kms.barbican.api.DeleteSecretRequest;
import com.intel.kms.barbican.api.DeleteSecretResponse;
import com.intel.kms.barbican.api.GetOrderRequest;
import com.intel.kms.barbican.api.GetOrderResponse;
import com.intel.kms.barbican.api.RegisterSecretRequest;
import com.intel.kms.barbican.api.RegisterSecretResponse;
import com.intel.kms.barbican.api.TransferSecretRequest;
import com.intel.kms.barbican.api.TransferSecretResponse;
import com.intel.kms.barbican.client.httpclient.BarbicanHttpClient;
import com.intel.kms.barbican.client.httpclient.rs.Orders;
import com.intel.kms.barbican.client.httpclient.rs.Secrets;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.configuration.BaseConfiguration;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 *
 * @author GS-0681
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({BarbicanKeyManager.class, BarbicanHttpClient.class, RandomUtil.class})
public class BarbicanKeyManagerTest {

    @Mock
    BarbicanHttpClient mockBHC;

    Configuration config;
    Orders mockOrders;
    Secrets mockSecrets;
    CreateKeyRequest mockCreateKeyRequest;
    CreateOrderRequest mockOrderRequest;
    CreateOrderResponse mockOrderResponse;
    GetOrderResponse mockGetOrderResponse;
    GetOrderRequest mockGetOrderRequest;
    TransferKeyRequest mockTransferKeyRequest;
    TransferKeyResponse mockTransferKeyResponse;
    TransferSecretResponse mockTransferSecretResponse;
    TransferSecretRequest mockTransferSecretRequest;
    RegisterKeyRequest mockRegisterKeyRequest;
    RegisterKeyResponse mockRegisterKeyResponse;
    DeleteKeyRequest mockDeleteKeyRequest;
    DeleteKeyResponse mockDeleteKeyResponse;
    RegisterSecretResponse mockRegisterSecretResponse;
    RegisterSecretRequest mockRegisterSecretRequest;
    DeleteSecretResponse mockDeleteSecretResponse;
    DeleteSecretRequest mockDeleteSecretRequest;

    @Before
    public void setup() throws Exception {
        org.apache.commons.configuration.Configuration apacheConfig = new BaseConfiguration();
        config = new CommonsConfiguration(apacheConfig);
        config.set("endpoint.url", "http://127.0.0.1:8080/");
        config.set("x_PROJECT-ID", "PROJECT_ID");
        mockBHC = Mockito.mock(BarbicanHttpClient.class);
        PowerMockito.mockStatic(BarbicanHttpClient.class);
        PowerMockito.mockStatic(RandomUtil.class);
        mockTransferKeyResponse = mock(TransferKeyResponse.class);
    }

    @Test
    public void testCreateInvalidRequest() throws Exception {
        CreateKeyRequest ckr = new CreateKeyRequest();
        BarbicanKeyManager barbicanKeyManager = new BarbicanKeyManager();
        CreateKeyResponse createKey = barbicanKeyManager.createKey(ckr);
        Assert.assertTrue("Response has faults in it", createKey.getFaults().size() > 0);
        Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
        Assert.assertEquals("Missing argument exception", new MissingRequiredParameter("algorithm").getClass(), createKey.getFaults().get(0).getClass());

        ckr.setAlgorithm("AESA");
        createKey = barbicanKeyManager.createKey(ckr);
        Assert.assertTrue("Response has faults in it", createKey.getFaults().size() > 0);
        Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
        Assert.assertEquals("Missing argument exception", InvalidParameter.class, createKey.getFaults().get(0).getClass());

        ckr.setAlgorithm("AES");
        createKey = barbicanKeyManager.createKey(ckr);
        Assert.assertTrue("Response has faults in it", createKey.getFaults().size() > 0);
        Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
        Assert.assertEquals("Missing argument exception", MissingRequiredParameter.class, createKey.getFaults().get(0).getClass());

        ckr.setKeyLength(999);
        createKey = barbicanKeyManager.createKey(ckr);
        Assert.assertTrue("Response has faults in it", createKey.getFaults().size() > 0);
        Assert.assertEquals("1 error ", 1, createKey.getFaults().size());
        Assert.assertEquals("Missing argument exception", InvalidParameter.class, createKey.getFaults().get(0).getClass());

    }

    @Test
    public void testCreateWithErrorOnKeyGenerationFromBarbicanKey() throws Exception {
        CreateKeyRequest ckr = new CreateKeyRequest();//mock(CreateKeyRequest.class);
        ckr.setAlgorithm("AES");
        ckr.setKeyLength(256);
        BarbicanKeyManager barbicanKeyManager = new BarbicanKeyManager();
        Mockito.when(BarbicanHttpClient.getBarbicanHttpClient(config)).thenReturn(mockBHC);
        Mockito.when(mockBHC.createSecret(ckr)).thenReturn(mockTransferKeyResponse);
        byte[] bytes = "111".getBytes();
        PowerMockito.whenNew(HKDF.class).withAnyArguments().thenThrow(new NoSuchAlgorithmException());
        barbicanKeyManager.configuration = config;
        CreateKeyResponse createKeyResponse = barbicanKeyManager.createKey(ckr);
        Assert.assertTrue("Response has faults in it", createKeyResponse.getFaults().size() > 0);
        Assert.assertEquals("1 error ", 1, createKeyResponse.getFaults().size());
        Assert.assertTrue("deriveKeyFromBarbican exception", createKeyResponse.getFaults().get(0).getDescription().contains("Unable to deriveKeyFromBarbican with algorithm"));

        
    }

}
