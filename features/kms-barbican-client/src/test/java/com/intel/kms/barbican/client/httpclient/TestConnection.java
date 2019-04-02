/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.httpclient;

import com.intel.dcsg.cpg.configuration.CommonsConfiguration;
import com.intel.dcsg.cpg.configuration.Configuration;
import java.io.IOException;
import com.intel.kms.barbican.api.CreateOrderRequest;
import com.intel.kms.barbican.api.DeleteSecretRequest;
import com.intel.kms.barbican.api.GetOrderRequest;
import com.intel.kms.barbican.api.RegisterSecretRequest;
import com.intel.kms.barbican.api.TransferSecretRequest;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.kms.barbican.client.httpclient.rs.Orders;
import com.intel.kms.barbican.client.httpclient.rs.Secrets;
import javax.ws.rs.core.MediaType;
import org.apache.commons.configuration.BaseConfiguration;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author GS-0681
 */
public class TestConnection {

    Orders orders;
    Secrets secrets;

    @Before
    public void setup() throws BarbicanClientException {
        org.apache.commons.configuration.Configuration apacheConfig = new BaseConfiguration();
        Configuration configuration = new CommonsConfiguration(apacheConfig);
        configuration.set("endpoint.url", "http://127.0.0.1:8080/");
        orders = new Orders(configuration);
        secrets = new Secrets(configuration);
    }

//    @Test
    public void testCreate() {
        orders.createOrderRequest(createSecretRequest());

    }

//    @Test
    public void testGet() {
        GetOrderRequest getOrderRequest = new GetOrderRequest();
        getOrderRequest.id = "7987807-73291737-798897";
        getOrderRequest.projectId = "PROJECT_ID";
        orders.getOrderRequest(getOrderRequest);
    }
    
//    @Test
    public void testTransferSecret(){
        TransferSecretRequest request = new TransferSecretRequest();
        request.accept = MediaType.APPLICATION_OCTET_STREAM;
        request.id = "768978-432-4-324-32-423";
        request.projectId = "PROJECT_ID";
        request.accept = MediaType.APPLICATION_OCTET_STREAM;
        secrets.transferSecret(request);
    }
    
//    @Test
    public void testRegisterSecret(){
        secrets.registerSecret(createRegisterSecret());
    }
    
    @Test
    public void testDeleteSecret(){
        DeleteSecretRequest deleteSecretRequest = new DeleteSecretRequest();
        deleteSecretRequest.id = "4234324-4-324-32-432-42";
        deleteSecretRequest.projectId = "PROJECT_ID";
        secrets.deleteSecret(deleteSecretRequest);
    }
    
    
    private RegisterSecretRequest createRegisterSecret(){
        RegisterSecretRequest registerSecretRequest = new RegisterSecretRequest();
        registerSecretRequest.algorithm = "AES";
        registerSecretRequest.bit_length = 256;
        registerSecretRequest.mode = "cbc";
        registerSecretRequest.name = "SecretName";
        registerSecretRequest.payload = "00000000000000000000000000000";
        registerSecretRequest.payload_content_type = MediaType.APPLICATION_OCTET_STREAM;
        registerSecretRequest.secretType = "symmetric";
        return registerSecretRequest;
    }
    private static CreateOrderRequest createSecretRequest() {
        CreateOrderRequest createOrderRequest = new CreateOrderRequest();
        createOrderRequest.projectId = "PROJECT_ID";
        createOrderRequest.type = "key";
        RegisterSecretRequest registerSecretRequest = new RegisterSecretRequest();
        createOrderRequest.meta = registerSecretRequest;
        registerSecretRequest.algorithm = "AES";
        registerSecretRequest.mode = "cbc";
        registerSecretRequest.bit_length = 256;
        registerSecretRequest.payload_content_type = MediaType.APPLICATION_OCTET_STREAM;
        return createOrderRequest;
    }
    
    

}
