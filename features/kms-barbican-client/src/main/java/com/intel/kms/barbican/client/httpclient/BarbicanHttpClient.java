package com.intel.kms.barbican.client.httpclient;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.barbican.api.CreateOrderRequest;
import com.intel.kms.barbican.api.CreateOrderResponse;
import com.intel.kms.barbican.api.DeleteSecretRequest;
import com.intel.kms.barbican.api.DeleteSecretResponse;
import com.intel.kms.barbican.api.GetOrderRequest;
import com.intel.kms.barbican.api.GetOrderResponse;
import com.intel.kms.barbican.api.ListSecretsRequest;
import com.intel.kms.barbican.api.ListSecretsResponse;
import com.intel.kms.barbican.api.RegisterSecretRequest;
import com.intel.kms.barbican.api.RegisterSecretResponse;
import com.intel.kms.barbican.api.TransferSecretRequest;
import com.intel.kms.barbican.api.TransferSecretResponse;
import com.intel.kms.barbican.client.util.BarbicanApiUtil;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.kms.barbican.client.httpclient.rs.Orders;
import com.intel.kms.barbican.client.httpclient.rs.Secrets;

/**
 *
 * @author soakx
 */
public class BarbicanHttpClient {

    private static BarbicanHttpClient barbicanHttpClient = null;
    private final Configuration configuration;
    private static String PROJECT_ID = null;
    private static Orders ordersClient;
    private static Secrets secretsClient;
    
    public void setOrders(Orders orders){
        ordersClient = orders;
    }
    public void setSecrets(Secrets secrets){
        secretsClient = secrets;
    }

    public BarbicanHttpClient(Configuration configuration) {
        this.configuration = configuration;
    }

    public static BarbicanHttpClient getBarbicanHttpClient(Configuration configuration) throws BarbicanClientException {
        if (barbicanHttpClient == null) {
            barbicanHttpClient = new BarbicanHttpClient(configuration);
        }
        PROJECT_ID = configuration.get("X-PROJECT-ID");
        ordersClient = new Orders(configuration);
        secretsClient = new Secrets(configuration);
        return barbicanHttpClient;
    }

    /**
     * Barbican can generate secrets via the orders resource Create an order
     * (which will then generate a secret) as follows:
     *
     * curl -X POST -H 'content-type:application/json' -H 'X-Project-Id: 12345'
     * -d '{ "secret": {"name": "secretname", "algorithm": "aes", "bit_length":
     * 256, "mode": "cbc", "payload_content_type": "application/octet-stream"}}'
     * http://localhost:9311/v1/orders
     *
     * You should see a response like the following: {"order_ref":
     * "http://localhost:9311/v1/orders/62d57f53-ecfe-4ae4-87bd-fab2f24e29bc"}
     *
     *
     * Once the request is made, the barbican would respond with 202 OK and a
     * link to the order : "order_ref":
     * "http://localhost:9311/v1/orders/30b3758a-7b8e-4f2c-b9f0-f590c6f8cc6d"
     *
     * Make another call to barbican to get the order details
     *
     * The response would contain URL to the secret: {"status": "ACTIVE",
     * "secret_ref":
     * "http://localhost:9311/v1/secrets/2df8d196-76b6-4f89-a6d2-c9e764900791",
     * "updated": "2013-11-04T16:39:13.593962", "name": "secretname",
     * "algorithm": "aes", "created": "2013-11-04T16:39:13.593956",
     * "content_types": {"default": "application/octet-stream"}, "mode": "cbc",
     * "bit_length": 256, "expiration": null}
     *
     * @param createKeyRequest
     * @return CreateKeyResponse with the URL to the secret
     * @throws BarbicanClientException
     */
    public TransferKeyResponse createSecret(CreateKeyRequest createKeyRequest) throws BarbicanClientException {
        /*
         1) Construct a CreateOrderRequest object from the  createKeyRequest and Create order in Barbican
         2) Get the order details from barbican containing the secret_ref
         3) Make a GetSecret call to Barbican to get the actual key
         4) Encrypt the key with storage key
         5) Make a registerSecret call and replace Barbican key with the new key
         6) Delete the barbican key as keys are immutable in Barbican
         7) return the response
         */

        //Step 1
        CreateOrderRequest createOrderRequest = BarbicanApiUtil.mapCreateKeyRequestToCreateOrderRequest(createKeyRequest);
        CreateOrderResponse createOrderResponse = ordersClient.createOrderRequest(createOrderRequest);

        //Step 2
        //Here we get the secret_ref
        String orderId = createOrderResponse.order_ref.substring(createOrderResponse.order_ref.lastIndexOf("/") + 1);
        GetOrderRequest getOrderRequest = new GetOrderRequest();
        getOrderRequest.id = orderId;
        getOrderRequest.projectId = configuration.get("X-Project-Id");
        GetOrderResponse getOrderResponse = ordersClient.getOrderRequest(getOrderRequest);
        String keyId = getOrderResponse.secret_ref.substring(getOrderResponse.secret_ref.lastIndexOf("/") + 1);

        //Step 3 
        TransferKeyRequest transferKeyRequest = new TransferKeyRequest(keyId);
        TransferKeyResponse transferKeyResponse = retrieveSecret(transferKeyRequest);
        return transferKeyResponse;
    }

    /**
     * sample curl request to get the secret curl -H
     * 'Accept:application/octet-stream' -H 'X-Project-Id: 12345'
     * http://localhost:9311/v1/secrets/2df8d196-76b6-4f89-a6d2-c9e764900791
     *
     * @param transferKeyRequest
     * @return TransferKeyResponse with the key populated
     * @throws com.intel.kms.barbican.client.exception.BarbicanClientException
     */
    public TransferKeyResponse retrieveSecret(TransferKeyRequest transferKeyRequest) throws BarbicanClientException {
        TransferSecretRequest transferSecretRequest = BarbicanApiUtil.mapTransferKeyRequestToTransferSecretRequest(transferKeyRequest);
        transferSecretRequest.projectId = PROJECT_ID;
        TransferSecretResponse transferSecret = secretsClient.transferSecret(transferSecretRequest);
        TransferKeyResponse transferKeyResponse = BarbicanApiUtil.mapTransferSecretResponseToTransferKeyResponse(transferSecret, transferKeyRequest);
        return transferKeyResponse;
    }
    

    /**
     *
     * Header: content-type=application/json X-Project-Id: {project_id}
     *
     * {
     * "name": "AES key", "expiration": "2014-02-28T19:14:44.180394",
     * "algorithm": "aes", "bit_length": 256, "mode": "cbc", "payload":
     * "gF6+lLoF3ohA9aPRpt+6bQ==", "payload_content_type":
     * "application/octet-stream", "payload_content_encoding": "base64",
     * "secret_type": "opaque" }
     *
     * On successful retrieval, barbican returns the following reponse {
     * "secret_ref":
     * "http://localhost:9311/v1/secrets/a8957047-16c6-4b05-ac57-8621edd0e9ee" }
     *
     *
     * @param registerKeyRequest
     * @return
     * @throws BarbicanClientException
     */
    public RegisterKeyResponse registerSecret(RegisterKeyRequest registerKeyRequest) throws BarbicanClientException {
        RegisterKeyResponse registerKeyResponse;
        RegisterSecretRequest registerSecretRequest = BarbicanApiUtil.mapRegisterKeyRequestToRegisterSecretRequest(registerKeyRequest);
        RegisterSecretResponse registerSecretResponse = secretsClient.registerSecret(registerSecretRequest);
        registerKeyResponse = BarbicanApiUtil.mapRegisterSecretResponseToRegisterKeyResponse(registerSecretResponse, registerKeyRequest);
        return registerKeyResponse;
    }

    /**
     *
     * @param request
     * @return
     * @throws BarbicanClientException
     */
    public DeleteKeyResponse deleteSecret(DeleteKeyRequest request) throws BarbicanClientException {
        DeleteKeyResponse response;
        DeleteSecretRequest deleteSecretRequest = new DeleteSecretRequest();
        deleteSecretRequest.id = request.getKeyId();
        DeleteSecretResponse deleteSecretResponse = secretsClient.deleteSecret(deleteSecretRequest);
        response = BarbicanApiUtil.mapDeleteSecretResponseToDeleteKeyResponse(deleteSecretResponse);
        return response;
    }

    
    public SearchKeyAttributesResponse searchSecrets(SearchKeyAttributesRequest request) throws BarbicanClientException {
        SearchKeyAttributesResponse response;
        ListSecretsRequest listSecretsRequest = BarbicanApiUtil.mapSearchKeyAttributesRequestToListSecretsRequest(request);
        ListSecretsResponse searchSecrets = secretsClient.searchSecrets(listSecretsRequest);
        response = BarbicanApiUtil.mapListSecretsResponseToSearchKeyAttributesResponse(searchSecrets);
        return response;
    }
}
