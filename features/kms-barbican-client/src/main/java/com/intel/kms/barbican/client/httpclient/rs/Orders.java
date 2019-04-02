/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.httpclient.rs;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.barbican.api.CreateOrderRequest;
import com.intel.kms.barbican.api.CreateOrderResponse;
import com.intel.kms.barbican.api.GetOrderRequest;
import com.intel.kms.barbican.api.GetOrderResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 *
 * @author soakx
 */
public class Orders extends BarbicanOperation {

    public Orders(Configuration configuration) throws BarbicanClientException {
        super(configuration);
    }

    public CreateOrderResponse createOrderRequest(CreateOrderRequest createOrderRequest) {
        CreateOrderResponse createOrderResponse;
        LOG.debug("createOrderRequest: {}", getTarget().getUri().toString());
        createOrderResponse = getTarget().path("/v1/orders").request().
                header("X-Project-Id", xProjectID).
                header("X-Auth-Token", barbAuthToken.getToken()).
                header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).
                post(Entity.json(createOrderRequest), CreateOrderResponse.class);
        return createOrderResponse;
    }

    public GetOrderResponse getOrderRequest(GetOrderRequest getOrderRequest) {
        GetOrderResponse getOrderResponse;
        LOG.debug("GetOrderResponse: {}", getTarget().getUri().toString());
        Map<String, Object> map = new HashMap<>();
        map.put("id", getOrderRequest.id);

        Response getResponse = getTarget().path("/v1/orders/{id}").
                resolveTemplates(map).
                request().
                header("X-Project-Id", xProjectID).
                header("X-Auth-Token", barbAuthToken.getToken()).
                get();
        getOrderResponse = getResponse.readEntity(GetOrderResponse.class);
        return getOrderResponse;
    }

}
