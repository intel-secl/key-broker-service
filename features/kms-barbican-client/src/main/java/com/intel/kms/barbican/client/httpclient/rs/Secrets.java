/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.httpclient.rs;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.barbican.api.DeleteSecretRequest;
import com.intel.kms.barbican.api.DeleteSecretResponse;
import com.intel.kms.barbican.api.GetOrderResponse;
import com.intel.kms.barbican.api.ListSecretsRequest;
import com.intel.kms.barbican.api.ListSecretsResponse;
import com.intel.kms.barbican.api.RegisterSecretRequest;
import com.intel.kms.barbican.api.RegisterSecretResponse;
import com.intel.kms.barbican.api.TransferSecretRequest;
import com.intel.kms.barbican.api.TransferSecretResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import static com.intel.kms.barbican.client.httpclient.rs.BarbicanOperation.xProjectID;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Link;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.client.WebTarget;

/**
 *
 * @author GS-0681
 */
public class Secrets extends BarbicanOperation {

    public Secrets(Configuration configuration) throws BarbicanClientException {
        super(configuration);
    }

    public TransferSecretResponse transferSecret(TransferSecretRequest transferSecretRequest) {
        LOG.debug("transferSecret: {}", getTarget().getUri().toString());
        Map<String, Object> map = new HashMap<>();
        map.put("id", transferSecretRequest.id);
        byte[] sc = getTarget().path("/v1/secrets/{id}").
                resolveTemplates(map).request().
                header("X-Project-Id", xProjectID).
                header("X-Auth-Token", barbAuthToken.getToken()).
                accept(transferSecretRequest.accept).
                get(byte[].class);
        TransferSecretResponse transferSecretResponse = new TransferSecretResponse();
        transferSecretResponse.secret = sc;
        return transferSecretResponse;

    }

    public RegisterSecretResponse registerSecret(RegisterSecretRequest registerSecretRequest) {
        RegisterSecretResponse registerSecretResponse;
        LOG.debug("registerSecretResponse: {}", getTarget().getUri().toString());
        Response response = getTarget().path("/v1/secrets").request().
                header("X-Project-Id", xProjectID).
                header("X-Auth-Token", barbAuthToken.getToken()). 
                header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).
                post(Entity.json(registerSecretRequest));
        registerSecretResponse = response.readEntity(RegisterSecretResponse.class);

        return registerSecretResponse;
    }

    public DeleteSecretResponse deleteSecret(DeleteSecretRequest deleteSecretRequest) {
        DeleteSecretResponse deleteSecretResponse;
        LOG.debug("deleteSecret: {}", getTarget().getUri().toString());
        Map<String, Object> map = new HashMap<>();
        map.put("id", deleteSecretRequest.id);
        Response response = getTarget().path("/v1/secrets/{id}").resolveTemplates(map).request().
                header("X-Project-Id", xProjectID).
                header("X-Auth-Token", barbAuthToken.getToken()).
                accept(MediaType.APPLICATION_JSON).
                delete();
        deleteSecretResponse = new DeleteSecretResponse();
        deleteSecretResponse.status = response.getStatus();
        return deleteSecretResponse;
    }

    public ListSecretsResponse searchSecrets(ListSecretsRequest listSecretsRequest)  {
		ListSecretsResponse listSecretsResponse;
        LOG.debug("searchSecrets: {}", getTarget().getUri().toString());
        WebTarget path = getTarget().path("/v1/secrets");
        path.queryParam("limit", listSecretsRequest.limit);
        path.queryParam("offset", listSecretsRequest.offset);
        Response response = path.request().
                header("X-Project-Id", xProjectID).
                header("X-Auth-Token", barbAuthToken.getToken()).get();
        listSecretsResponse = response.readEntity(ListSecretsResponse.class);

        return listSecretsResponse;

    }
}
