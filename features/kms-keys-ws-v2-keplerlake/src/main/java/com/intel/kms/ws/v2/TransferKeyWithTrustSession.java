/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.ws.v2;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.keplerlake.registry.util.JacksonMapperFactory;
import com.intel.keplerlake.servlet3.SessionTokenMonitoringServiceListener;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.keplerlake.etcd.EtcdUtils;
import com.intel.kms.keystore.KeyManagerFactory;
import com.intel.kms.keystore.KeyTransferUtil;
import com.intel.mtwilson.json.JsonPath;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.shiro.ShiroUtil;
import java.io.IOException;
import java.util.List;
import javax.script.ScriptException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class TransferKeyWithTrustSession {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransferKeyWithTrustSession.class);
    private KeyManager keyManager = null;
    private KeyTransferUtil keyTransferUtil;
    final private JsonPath jsonpath = new JsonPath();
    final private ObjectMapper mapper = JacksonMapperFactory.createObjectMapper();

    public KeyManager getKeyManager() throws IOException {
        if (keyManager == null) {
            keyManager = KeyManagerFactory.getKeyManager();
        }
        return keyManager;
    }

    private void logFaults(String message, List<Fault> faults) {
        for (Fault f : faults) {
            log.error("{}: {}", message, f.toString());
        }
    }

    private KeyTransferUtil getKeyTransferUtil() throws IOException {
        if (keyTransferUtil == null) {
            keyTransferUtil = new KeyTransferUtil(getKeyManager());
        }
        return keyTransferUtil;
    }

    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes("application/kepler-lake-key-request")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @RequiresPermissions("keys:transfer")
    public Response getKeyWithRemoteAttestationAsEncryptedBytes(@PathParam("keyId") String keyId, @QueryParam("context") String context, String messageBody, @Context HttpServletRequest request, @Context HttpServletResponse response) {
        log.debug("getKeyWithRemoteAttestationAsEncryptedBytes");
        log.debug("Received trust assertion to transfer key {} for host {}", messageBody, request.getRemoteAddr());

        TransferKeyRequest transferKeyRequest = new TransferKeyRequest();
        if (context != null && !context.isEmpty()) {
            log.debug("setting context {}", context);
            transferKeyRequest.set("context", context);
        } //        transferKeyRequest.set("OAuth2-Authorization", request.getHeader("OAuth2-Authorization"));
        try {
            String hostIp = request.getRemoteAddr();
            String shiroHostAddress = ShiroUtil.subjectUsername();
            log.debug("getKeyWithRemoteAttestationAsEncryptedBytes client addr {} and shiro usrname {}", hostIp, shiroHostAddress);

            com.intel.keplerlake.session.HostInfo hostInfo = SessionTokenMonitoringServiceListener.getMonitoringService().getHostInfo(request.getRemoteAddr());
            if (hostInfo != null && hostInfo.bindingPublicKey != null) {
                // get flavor id from host info,  check if it's in the policy for they being requested

                EtcdUtils etcdUtils = new EtcdUtils();
                GetKeyAttributesResponse getResponse = getKeyManager().getKeyAttributes(new GetKeyAttributesRequest(keyId));
                // String policy = etcdUtils.retrieveValueForKey(String.valueOf(getResponse.getData().get("policy_uri")));
                // String policyFlavor = jsonpath.getString(policy, "$.permission.key_transfer.flavor");
                // if (!policyFlavor.contains(hostInfo.flavorId)) {

				String policy;
                if(String.valueOf(getResponse.getData().get("policy_uri")).contains("/content")){
                    policy = etcdUtils.getKeplerLakeRegistryDAO().getString(String.valueOf(getResponse.getData().get("policy_uri")).replaceAll("urn:etcd:", ""));
                } else {
                    policy = etcdUtils.getKeplerLakeRegistryDAO().getString(String.valueOf(getResponse.getData().get("policy_uri")).concat("/content").replaceAll("urn:etcd:", ""));
                }
                log.debug("validating hostInfo flavor {} against policy {}", hostInfo.flavorId, policy);
                boolean flavorFound = false;
                AllOf[] allOfPolicy = jsonpath.getObject(AllOf[].class, policy, "$.allOf");
                /*if (allOfPolicy != null) {
                    log.debug("fetching merged policy details");
                    String policyContent;
                    for (AllOf allPol : allOfPolicy) {
                        policyContent = etcdUtils.getKeplerLakeRegistryDAO().getString(allPol.getUri().replace("urn:etcd:", ""));
                        if (policyContent != null) {
                            Flavor[] policyFlavor = jsonpath.getObject(Flavor[].class, policyContent, "$.permission.key_transfer.flavor");
                            for (Flavor flavor : policyFlavor) {
                                if (flavor != null && flavor.getUri() != null && flavor.getUri().contains(hostInfo.flavorId)) {
                                    flavorFound = true;
                                    break;
                                }
                            }
                            if (!flavorFound) {
                                break;
                            }
                        }
                    }
                } else {*/
                if (allOfPolicy == null || allOfPolicy.length == 0) {
                    log.warn("Searching for policy associated with the key");
                    Flavor[] policyFlavor = jsonpath.getObject(Flavor[].class, policy, "$.permission.key_transfer.flavor");
                    if (policyFlavor != null) {
                        for (Flavor flavor : policyFlavor) {
                            if (flavor != null && flavor.getUri() != null && flavor.getUri().contains(hostInfo.flavorId)) {
                                flavorFound = true;
                                break;
                            }
                        }
                    }

                    if (!flavorFound) {
                        log.error("Flavor {} not authorized to transfer key {}", hostInfo.flavorId, getResponse.getData().getKeyId());
                        return Response.status(Response.Status.UNAUTHORIZED).build();
                    }
                }
                log.debug("Before Calling transferKeyWithRemoteAttestation");
                try {
                    TransferKeyResponse transferKeyResponse = getKeyTransferUtil().transferKeyWithRemoteAttestation(request, keyId, context, hostIp, hostInfo.bindingPublicKey);
                    log.debug("transferKeyResponse");
                    // if there are no problems, return the key
                    if (transferKeyResponse.getFaults().isEmpty()) {
                        Pem pem = getKeyTransferUtil().createPemFromTransferKeyResponse(transferKeyResponse);
                        for (String headerName : pem.getHeaders().keySet()) {
                            response.addHeader(headerName, pem.getHeaders().get(headerName));
                        }
                        //return transferKeyResponse.getKey();
                        return Response.status(Response.Status.OK).entity(transferKeyResponse.getKey()).build();
                    }
                    // otherwise, return an error message using hint provided by business object, if available
                    logFaults("Cannot process key transfer", transferKeyResponse.getFaults());
                    if (transferKeyResponse.getHttpResponse().getStatusCode() != null) {
                        log.debug("Setting http status code {}", transferKeyResponse.getHttpResponse().getStatusCode());
                        /*
                 response.setStatus(transferKeyResponse.getHttpResponse().getStatusCode());
                 for(String name : transferKeyResponse.getHttpResponse().getHeaders().keys() ) {
                 for(String value : transferKeyResponse.getHttpResponse().getHeaders().get(name)) {
                 log.debug("Adding error response header {}: {}", name, value);
                 response.addHeader(name, value);
                 }
                 }
                 return null;
                         */
                        throw new WebApplicationException(transferKeyResponse.getHttpResponse().getStatusCode());
                    }
                } catch (IOException e) {
                    log.error("getKeyWithRemoteAttestationAsEncryptedBytes: failed to generate PEM response", e);
                    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
                }

            } else {
                log.error("Trust session not established with host: {}", hostIp);
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }

        } catch (IOException e) {
            log.error("Error while retrieving policy information for key " + keyId, e);
            return Response.status(Response.Status.UNAUTHORIZED).build();
        } catch (ScriptException | NoSuchMethodException ex) {
            log.error("Error while retieving flavors from the policy associated with key " + keyId, ex);
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }

    public static class AllOf {

        @JsonProperty("uri")
        private String uri;

        public String getUri() {
            return uri;
        }

        public void setUri(String uri) {
            this.uri = uri;
        }
    }

}
