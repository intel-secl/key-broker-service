/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import com.intel.mtwilson.tag.model.Certificate;
import com.intel.mtwilson.tag.model.CertificateCollection;
import com.intel.mtwilson.tag.model.CertificateFilterCriteria;

/**
 * The API resource is used to create, delete and update TPM identity certificates.
 * @author rksavino
 */
public class TpmIdentityCertificates extends JaxrsClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmIdentityCertificates.class);
    
    /**
     * To use password-based HTTP BASIC authorization with the user server, 
     * the client must be initialized with the following properties:
     * endpoint.url, login.basic.username, login.basic.password, and any valid TLS
     * policy. The example below uses the Properties format, a sample URL, and
     * a sample TLS certificate SHA-384 fingerprint:
     *<pre>
     * endpoint.url=https://kms.example.com
     * tls.policy.certificate.sha384=3e290080376a2a27f6488a2e10b40902b2194d701625a9b93d6fb25e5f5deb194b452544f8c5c3603894eb56eccb3057
     * login.basic.username=client-username
     * login.basic.password=client-password
     * </pre>
     */
    public TpmIdentityCertificates(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public TpmIdentityCertificates(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    /**
     * Creates a TPM identity certificate in the service database.
     * <pre>
     * This method registers a TPM identity public key certificate to the service. During the
     * SAML transfer key API call, a SAML report containing a host TPM AIK certificate is provided.
     * It is verified that a TPM identity certificate registered with this service has signed this
     * AIK. The binding key certificate is retrieved from the SAML report and it verifies that a
     * TPM identity certificate has signed this cert as well. The certificate object model includes
     * an ID, base64 encoded certificate and a revoked status.
     * </pre>
     * @param certificate The serialized certificate java model object represents the content of the<br/>
     * request body. Only the certificate portion is specified in the request.<br/>
     * <pre>
     * 
     *              id (NOT required)                Certificate UUID that is randomly generated
     * 
     *              certificate (required)           Base64 encoded TPM identity certificate
     * 
     *              revoked (NOT required)           Boolean indicating whether the certificate is
     *                                               valid for the service
     * </pre>
     * @return The serialized certificate java model object that was created.
     * @since ISecL 2.0
     * @mtwRequiresPermissions tpm_identity_certificates:create
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre>
     * https://kms.server.com:kms_port/v1/tpm-identity-certificates
     * 
     * Headers:
     * Content-Type: application/x-pem-file
     * 
     * Input:
     *         -----BEGIN CERTIFICATE-----
     *         MIIDMjCCAhqgAwIBAgIGAWfO03T4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u
     *         LXBjYS1haWswHhcNMTgxMjIxMDMzMzQzWhcNMjgxMjIwMDMzMzQzWjAbMRkwFwYDVQQDExBtdHdp
     *         bHNvbi1wY2EtYWlrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1ci0WLpy+8hZeMt
     *         Gt6pH1tQYKS4IsKthZYcoJAoPKk3OZZr0egw12eOEJY2zV6l5OXq98NQ3GevvuDy/9GVcNjhIO/h
     *         Yn0LkedL3QF34TZrpVFb5seap+ppcgHUflVVqmcKMl8LpwlXxxkN0ABasajjKmBAQ6CUgL6KXVCE
     *         xUxyDOo46iz9muoJo3sZ71YXHLRUyPp4t1YBx8xwOA2hKE+uB1hhcABNTLu0CTdt5Wbh+Xe+MQhg
     *         HIhmJaTeBq5HGQa7iTfAmdWwwGW9OOHHXP33ppahQ5KaZ6301hz50Xtdobvlvwo0xGO3UJSL9zAB
     *         GV+Y27j1FRtD0rYPZEFTAwIDAQABo3wwejAdBgNVHQ4EFgQUL9YUt/Yv5BXKsYiJJK7CzXdEuZsw
     *         DwYDVR0TAQH/BAUwAwEB/zBIBgNVHSMEQTA/gBQv1hS39i/kFcqxiIkkrsLNd0S5m6EfpB0wGzEZ
     *         MBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpa4IGAWfO03T4MA0GCSqGSIb3DQEBCwUAA4IBAQAUdD1c
     *         3KHGI7KLZ2YZ//PliNSzNyuM6BCRN7ZCmlwDhwbPKkxVEeuPEQ+rT3eVE87Tvzx/Bwk18kI8ErB+
     *         6oQRO6KiZFnGOedHzaKT8GgQjmRSdszj2lRq6+1UCXIxeT8HVUAFUVgOa4bMndRZmlkwuhoSblsf
     *         kEDAojfh8EJa1/i52tkJR+uIy/7/D3wY2UEzYxoNquuDKlPWDbp2G48MOMMdhRk3HfDDna66mm3/
     *         DLhcRFbzNUIhWvn5Kp5sGGiN/VgQCHdDFvnZH/k0W1a/SO5gGTL/ttVjWFjEdDaKs34EPA4ySlW4
     *         t4WHBaD1mPVF39J7Y6QBlbvGo6JLKVFO
     *         -----END CERTIFICATE-----
     * 
     * Output:
     * {
     *      "id": "cd4f4fc4-73d4-42ac-a0d2-0fe896ec694c",
     *      "certificate": "MIIDMjCCAhqgAwIBAgIGAWfO03T4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u
     *                      LXBjYS1haWswHhcNMTgxMjIxMDMzMzQzWhcNMjgxMjIwMDMzMzQzWjAbMRkwFwYDVQQDExBtdHdp
     *                      bHNvbi1wY2EtYWlrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1ci0WLpy+8hZeMt
     *                      Gt6pH1tQYKS4IsKthZYcoJAoPKk3OZZr0egw12eOEJY2zV6l5OXq98NQ3GevvuDy/9GVcNjhIO/h
     *                      Yn0LkedL3QF34TZrpVFb5seap+ppcgHUflVVqmcKMl8LpwlXxxkN0ABasajjKmBAQ6CUgL6KXVCE
     *                      xUxyDOo46iz9muoJo3sZ71YXHLRUyPp4t1YBx8xwOA2hKE+uB1hhcABNTLu0CTdt5Wbh+Xe+MQhg
     *                      HIhmJaTeBq5HGQa7iTfAmdWwwGW9OOHHXP33ppahQ5KaZ6301hz50Xtdobvlvwo0xGO3UJSL9zAB
     *                      GV+Y27j1FRtD0rYPZEFTAwIDAQABo3wwejAdBgNVHQ4EFgQUL9YUt/Yv5BXKsYiJJK7CzXdEuZsw
     *                      DwYDVR0TAQH/BAUwAwEB/zBIBgNVHSMEQTA/gBQv1hS39i/kFcqxiIkkrsLNd0S5m6EfpB0wGzEZ
     *                      MBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpa4IGAWfO03T4MA0GCSqGSIb3DQEBCwUAA4IBAQAUdD1c
     *                      3KHGI7KLZ2YZ//PliNSzNyuM6BCRN7ZCmlwDhwbPKkxVEeuPEQ+rT3eVE87Tvzx/Bwk18kI8ErB+
     *                      6oQRO6KiZFnGOedHzaKT8GgQjmRSdszj2lRq6+1UCXIxeT8HVUAFUVgOa4bMndRZmlkwuhoSblsf
     *                      kEDAojfh8EJa1/i52tkJR+uIy/7/D3wY2UEzYxoNquuDKlPWDbp2G48MOMMdhRk3HfDDna66mm3/
     *                      DLhcRFbzNUIhWvn5Kp5sGGiN/VgQCHdDFvnZH/k0W1a/SO5gGTL/ttVjWFjEdDaKs34EPA4ySlW4
     *                      t4WHBaD1mPVF39J7Y6QBlbvGo6JLKVFO",
     *      "revoked": false
     * }
     * </pre>
     */
    public Certificate createTpmIdentityCertificate(Certificate certificate) {
        Certificate created = getTarget().path("/v1/tpm-identity-certificates").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(certificate), Certificate.class);
        return created;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificate
     * 
     */
    public void deleteTpmIdentityCertificate(Certificate certificate) {
        deleteTpmIdentityCertificate(certificate.getId().toString());
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificateId
     * 
     */
    public void deleteTpmIdentityCertificate(String certificateId) {
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", certificateId);
        getTarget().path("/v1/tpm-identity-certificates/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).delete();
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificate
     * @return 
     * 
     */
    public Certificate editTpmIdentityCertificate(Certificate certificate) {
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", certificate.getId());
        Certificate edited = getTarget().path("/v1/tpm-identity-certificates/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).put(Entity.json(certificate), Certificate.class);
        return edited;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param filterCriteria
     * @return 
     * 
     **/
    public CertificateCollection searchTpmIdentityCertificates(CertificateFilterCriteria filterCriteria) {
        CertificateCollection searchCertificatesResponse = getTargetPathWithQueryParams("/v1/tpm-identity-certificates", filterCriteria).request().accept(MediaType.APPLICATION_JSON).get(CertificateCollection.class);
        return searchCertificatesResponse;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificateId
     * @return 
     * 
     **/
    public Certificate retrieveTpmIdentityCertificate(String certificateId) {
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", certificateId);
        Certificate retrieved = getTarget().path("/v1/tpm-identity-certificates/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).get(Certificate.class);
        return retrieved;
    }
    
    
}
