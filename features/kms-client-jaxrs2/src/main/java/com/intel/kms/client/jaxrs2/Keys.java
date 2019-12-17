/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;

/**
 * The API resource is used to create, delete and retrieve keys. 
 * @author jbuhacoff
 */
public class Keys extends JaxrsClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Keys.class);
    
    /**
     * To use password-based HTTP BASIC authorization with the key server, 
     * the client must be initialized with the following properties:
     * endpoint.url, login.basic.username, login.basic.password, and any valid TLS
     * policy. The example below uses the Properties format, a sample URL, and
     * a sample TLS certificate SHA-384 fingerprint:
     * <pre>
     * endpoint.url=https://kms.example.com
     * tls.policy.certificate.sha384=3e290080376a2a27f6488a2e10b40902b2194d701625a9b93d6fb25e5f5deb194b452544f8c5c3603894eb56eccb3057
     * login.basic.username=client-username
     * login.basic.password=client-password
     * </pre>
     **/
    public Keys(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public Keys(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
   /**<pre>
     * Create key.
     *</pre>
     * @param createKeyRequest The CreateKeyRequest java model object represents the content of the request body.
     * <pre>
     *                 algorithm (required)             Encryption algorithm used to create key. Only supported algorithm is AES
     * 
     *                 key_length (required)            Key length supported is 256 bits.
     * 
     *                 mode   (required)                Encyption mode supported is GCM.
     * 
     *                 padding_mode (optional)          Block cipher modes for symmetric-key encryption algorithms require plain text input 
     *                                                  that is a multiple of the block size. Padding mode is used for this purpose.
     *                 
     *                 digest_algorithm (optional)      Digest algorithm used in conjunction with the key. Example : SHA 384
     *                 
     *                 transfer_policy (optional)       URI of a transfer policy to apply to this key. The KMS requires a transfer
     *                                                  policy for every key but may support a default policy for new key requests
     *                                                  which omit this attribute and/or a global (fixed) policy for all key requests
     *                                                  (where specifying the attribute would be an error because it would be ignored).
     *                                                  The policy itself is a separate document that describes who may access the key
     *                                                  under what conditions (trusted, authenticated, etc)
     *                                                  Example: urn:intel:trustedcomputing:keytransferpolicy:trusted might indicate 
     *                                                  that a built-in policy will enforce that the key is only released to trusted
     *                                                  clients, and leave the definition of trusted up to the trust attestation server.
     *                                                  Example: http://fileserver/path/to/policy.xml might indicate that the
     *                                                  fileserver has a file policy.xml which is signed by this keyserver and
     *                                                  contains the complete key transfer policy including what is a trusted
     *                                                  client, what is the attestation server trusted certificate, etc.
     *                
     *                description (optional)            User-provided description of the key.
     *                 
     * </pre>
     * @return <pre>The Key java model object that was created each containing:
     *          algorithm
     *          key_length
     *          mode
     *          padding_mode
     *          transfer_policy
     *          transferLink
     *          description
     *          digest_algorithm
     * @since ISecL 2.0
     * @mtwRequiresPermissions keys:create
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * https://kms.server.com:443/v1/keys
     *               
     * <b>Example 1:</b>
     *
     * Input:
     * { 
     *     "algorithm": "AES",
     *     "key_length": "256",
     *     "mode": "GCM",
     *     "padding_mode": "None",
     *     "digest_algorithm": "SHA384",
     *     "transfer_policy": "urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization"
     * }
     * Output:
     * {
     *      "id": "04cc4659-ace2-4128-9861-c51ede8ca586",
     *      "algorithm": "AES",
     *      "key_length": 256,
     *      "mode": "GCM",  
     *      "padding_mode": "None",
     *      "transfer_policy": "urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization",
     *      "transfer_link": "http://kms.server.com/v1/keys/04cc4659-ace2-4128-9861-c51ede8ca586/transfer",
     *      "digest_algorithm": "SHA384"
     * }
     */ 
    public Key createKey(CreateKeyRequest createKeyRequest) {
        log.debug("createKey: {}", getTarget().getUri().toString());
        Key createKeyResponse = getTarget().path("/v1/keys").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(createKeyRequest), Key.class);
        return createKeyResponse;
    }
    
    public KeyCollection registerKey(RegisterKeyRequest registerKeyRequest) {
        log.debug("registerKey: {}", getTarget().getUri().toString());
        KeyCollection registerKeyResponse = getTarget().path("/v1/keys").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(registerKeyRequest), KeyCollection.class);
        return registerKeyResponse;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param deleteKeyRequest
     * @return 
     */
    public DeleteKeyResponse deleteKey(DeleteKeyRequest deleteKeyRequest) {
        log.debug("deleteKey: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", deleteKeyRequest.getKeyId());
        DeleteKeyResponse deleteKeyResponse = getTarget().path("/v1/keys/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).delete(DeleteKeyResponse.class);
        return deleteKeyResponse;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param keyId
     * @return
     */
    public void deleteKey(String keyId) {
        DeleteKeyRequest deleteKeyRequest = new DeleteKeyRequest(keyId);
        DeleteKeyResponse deleteKeyResponse = deleteKey(deleteKeyRequest);
        if( deleteKeyResponse != null && !deleteKeyResponse.getFaults().isEmpty() ) {
            // log errors and throw exception
            for(Fault fault : deleteKeyResponse.getFaults() ) {
                log.error("Cannot delete key {}: {}", keyId, fault.toString());
            }
            throw new IllegalArgumentException("Cannot delete key");
        }
    }
    
    /**<pre>
     * This method retrieves a service generated key that is wrapped by a user transfer key. After the
     * user receives the wrapped key, they can use their user private key to unwrap the actual key.
     * This method returns a JSON formatted cipher.
     * </pre>
     * <pre>
     * @param 
     *           id (required)          Key ID specified as a path parameter.
     * </pre>
     * @since ISecL 2.0
     * @mtwContentTypeReturned application/json
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * http://kms.server.com/v1/keys/c229de31-ab6f-4e4d-b3fd-c902295a76bc/transfer
     * 
     * Headers:
     * Accept: application/json
     * 
     * Output:
     * {
     *     "cipher.key":"h85MQ5m4FqGliMNXgG+uu1b00j80fWwMkmApr1Sgc7sm5FFHTN9JVxNMaFR7nLOtAzuTenAD0fc7
     *                   G6E6zn5sYUGJo6HM16/Cgu+eiFTO7iIWFMfSNzPESFTruVQSpELVxnCkc+xQG6GhsNYh+IqEaZpc
     *                   UNiRLREKwCJ6/rEgFLISKbfihejQDy7B8HeH+WyJcTIaTb8cojZaZX2gy4kyyo9KO7nEKRughU/J
     *                   8KrsaqE2eDj1QtLYJprJ1yk2+UcyXjd2GnpMF0n6gCo5A/jbkITEWaN6NVsmV7nqGqKiTWJbTGcd
     *                   bSZmb/LoJws0tY85m+UPBUWB/SiHKbzXZaGjHA==",
     *     "cipher.json":{
     *         "content":{
     *             "key_id":"114a1bc1-78c2-4ad3-80d3-f5bc62d539ed",
     *             "algorithm":"AES",
     *             "key_length":128,
     *             "mode":"OFB",
     *             "padding_mode":"None",
     *             "digest_algorithm":"SHA-384",
     *             "transferPolicy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization",
     *             "transferLink":"http://kms.server.com/v1/keys/114a1bc1-78c2-4ad3-80d3-f5bc62d539ed/transfer"
     *         },
     *         "encryption":{
     *             "key_id":"admin",
     *             "algorithm":"RSA/ECB/OAEPWithSHA-384AndMGF1Padding",
     *             "key_length":3072
     *         },
     *         "integrity":{
     *             "key_id":"114a1bc1-78c2-4ad3-80d3-f5bc62d539ed",
     *             "algorithm":"HMAC-SHA256",
     *             "key_length":128,
     *             "manifest":["cipher.key","cipher.json"],
     *             "signature":"integrity.sig"
     *         },
     *         "links":[
     *             {
     *                 "rel":"content",
     *                 "href":"cipher.key",
     *                 "type":"application/octet-stream"
     *             },
     *             {
     *                 "rel":"content-descriptor",
     *                 "href":"cipher.json",
     *                 "type":"application/json"
     *             },
     *             {
     *                 "rel":"signature",
     *                 "href":"integrity.sig",
     *                 "type":"application/octet-stream"
     *             }
     *         ]
     *     },
     *     "integrity.sig":"iZklSGLcY9LrL4C28K/xj5mE0fcZ93fGQ5elpNjnrr0=",
     *     "key":"h85MQ5m4FqGliMNXgG+uu1b00j80fWwMkmApr1Sgc7sm5FFHTN9JVxNMaFR7nLOtAzuTenAD0fc7
     *            G6E6zn5sYUGJo6HM16/Cgu+eiFTO7iIWFMfSNzPESFTruVQSpELVxnCkc+xQG6GhsNYh+IqEaZpc
     *            UNiRLREKwCJ6/rEgFLISKbfihejQDy7B8HeH+WyJcTIaTb8cojZaZX2gy4kyyo9KO7nEKRughU/J
     *            8KrsaqE2eDj1QtLYJprJ1yk2+UcyXjd2GnpMF0n6gCo5A/jbkITEWaN6NVsmV7nqGqKiTWJbTGcd
     *            bSZmb/LoJws0tY85m+UPBUWB/SiHKbzXZaGjHA==",
     *     "descriptor":{
     *         "content":{
     *             "key_id":"114a1bc1-78c2-4ad3-80d3-f5bc62d539ed",
     *             "algorithm":"AES",
     *             "key_length":128,
     *             "mode":"OFB",
     *             "padding_mode":"None",
     *             "digest_algorithm":"SHA-384",
     *             "transferPolicy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization",
     *             "transferLink":"http://kms.server.com/v1/keys/114a1bc1-78c2-4ad3-80d3-f5bc62d539ed/transfer"
     *         },
     *         "encryption":{
     *             "key_id":"admin",
     *             "algorithm":"RSA/ECB/OAEPWithSHA-384AndMGF1Padding",
     *             "key_length":3072
     *         },
     *         "integrity":{
     *             "key_id":"114a1bc1-78c2-4ad3-80d3-f5bc62d539ed",
     *             "algorithm":"HMAC-SHA256",
     *             "key_length":128,
     *             "manifest":[
     *                 "cipher.key",
     *                 "cipher.json"
     *             ],
     *             "signature":"integrity.sig"
     *         },
     *         "links":[
     *             {
     *                 "rel":"content",
     *                 "href":"cipher.key",
     *                 "type":"application/octet-stream"
     *             },
     *             {
     *                 "rel":"content-descriptor",
     *                 "href":"cipher.json",
     *                 "type":"application/json"
     *             },
     *             {
     *                 "rel":"signature",
     *                 "href":"integrity.sig",
     *                 "type":"application/octet-stream"
     *             }
     *         ],
     *     }
     * }
     */
     public TransferKeyResponse transferKey(TransferKeyRequest transferKeyRequest) {
        log.debug("transferKey: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", transferKeyRequest.getKeyId());
        TransferKeyResponse transferKeyResponse = getTarget().path("/v1/keys/{id}/transfer").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).post(Entity.json(transferKeyRequest), TransferKeyResponse.class);
        return transferKeyResponse;
    }
     
    /**<pre>
     * This method retrieves a service generated key that is wrapped by a user transfer key. After the
     * user receives the wrapped key, they can use their user private key to unwrap the actual key.
     * This method returns a PEM formatted encrypted key.
     * </pre>
     * <pre>
     *@param
     *           id (required)          Key ID specified as a path parameter.
     * </pre>
     * @since ISecL 2.0
     * @mtwContentTypeReturned APPLICATION_X_PEM_FILE
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * http://kms.server.com/v1/keys/c229de31-ab6f-4e4d-b3fd-c902295a76bc/transfer
     * 
     * Headers:
     * Content-Type: text/plain
     * Accept: application/x-pem-file
     * 
     * Output:
     * HTTP 200 OK
     * 
     * -----BEGIN ENCRYPTED KEY-----
     * Content-Algorithm: AES
     * Content-Key-Id: 114a1bc1-78c2-4ad3-80d3-f5bc62d539ed
     * Content-Key-Length: 256
     * Content-Mode: GCM
     * Content-Padding-Mode: None
     * Encryption-Algorithm: RSA/ECB/OAEPWithSHA-384AndMGF1Padding
     * Encryption-Key-Id: admin
     * Encryption-Key-Length: 3072
     * Integrity-Algorithm: HMAC-SHA256
     * Integrity-Key-Id: 114a1bc1-78c2-4ad3-80d3-f5bc62d539ed
     * Integrity-Key-Length: 128
     * Integrity-Manifest: cipher.key, cipher.json
     * XbEurYAMrpi4JuTo/ea+KGNUNSOGstySdb8quYNgBDaFGAJ55iaXCwwtY4Eet6PN4OcmcmL+ZFR6
     * WTt2UzQXLO8xs9UtWeryPuSlm0zU6/1LwxwDg3gETtR1FmXfG9HrD4G+uSlGWLL0+Qg4819WHacX
     * vNaYtZN4QPVptQyE/+ZJSim6XyiilOQsgKOo5DATe8LoZJz76vfYSo8S5cBbucsf8WlDMKCtMIks
     * LqrPB1L4J5fDMRP2W9BwKGkpszWclrGtjfmnNwuSLqQCkRmTspP1QmGSveHdFkYbOkFHDFkDA3/X
     * EoIG2j0ekuBqYBQII/Iu3ga52TEvOyYCy9Sdpw==
     * -----END ENCRYPTED KEY-----
     *               
     */
     public String transferKey(String keyId) {
        log.debug("transferKey: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", keyId);
        // note we are sending an empty post body because this transfer request requires only key id (from url) and username (from login) which are already available to server without any message body
        String transferKeyResponse = getTarget().path("/v1/keys/{id}/transfer").resolveTemplates(map).request().accept(CryptoMediaType.APPLICATION_X_PEM_FILE).post(Entity.text(""), String.class);
        return transferKeyResponse;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param getKeyAttributesRequest
     * @return 
     */
    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest getKeyAttributesRequest) {
        log.debug("searchKeyAttributes: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", getKeyAttributesRequest.getKeyId());
        GetKeyAttributesResponse getKeyAttributesResponse = getTarget().path("/v1/keys/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).get(GetKeyAttributesResponse.class);
        return getKeyAttributesResponse;
    }
    /***
     * Method supported. Description of method to be added in future.
     * @param searchKeyAttributesRequest
     * @return 
     */
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        log.debug("searchKeyAttributes: {}", getTarget().getUri().toString());
        SearchKeyAttributesResponse searchKeyAttributesResponse = getTargetPathWithQueryParams("/v1/keys", searchKeyAttributesRequest).request().accept(MediaType.APPLICATION_JSON).get(SearchKeyAttributesResponse.class);
        return searchKeyAttributesResponse;
    }
       
    
    
}
