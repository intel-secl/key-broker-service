/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.ws.v2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.impl.InsecureTlsPolicy;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.keplerlake.io.Etcdctl3;
import com.intel.keplerlake.registry.content.DatasetInfo;
import com.intel.keplerlake.registry.content.Service;
import com.intel.keplerlake.registry.ext.KeplerLakeRegistryDAO;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.KeyNotFound;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.keplerlake.KeplerLakeUtil;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 *
 * @author SSHEKHEX
 */
@V2
@Path("/key-proxy")
public class KeyProxy {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(KeyProxy.class);
    private final ObjectMapper mapper;
    public static final String KEY_ESCROW_TLS_SHA256 = "tls.certificate.sha256";
    public static final String KEY_ESCROW_URL = "url";
    public static final String KEY_ESCROW = "key-escrow";
    private final String UUID_REGEX = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private final String KEY_ID_REGEX = "/v1/keys/(" + UUID_REGEX + ")";
    private final KeyRepository repository;
    private final Configuration configuration;
    KeplerLakeUtil keplerLakeUtil;

    //public KeyProxy() throws IOException {
    public KeyProxy() throws Exception {
        mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        repository = new KeyRepository();
        keplerLakeUtil = new KeplerLakeUtil();
        configuration = ConfigurationFactory.getConfiguration();
    }

    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public GetKeyAttributesResponse keplerlakeKeyProxy(@QueryParam("url") String url, @QueryParam("source_realm") String source_realm,
            @QueryParam("source_path") String source_path, @QueryParam("replace_path") String replace_path,
            @Context HttpServletRequest httpServletRequest) {

        LOG.debug("Received Keplerlake KeyProxy request.");
        LOG.debug("keplerlakeKeyProxy url: {}", url);
        LOG.debug("keplerlakeKeyProxy source realm: {}", source_realm);
        LOG.debug("keplerlakeKeyProxy source path: {}", source_path);
        LOG.debug("keplerlakeKeyProxy replace path: {}", replace_path);

        GetKeyAttributesResponse response = new GetKeyAttributesResponse();
        String  bearer;
        if (url == null || url.isEmpty()) {
            response.getHttpResponse().setStatusCode(Response.Status.BAD_REQUEST.getStatusCode());
            response.getFaults().add(new InvalidParameter("url"));
            return response;
        }

        try {
            URL keyInfoUrl = new URL(url);
            List<Fault> faults = new ArrayList<>();
            String scheme = keyInfoUrl.getProtocol();
            String host = keyInfoUrl.getHost();
            int port = keyInfoUrl.getPort();
            String path = keyInfoUrl.getPath();

            if (scheme == null || scheme.isEmpty()) {
                faults.add(new InvalidParameter("scheme"));
            }
            if (host == null || host.isEmpty()) {
                faults.add(new InvalidParameter("serverName"));
            }
            if (port <= 0) {
                faults.add(new InvalidParameter("port"));
            }
            if (path == null || path.isEmpty()) {
                faults.add(new InvalidParameter("path"));
            }

            if (source_realm == null || source_realm.isEmpty()) {
                faults.add(new InvalidParameter("source_realm"));
            }

            bearer = httpServletRequest.getHeader("OAuth2-Authorization");
            LOG.debug("keyproxy bearer header value {}", bearer);
            bearer = bearer.replace("Bearer", "").trim();
            LOG.debug("keyproxy bearer value {}", bearer);
            if (bearer == null || bearer.isEmpty()) {
                faults.add(new MissingRequiredParameter("OAuth2-Authorization header must be present."));
            }

            if (!faults.isEmpty()) {
                LOG.error("Error in KeyProxy request.");
                response.getHttpResponse().setStatusCode(Response.Status.BAD_REQUEST.getStatusCode());
                response.getFaults().addAll(faults);
                return response;
            }

            String keyId;
            Matcher m = Pattern.compile(KEY_ID_REGEX).matcher(keyInfoUrl.getPath());
            if (m.matches()) {
                keyId = m.group(1);
            } else {
                LOG.error("Error while parsing keyid from proxy url.");
                throw new Exception("Error while parsing keyid from proxy url.");
            }
            LOG.debug("key id fetched {}", keyId);

            GetKeyAttributesRequest getLocalKeyReq = new GetKeyAttributesRequest(keyId);
            Etcdctl3 etcdctl3 = new Etcdctl3(keplerLakeUtil.getEnvMap());
            KeplerLakeRegistryDAO keplerLakeRegistryDAO = new KeplerLakeRegistryDAO(etcdctl3, source_realm);
            GetKeyAttributesResponse getLocalKeyResp = repository.getKeyManager().getKeyAttributes(getLocalKeyReq);
            LOG.debug("Get Key response from local Key Escrow server : {}", mapper.writeValueAsString(getLocalKeyResp));
            if (getLocalKeyResp != null && getLocalKeyResp.getData() != null && getLocalKeyResp.getData().map().containsKey("origin_url")
                    && (String.valueOf(getLocalKeyResp.getData().get("origin_url"))).equals(url)) {
                LOG.debug("Found key in local key escrow server.");
                GetKeyAttributesResponse keyResponse = new GetKeyAttributesResponse();
                keyResponse.setData(getLocalKeyResp.getData());
                response.getHttpResponse().setStatusCode(Response.Status.OK.getStatusCode());
                return keyResponse;
            } else {
                LOG.warn("Key not found in local server, searching in original server.");
                TlsConnection tlsConnection = new TlsConnection(new URL(String.format("https://%s:%d/v2", "127.0.0.1", 1443)),
                        new InsecureTlsPolicy());
                TEEClient teeClient = new TEEClient(new Properties(), tlsConnection);
                Service originalKmsService = keplerLakeRegistryDAO.getKMSService();
                String originalKmsURL = originalKmsService.map().get("url");
                String originalKmsTls = originalKmsService.map().get("tls.certificate.sha256");

                Key getRemoteKeyResp = teeClient.getKeyProxyCall(url, originalKmsTls);
                LOG.debug("Get Key response from remote Key Escrow server : {}", mapper.writeValueAsString(getRemoteKeyResp));
                if (getRemoteKeyResp != null) {
                    LOG.info("Found key in original key escrow server");
                    URL transferKeyUrl = getRemoteKeyResp.getTransferLink();
                    byte[] encryptedKey = teeClient.transferKeyProxyCall(transferKeyUrl.toURI().toString(), originalKmsTls,
                            httpServletRequest.getHeader("OAuth2-Authorization"));
                    LOG.debug("Encrypted key from Original Key Escrow server : '{}'", encryptedKey);
                    byte[] decryptedKey = teeClient.unbind(encryptedKey);
                    LOG.debug("Decrypted key from Original Key Escrow server : '{}'", decryptedKey);
                    RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
                    KeyDescriptor keyDescriptor = new KeyDescriptor();
                    KeyAttributes keyAttr = replaceAllIPWithLocal(getRemoteKeyResp);
                    if (replace_path != null && !replace_path.isEmpty()) {
                        keyAttr.set("path", replace_path);
                    }
                    keyAttr.set("origin_url", getRemoteKeyResp.getTransferLink().toExternalForm().replace("/transfer", ""));
                    LOG.debug("Key after replacing IPs : {}", mapper.writeValueAsString(keyAttr));
                    keyDescriptor.setContent(keyAttr);
                    registerKeyRequest.setKey(decryptedKey);
                    registerKeyRequest.setDescriptor(keyDescriptor);
                    RegisterKeyResponse registerKeyResponse = repository.getKeyManager().registerKey(registerKeyRequest);
                    response.setData(registerKeyResponse.getData().get(0));

                    CipherKeyAttributes derivedKeyAttributes = new CipherKeyAttributes();
                    derivedKeyAttributes.setAlgorithm("HMAC");
                    derivedKeyAttributes.setKeyLength(256);

                    String datasetPath = null;
                    if (replace_path != null && !replace_path.isEmpty()) {
                        LOG.debug("replace path:{}", replace_path);
                        datasetPath = replace_path;
                    } else if (source_path != null && !source_path.isEmpty()) {
                        LOG.debug("source path:{}", replace_path);
                        datasetPath = source_path;
                    }
                     LOG.debug("before storeDatasetInfo call:{}",datasetPath);
                     storeDatasetInfo(registerKeyResponse.getData().get(0), datasetPath, bearer, source_realm);
                    response.getHttpResponse().setStatusCode(Response.Status.OK.getStatusCode());
                    return response;
                } else if (source_path != null && source_realm != null && !source_path.isEmpty() && !source_realm.isEmpty()) {

                    String regex = "(.*/v1/keys)";
                    Pattern pattern = Pattern.compile(regex);
                    Matcher matcher = pattern.matcher(originalKmsURL);
                    if (matcher.find()) {
                        KeyCollection keys = teeClient.searchKeyProxyCall(matcher.group(0) + source_path, originalKmsTls);
                        if (keys != null && keys.getKeys() != null && keys.getKeys().size() > 0) {
                            LOG.debug("Search Key response from remote Key Escrow server : {}", mapper.writeValueAsString(keys));
                            URL transferKeyUrl = keys.getKeys().get(0).getTransferLink();
                            byte[] encryptedKey = teeClient.transferKeyProxyCall(transferKeyUrl.toURI().toString(), originalKmsTls,
                                    httpServletRequest.getHeader("OAuth2-Authorization"));
                            LOG.debug("Encrypted key from Original Key Escrow server : '{}'", encryptedKey);
                            byte[] decryptedKey = teeClient.unbind(encryptedKey);
                            LOG.debug("Decrypted key from Original Key Escrow server : '{}'", decryptedKey);
                            RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
                            KeyAttributes keyAttr = new KeyAttributes();
                            copy(keys.getKeys().get(0), keyAttr);
                            keyAttr = replaceAllIPWithLocal(keyAttr);
                            keyAttr.set("source_path", source_path);
                            keyAttr.set("source_realm", source_realm);
                            KeyDescriptor keyDescriptor = new KeyDescriptor();
                            LOG.debug("Key after replacing IPs : {}", mapper.writeValueAsString(keyAttr));
                            keyDescriptor.setContent(keyAttr);
                            registerKeyRequest.setDescriptor(keyDescriptor);
                            RegisterKeyResponse registerKeyResponse = repository.getKeyManager().registerKey(registerKeyRequest);
                            response.setData(registerKeyResponse.getData().get(0));
                            CipherKeyAttributes derivedKeyAttributes = new CipherKeyAttributes();
                            derivedKeyAttributes.setAlgorithm("HMAC");
                            derivedKeyAttributes.setKeyLength(256);
                            byte[] derivedHmacSecretKey = keplerLakeUtil.deriveKey(decryptedKey, (byte[]) registerKeyResponse.getData().get(0).get("salt"),
                                    "hmac", keyAttr, derivedKeyAttributes);
                            SecretKey skey = new SecretKeySpec(derivedHmacSecretKey, "hmac");
                            String dataInfo = keplerLakeRegistryDAO.getDatasetInfoWithHmac(source_path, skey);
                            if (dataInfo == null || dataInfo.isEmpty()) {
                                LOG.debug("retrieved dataset info");
                                  storeDatasetInfo(registerKeyResponse.getData().get(0), source_path, bearer, source_realm);
                            }
                            response.getHttpResponse().setStatusCode(Response.Status.OK.getStatusCode());
                            return response;
                        } else {
                            LOG.error("Key {} not found in original key escrow server.", keyId);
                            response.getHttpResponse().setStatusCode(Response.Status.NOT_FOUND.getStatusCode());
                            response.getFaults().add(new KeyNotFound(keyId));
                            return response;
                        }
                    } else {
                        LOG.error("Unable to parse key info url " + originalKmsURL);
                        response.getHttpResponse().setStatusCode(Response.Status.NOT_FOUND.getStatusCode());
                        response.getFaults().add(new InvalidParameter(originalKmsURL));
                        return response;
                    }
                } else {
                    LOG.error("Key {} not found in original key escrow server.", keyId);
                    response.getHttpResponse().setStatusCode(Response.Status.NOT_FOUND.getStatusCode());
                    response.getFaults().add(new KeyNotFound(keyId));
                    return response;
                }
            }
        } catch (Exception ex) {
            LOG.error("Error while executing proxy key service class.", ex);
            response.getHttpResponse().setStatusCode(Response.Status.BAD_GATEWAY.getStatusCode());
            response.getFaults().add(new Fault(ex.getCause(), ex.getMessage()));
            return response;
        }
    }

  /**
     *
     * @param attr
     * @param datasetPath
     * @param oauth2BearerToken
     * @param realmName
     */
    private void storeDatasetInfo(KeyAttributes attr,String datasetPath,String oauth2BearerToken,String realmName) {
        DatasetInfo datasetInfo = new DatasetInfo();
        try {
            LOG.debug("dataset path in storedatasetinfo:{}",datasetPath);
            datasetInfo.path = datasetPath;
            datasetInfo.date = keplerLakeUtil.getISOTimeZone();
            Map<String, DatasetInfo.Link> link = new HashMap();
            DatasetInfo.Link policyLink = new DatasetInfo.Link();
            DatasetInfo.Link keyLink = new DatasetInfo.Link();
            policyLink.uri = String.valueOf(attr.get("policy_uri"));
            keyLink.uri = attr.getTransferLink().toURI().toString().replace("/transfer", "");
            link.put("policy", policyLink);
            link.put("key", keyLink);
            datasetInfo.link = link;
            LOG.debug("source realm in keyproxy:{}", realmName);
            KeplerLakeRegistryDAO  keplerLakeRegistryDAO;
            LOG.debug("keplerlake key dataset info:{}", mapper.writeValueAsString(datasetInfo));
            keplerLakeRegistryDAO = keplerLakeUtil.getDaoInstance();
            Service originalKmsService = keplerLakeRegistryDAO.getKMSService();
            String originalKmsTls = originalKmsService.map().get("tls.certificate.sha256");
            keplerLakeRegistryDAO = keplerLakeUtil.getDaoInstanceWithTagentClient(realmName);
            if (keplerLakeRegistryDAO != null) {
                LOG.debug("originalKmsTls in keyproxy:{}", originalKmsTls);
                keplerLakeRegistryDAO.putDatasetInfoWithHmac(datasetInfo, oauth2BearerToken, originalKmsTls);
                 LOG.debug("In keyproxy datasetinfo stored");

            }
        } catch (IOException | SignatureException | URISyntaxException ex) {
            LOG.debug("Exception in storing datasetinfo for merge policy{}", ex);
        }

    }

    private void copy(Key from, KeyAttributes to) throws IOException {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setKeyId(from.getId().toString());
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setTransferLink(from.getTransferLink());
        to.setUsername(from.getUsername());
        to.copyFrom(from.getExtensions());
    }

    private KeyAttributes replaceAllIPWithLocal(KeyAttributes key) throws IOException {
        KeyAttributes keyAttr = new KeyAttributes();
        LOG.debug("Replacing key info details to point to local key escrow.");
        LOG.debug("Key before replacing IPs : {}", mapper.writeValueAsString(key));
        keyAttr.setAlgorithm(key.getAlgorithm());
        keyAttr.setDescription(key.getDescription());
        keyAttr.setDigestAlgorithm(key.getDigestAlgorithm());
        keyAttr.setKeyId(key.getKeyId());
        keyAttr.setKeyLength(key.getKeyLength());
        keyAttr.setMode(key.getMode());
        keyAttr.setPaddingMode(key.getPaddingMode());
        keyAttr.setRole(key.getRole());
        keyAttr.setUsername(key.getUsername());
        keyAttr.setTransferPolicy(key.getTransferPolicy());
        keyAttr.setTransferLink(getTransferLinkForKeyId(key.getKeyId()));
        keyAttr.set("transferLink", getTransferLinkForKeyId(key.getKeyId()));

        Map<String, Object> modifiableMap = new HashMap<>();
        modifiableMap.putAll(key.map());

        keyAttr.set("derivation", createDerivationObject(getTransferLinkForKeyId(key.getKeyId()).toExternalForm()));

        LOG.debug("dervivation obj formed : {}", mapper.writeValueAsString(keyAttr.get("derivation")));
        for (String obj : modifiableMap.keySet()) {
            LOG.debug("Adding key {} value {}", obj, modifiableMap.get(obj));
            keyAttr.set(obj, modifiableMap.get(obj));
        }
        LOG.debug("Key after replacing IPs in function : {}", mapper.writeValueAsString(keyAttr));
        return keyAttr;
    }

    private URL getTransferLinkForKeyId(String keyId) throws MalformedURLException {
        String template = configuration.get("endpoint.key.transfer.url", String.format("%s/v1/keys/{keyId}/transfer", configuration.get("endpoint.url", "http://localhost")));
        LOG.debug("getTransferLinkForKeyId template: {}", template);
        String url = template.replace("{keyId}", keyId);
        LOG.debug("getTransferLinkForKeyId url: {}", url);
        return new URL(url);
    }

    private KeyAttributes replaceAllIPWithLocal(Key key) throws IOException {
        KeyAttributes keyAttr = new KeyAttributes();
        LOG.debug("Replacing key info details to point to local key escrow.");
        LOG.debug("Key before replacing IPs : {}", mapper.writeValueAsString(key));
        keyAttr.setAlgorithm(key.getAlgorithm());
        keyAttr.setDescription(key.getDescription());
        keyAttr.setDigestAlgorithm(key.getDigestAlgorithm());
        keyAttr.setKeyId(key.getId().toString());
        keyAttr.setKeyLength(key.getKeyLength());
        keyAttr.setMode(key.getMode());
        keyAttr.setPaddingMode(key.getPaddingMode());
        keyAttr.setRole(key.getRole());
        keyAttr.setUsername(key.getUsername());
        keyAttr.setTransferPolicy(key.getTransferPolicy());
        keyAttr.setTransferLink(getTransferLinkForKeyId(key.getId().toString()));
        keyAttr.set("transferLink", getTransferLinkForKeyId(key.getId().toString()));

        Map<String, Object> modifiableMap = new HashMap<>();
        modifiableMap.putAll(key.getExtensions().map());

        for (String obj : modifiableMap.keySet()) {
            LOG.debug("Adding key {} value {}", obj, modifiableMap.get(obj));
            keyAttr.set(obj, modifiableMap.get(obj));
        }

        keyAttr.set("derivation", createDerivationObject(getTransferLinkForKeyId(key.getId().toString()).toExternalForm()));
        LOG.debug("dervivation obj formed : {}", mapper.writeValueAsString(keyAttr.get("derivation")));

        LOG.debug("Key after replacing IPs in function : {}", mapper.writeValueAsString(keyAttr));
        return keyAttr;
    }

    private Object createDerivationObject(String transferLink) {

        Map<String, Map<String, Object>> map = new HashMap<>();

        Map<String, Object> sub;
        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "XTS");
        sub.put("key_length", 512);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=dm-crypt");
        map.put("dm-crypt", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "CBC");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=ecryptfs");
        map.put("ecryptfs", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "CBC");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=openssl");
        map.put("openssl", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "HMAC");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=hmac");
        map.put("hmac", sub);

        return map;
    }
}
