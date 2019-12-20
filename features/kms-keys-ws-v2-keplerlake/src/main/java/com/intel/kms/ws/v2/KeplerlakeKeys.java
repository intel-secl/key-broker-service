/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.ws.v2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashBiMap;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.dcsg.cpg.validation.ValidationException;
import com.intel.keplerlake.authz.oauth2.OAuth2Client;
import com.intel.keplerlake.registry.content.DatasetInfo;
import com.intel.keplerlake.registry.content.Service;
import com.intel.keplerlake.registry.ext.KeplerLakeRegistryDAO;
import com.intel.keplerlake.registry.locator.PolicyLocator;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.keplerlake.KeplerLakeUtil;
import com.intel.kms.keplerlake.KeplerlakeClient;
import com.intel.kms.keplerlake.Meta;
import com.intel.kms.keplerlake.Policy;
import com.intel.kms.keplerlake.PolicyUri;
import com.intel.kms.keplerlake.etcd.EtcdUtils;
import com.intel.kms.keplerlake.faults.OauthAuthorizationFault;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.kms.ws.v2.api.KeyFilterCriteria;
import com.intel.kms.ws.v2.keplerlake.InputEntry;
import com.intel.kms.ws.v2.keplerlake.KeplerLakeCreateKeyResponse;
import com.intel.kms.ws.v2.keplerlake.KeplerLakeCreateKeysRequest;
import com.intel.kms.ws.v2.keplerlake.OutputEntry;
import com.intel.mtwilson.jaxrs2.provider.DateParamConverter;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.shiro.ShiroUtil;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStoreException;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 *
 * @author SSHEKHEX
 */
@V2
@Path("/rpc")
public class KeplerlakeKeys {

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeplerlakeKeys.class);
    final private ObjectMapper mapper;
    final private KeyRepository repository;
    public static final String CONTENT = "content";
    public static final String POLICY_URN = "urn:etcd:";
    KeplerlakeClient client = null;
    EtcdUtils etcdUtils = new EtcdUtils();
    KeplerLakeUtil keplerLakeUtil = null;
    OAuth2Client auth2Client=null;
    KeplerLakeRegistryDAO keplerLakeRegistryDAO = null;
    private static final Charset UTF8 = Charset.forName("UTF-8");

    public KeplerlakeKeys() throws Exception {
        repository = new KeyRepository();
        mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        keplerLakeUtil = new KeplerLakeUtil();
        keplerLakeRegistryDAO = keplerLakeUtil.getDaoInstance();
        client = new KeplerlakeClient(keplerLakeUtil.oAuthConfiguration());
        auth2Client=new OAuth2Client(keplerLakeUtil.oAuthConfiguration());

    }

    @Path("/keplerlake-create-keys")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @POST
    public KeplerLakeCreateKeyResponse createKeplerlakeKeys(KeplerLakeCreateKeysRequest request, @Context HttpServletRequest httpServletRequest) {
        log.debug("Key:Create - Got request to create a new keplerlake Key.");

        KeplerLakeCreateKeyResponse response = new KeplerLakeCreateKeyResponse();
        List<Key> outputKeys = new ArrayList<>();
        InputEntry input;
        String bearer;
        Policy consolidatedPolicy;
        String pId;
        Map<String, Object> user = new HashMap<>();
        Map<String, Object> map = new HashMap<>();
        String consolidatedPolicyUri;

        if (request == null) {
            log.error("Create Keplerlake Key request cannot be null.");
            KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
            errorResponse.getFaults().add(new Fault("Create Keplerlake Key request cannot be null."));
            return errorResponse;
        }

        if (request.getInput() == null || request.getInput().isEmpty()) {
            log.error("Create Keplerlake Key request input section cannot be null or empty.");
            KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
            errorResponse.getFaults().add(new Fault("Create Keplerlake Key request input section cannot be null or empty."));
            return errorResponse;
        }

        if (request.getOutput() == null || request.getOutput().isEmpty()) {
            log.error("Create Keplerlake Key request output section cannot be null or empty.");
            KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
            errorResponse.getFaults().add(new Fault("Create Keplerlake Key request output section cannot be null or empty."));
            return errorResponse;
        }

        try {
            bearer = httpServletRequest.getHeader("OAuth2-Authorization");
            log.debug("bearer header value {}", bearer);
            bearer = bearer.replace("Bearer", "").trim();
            log.debug("bearer value {}", bearer);
            if (bearer == null || bearer.isEmpty()) {
                log.error("Create Keplerlake Key request must have Authorization header.");
                KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
                errorResponse.getFaults().add(new Fault("Create Keplerlake Key request must have Authorization header."));
                return errorResponse;
            }
           /* map.clear();
            map.put("id", bearer);
            String oAuthResponse = client.getTarget().path("api/v1/jwt/token/{id}").resolveTemplates(map)
                    .request().accept(MediaType.APPLICATION_JSON).get(String.class);
            Map<String, String> oAuthResponseMap = mapper.readValue(oAuthResponse, Map.class);
            */
            Map<String, String> oAuthResponseMap = auth2Client.getVerifiedAttributes(bearer);
            log.debug("oauth api call with token {}", bearer);
            if (oAuthResponseMap == null || oAuthResponseMap.isEmpty() || oAuthResponseMap.containsKey("error")) {
                log.error("User not Authorized.");
                KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
                errorResponse.getFaults().add(new OauthAuthorizationFault("uri", new Fault("urn:intel:keplerlake:fault:oauth2-unauthorized")));
                errorResponse.getHttpResponse().setStatusCode(Response.Status.UNAUTHORIZED.getStatusCode());
                return errorResponse;
            }
        } catch (Exception e) {
            log.error("Error in oAuth authorization:{}", e);
            KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
            errorResponse.getFaults().add(new Fault("Error in oAuth authorization.", e));
            errorResponse.getHttpResponse().setStatusCode(Response.Status.UNAUTHORIZED.getStatusCode());
            return errorResponse;
        }
        try {
               request.setRealmName(keplerLakeUtil.realm);
                //If the request contains more than one input dataset,Need to merge the policy and create new policy.
                List<Policy> inputPolicies = new ArrayList<>();
                map.clear();
               String policyJson;
               String policyUri;
                Map<String,String> policyUriMap=new HashMap<>();
                for (InputEntry inputFile : request.getInput()) {
                    log.debug("input path: {}", inputFile.getPath());
                    //Get policy from etcd
                    KeyFilterCriteria criteria = new KeyFilterCriteria();
                    criteria.extensions = inputFile.getPath();
                    KeyCollection keys = repository.search(criteria);
                    policyUri = ((String) keys.getKeys().get(0).getExtensions().get("policy_uri")).replace("urn:etcd:", "");
                    log.debug("fetching policy {} for key {}", policyUri, keys.getKeys().get(0).getId().toString());
                    policyJson = etcdUtils.getKeplerLakeRegistryDAO().getString(policyUri.replace("urn:etcd:", ""));
                    if (policyJson != null && policyJson.length() > 1) {
                        log.debug("Mapping input policy into actual policy object");
                        Policy policy = mapper.readValue(policyJson, Policy.class);
                        String policyId = policy.getMeta().any().get("id").toString();
                        log.debug("inputDatasetPolicyId: {}", policyId);
                        policyUriMap.put(policyId, policyUri);

                        map.clear();
                        inputPolicies.add(policy);
                    }
                }
                request.setRealmName(keplerLakeUtil.realm);
                pId = new UUID().toString();
                consolidatedPolicy = mergePolicies(inputPolicies, pId, policyUriMap,request.getRealmName());
                map.clear();
                log.debug("Merged input policy and created new");
                keplerLakeRegistryDAO = keplerLakeUtil.getDaoInstance();
                String policyJsonString = mapper.writeValueAsString(consolidatedPolicy);
                log.debug("Merged policy:{}", policyJsonString);
                //Adding policy with signature in registry.
                String policyLocator = new PolicyLocator(request.getRealmName(), pId, CONTENT).toPath();
                log.debug("Registry key to store merged policy:{}", policyLocator);
                consolidatedPolicyUri = POLICY_URN + policyLocator;
                log.debug("consolidatedPolicyUri for merged policy:{}", consolidatedPolicyUri);
                try {

                    keplerLakeRegistryDAO.putPolicyWithSignature(pId, policyJsonString, keplerLakeUtil.getNotary());
                } catch (SignatureException ex) {
                    log.error("Unable to store consolidated policy :{}", ex);
                    KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
                    errorResponse.getFaults().add(new Fault("Unable to store consolidated policy."));
                    return errorResponse;
                }
                log.debug("Stored consolidated policy successfully with id {}", pId);

            //}

            // TODO.Store Policy and set perameters in response
        } catch (IOException | KeyStoreException e) {
            log.error("Error while merging policies", e);
            KeplerLakeCreateKeyResponse errorResponse = new KeplerLakeCreateKeyResponse();
            errorResponse.getFaults().add(new Fault("Error while merging policies: {}", e));
            return errorResponse;
        }

        // Creating keys for output datasets
        for (OutputEntry outputEntry : request.getOutput()) {
            try {

                CreateKeyRequest createKeyRequest = new CreateKeyRequest();
                createKeyRequest.set("descriptor_uri", request.getDescriptorUri());
                createKeyRequest.set("path", outputEntry.getPath());
                createKeyRequest.set("realm", request.getRealmName());
                if (consolidatedPolicyUri != null) {
                    log.debug("consolidatedPolicyUri {}", consolidatedPolicyUri);
                    createKeyRequest.set("policy_uri", consolidatedPolicyUri);
                }

                createKeyRequest.set("user", user);
                log.debug("createKeyRequest: {}", mapper.writeValueAsString(createKeyRequest));
                CreateKeyResponse createKeyResponse = repository.getKeyManager().createKey(createKeyRequest);
                log.debug("createKeyResponse: {}", mapper.writeValueAsString(createKeyResponse));
                if (!createKeyResponse.getFaults().isEmpty()) {
                    throw new ValidationException(createKeyResponse.getFaults());
                }
                if (createKeyResponse.getData().size() > 0) {
                    Key key = new Key();
                    copy(createKeyResponse.getData().get(0), key);
                    outputKeys.add(key);
                    log.debug("Key:KeplerLakeCreate - Created the Key {} successfully.", key.getId());
                    //Create a dataset entry for output dataset with associate key and the policy.
                    storeDatasetInfo(outputEntry.getPath(), consolidatedPolicyUri, key.getTransferLink().toURI().toString().replace("/transfer", ""), bearer);
                }
            } catch (Exception ex) {
                log.error("Exception occured in keplerlake key:{}", ex);
            }
        }
        // setting the response
        response.setData(outputKeys);
        return response;
    }

    private void copy(KeyAttributes from, Key to) {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setId(UUID.valueOf(from.getKeyId()));
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setTransferLink(from.getTransferLink());
        to.setUsername(from.getUsername());
        to.getExtensions().copyFrom(from);
    }

    /**
     * This method is used to merge the policy
     * @param policyList
     * @param pId
     * @param policyUriMap
     * @param realmName
     * @return
     */
    private Policy mergePolicies(List<Policy> policyList, String pId, Map<String,String> policyUriMap,String realmName) {

        Policy policy = new Policy();

        try {
           
            List<String> inputPolicyIdList = new ArrayList<>();
            List<String> notBeforeList = new ArrayList<>();
            preparePolicyForallOf(policyList, inputPolicyIdList, notBeforeList);
            log.debug("Merged policy preparation");
            Meta metaData = new Meta();
            Map<String, String> author=new HashMap<>();
            metaData.any().put("version", "1");
            metaData.any().put("id", pId);
            String realmURI = String.format("urn:etcd:/realm/%1$s/x509/subject/%2$s", realmName, ShiroUtil.subjectUsername());
            author.put("uri", realmURI);
            metaData.set("author", author);
            log.debug("merged policy author:{}",realmURI);
            Map<String, String> validity = new HashMap();
            if (notBeforeList.size() > 0) {
                log.debug("adding notBefore to merged policy");
                validity.put("notBefore", getLatestDateFromList(notBeforeList));
            }
            validity.put("notAfter", null);
            policy.setMeta(metaData);
            policy.setValidity(validity);
            List<PolicyUri> allOfList = new ArrayList<>();
            PolicyUri policyUri;
            for (String policyId : inputPolicyIdList) {
              log.debug("policyId in merge policy : {} and mapsize:{}", policyId, policyUriMap.size());
                if (policyUriMap.size() > 0 && policyUriMap.containsKey(policyId)) {
                    log.debug("get policy id from poilcyUri Map:{}", policyUriMap.get(policyId));
                    policyUri = new PolicyUri();
                    policyUri.setPolicyUri(policyUriMap.get(policyId));
                    allOfList.add(policyUri);
                }  
            }
            policy.setAllOf(allOfList);
            log.debug("AllOf section from merged policy : {}", mapper.writeValueAsString(policy.getAllOf()));

        } catch (IOException | ParseException ex) {
            log.error("Exception occur in mergePolicies:{}", ex);
        }
        return policy;
    }

    /**
     * This method used to identify the policies for merge policy.
     *
     * @param policyList
     * @param inputPolicyIdList
     * @param notBeforeList
     */
    private void preparePolicyForallOf(List<Policy> policyList, List<String> inputPolicyIdList, List<String> notBeforeList) {
        log.debug("preparePolicyForallOf method call");
        String inputPolicyId;
        try {
            log.debug("Input policies list size:{}", policyList.size());
            for (Policy inputPolicy : policyList) {
                log.debug("Populate input policy");
                if (inputPolicy.getMeta() != null && inputPolicy.getMeta().any().size() > 0) {
                    log.debug("Input policy contains meta section");
                    if (inputPolicy.getMeta().any().containsKey("id")) {
                        log.debug("Meta section contains id");
                        inputPolicyId = (String) inputPolicy.getMeta().any().get("id");
                        log.debug("Meta section policy Id:{}", inputPolicyId);
                        if (!inputPolicyIdList.contains(inputPolicyId)) {
                            log.debug("The policy {} not there in the list", inputPolicyId);
                            inputPolicyIdList.add(inputPolicyId);
                        }

                    }

                }
                log.debug("Check not before attribut in input policies");
                if (inputPolicy.getValidity() != null && inputPolicy.getValidity().size() > 0) {
                    log.debug("Policy validity size:{}", inputPolicy.getValidity().size());
                    if (inputPolicy.getValidity().containsKey("notBefore")) {
                        notBeforeList.add(inputPolicy.getValidity().get("notBefore"));
                    }
                }
            }
            log.debug("Input policies and notbefore list size:{}", inputPolicyIdList.size(), notBeforeList.size());
        } catch (Exception ex) {
            log.debug("Exception in preparePolicyForallOf call:{}", ex);
        }

    }

    /**
     *
     * @param notBeforeList
     * @return
     * @throws IOException
     * @throws ParseException
     */
    private String getLatestDateFromList(List<String> notBeforeList) throws IOException, ParseException {
        DateParamConverter dateParamConverter = new DateParamConverter();
        String latestDate = null;
        for (String notbefore : notBeforeList) {
            if (latestDate == null) {
                latestDate = notbefore;
            } else if (dateParamConverter.fromString(latestDate).before(dateParamConverter.fromString(notbefore))) {
                latestDate = notbefore;
            }
            log.debug("latestDate:{}", latestDate);
        }
        return latestDate;
    }

    /**
     *
     * @param datasetPath
     * @param policyUri
     * @param keyUri
     * @param oauth2BearerToken
     */
    private void storeDatasetInfo(String datasetPath, String policyUri, String keyUri, String oauth2BearerToken) {
        DatasetInfo datasetInfo = new DatasetInfo();
        try {
            datasetInfo.path = datasetPath;
            datasetInfo.date = keplerLakeUtil.getISOTimeZone();
            Map<String, DatasetInfo.Link> link = new HashMap();
            DatasetInfo.Link policyLink = new DatasetInfo.Link();
            DatasetInfo.Link keyLink = new DatasetInfo.Link();
            policyLink.uri = policyUri;
            keyLink.uri = keyUri;
            link.put("policy", policyLink);
            link.put("key", keyLink);
            datasetInfo.link = link;
            log.debug("datacenter realm:{}", keplerLakeUtil.realm);
            log.debug("keplerlake key dataset info:{}", mapper.writeValueAsString(datasetInfo));
            keplerLakeRegistryDAO = keplerLakeUtil.getDaoInstance();
            Service originalKmsService = keplerLakeRegistryDAO.getKMSService();
            String originalKmsTls = originalKmsService.map().get("tls.certificate.sha256");
            keplerLakeRegistryDAO = keplerLakeUtil.getDaoInstanceWithTagentClient();
            if (keplerLakeRegistryDAO != null) {
                log.debug("originalKmsTls in keplerlake:{}", originalKmsTls);
                keplerLakeRegistryDAO.putDatasetInfoWithHmac(datasetInfo, oauth2BearerToken, originalKmsTls);

            }
        } catch (IOException | SignatureException ex) {
            log.debug("Exception in storing datasetinfo for merge policy{}", ex);
        }

    }

}
