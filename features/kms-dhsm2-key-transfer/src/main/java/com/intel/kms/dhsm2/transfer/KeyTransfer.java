/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.key.transfer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.intel.dcsg.cpg.iso8601.Iso8601Date;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.AsymmetricKey;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.EcUtil;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import static com.intel.mtwilson.configuration.ConfigurationFactory.getConfiguration;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.NotFoundFault;
import com.intel.kms.api.fault.NotAuthorizedFault;
import com.intel.kms.api.fault.InvalidAttributesFault;
import com.intel.kms.repository.Repository;
import com.intel.kms.keystore.directory.JacksonFileRepository;
import com.intel.kms.dhsm2.common.CommonSession.TokenFetcher;
import com.intel.kms.dhsm2.transfer.policy.*;
import com.intel.kms.dhsm2.sessionManagement.SessionResponseMap;
import com.intel.kms.dhsm2.sessionManagement.QuoteVerifyResponseAttributes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.io.File;
import java.nio.charset.Charset;
import java.io.FileNotFoundException;
import java.lang.System;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URL;
import java.io.UnsupportedEncodingException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import com.intel.kms.dhsm2.common.CommonSession.KeyTransferSession;
import com.intel.kms.dhsm2.common.CommonSession.SessionMap;
import com.intel.mtwilson.jaxrs2.client.AASClient;
import java.util.Properties;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.TlsPolicyBuilder;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Arrays;

/**
 * KeyTransfer class is responsible for providing application key access to workload
 * It provides methods to Authenticate and Authorize workload and accordingly transfer
 * wrapped application key securely.
 *
 * @author rbhat
 */
@V2
@Path("/keys")
public class KeyTransfer {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyTransfer.class);

    final private ObjectMapper mapper;
    final protected Repository keyRepository;
    final protected FileRepository transferPolicyRepository;
    final private SessionMap sessionMap;
    final private SessionResponseMap sessionResMap;
    private String activeSessionId;
    private String activeStmLabel;
    private List<String> stmLabels = new ArrayList<String>();
    private List<String> contextList = new ArrayList<String>();
    private List<String> commonNames = new ArrayList<String>();
    private Map<String, String> sessionIdMap = new HashMap<String, String>();
    private String clientCertSHA;
    private KeyTransferPolicyAttributes keyTransferPolicyAttr;
    private static final String KEY_ID_REGEX = "^(permissions=)(.*)$";
	final private static String uuidRegex = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    public KeyTransfer() throws IOException {
        this(getKeyRepository());
    }

    public KeyTransfer(Repository keyRepository) throws IOException {
        this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
        // define custom naming strategy for this class json input
        // json inputs for key transfer are of the form where first letter is in capital
        // and there is a hyphen. for ex: Accept-Challenge. This convention is not
        // addressed by jackson property naming strategies
        this.mapper.setPropertyNamingStrategy(new CustomNamingStrategy());
        this.sessionMap = new SessionMap();
        this.sessionResMap = new SessionResponseMap();
        this.keyRepository = keyRepository;
        File transferPolicyDirectory = new File(Folders.repository("keys-transfer-policy"));
        this.transferPolicyRepository = new FileRepository(transferPolicyDirectory);
    }

    private static Repository getKeyRepository() throws FileNotFoundException {
        File keysDirectory = new File(Folders.repository("keys"));
        return new JacksonFileRepository(keysDirectory);
    }

    protected boolean isUUID(String s) {
        return s.matches(uuidRegex);
    }

    // validate if Session-ID is an array of the form [stmlabel:sessionID]
    protected boolean isValidStmSessionIdPair(String stmSessionStr) {
        boolean retVal = false;

        try {
            if (stmSessionStr.contains(":")) {
                String[] stmSessionIdPair = stmSessionStr.split(":");
                String stmLab = stmSessionIdPair[0].trim();
                String session = stmSessionIdPair[1].trim();
                String encSessionId = Base64.getEncoder().encodeToString(session.getBytes("utf-8"));

                // make sure session ID passed is of type uuid and stm label is set and non null
                if(isUUID(session) && stmLab.length() != 0) {
                    sessionIdMap.put(stmLab, encSessionId);
                    return true;
                }
            }
        } catch (IOException ex) {
            log.error("Exception during base64 encoding", ex.getMessage());
        }
        return retVal;
    }

    private String PrioratizeStms(List<String> stmLabels) {
	if(stmLabels.contains("SGX")) {
	    return "SGX";
	} else {
	    return "SW";
	}
    }

    /**
     * Method to validate Key Transfer input json request.
     * Accept-Chellenge is mandatory and Session-ID  field
     * will not be present for a new session
     */
    private List<Fault> validateKeyTransferRequest(String inputReq) {
        ArrayList<Fault> faults = new ArrayList<>();
        boolean retVal = false;

        try {
            JsonNode rootNode = mapper.readTree(inputReq);

            // read all Json Nodes in the input transfer application key json request
            JsonNode acceptChallenge = rootNode.path("Accept-Challenge");
            JsonNode sessionId = rootNode.path("Session-ID");
            // Accept-Challenge node is mandatory, specifying the list of supported technology modules
            if (acceptChallenge.isMissingNode()) {
                faults.add(new MissingRequiredParameter("Accept-Challenge node is missing in input"));
                return faults;
            }
            else {
                if (acceptChallenge.getNodeType() != JsonNodeType.ARRAY || acceptChallenge.size() == 0) {
                    faults.add(new InvalidParameter("Accept-Challenge cannot be empty"));
                    return faults;
                }
                else {
		    String stmLabel = "";
		    List<String> labels = new ArrayList<String>();
		    try {
			stmLabel = getConfiguration().get("dhsm2.challenge.type", "");
			
		    } catch(IOException ex) {
		    log.error("Exception while reading dhsm2.challenge.type {}", ex.getMessage());
		    }
		    if (stmLabel.contains(",")) {
			String[] stmLabels = stmLabel.split(",");
			for (String label : stmLabels) {
			    labels.add(label.trim());
			}
		    }
		    else {
			labels.add(stmLabel.trim());
		    }
                    for (final JsonNode objNode : acceptChallenge) {
                        String stmStr = objNode.textValue();
                        if(stmStr.contains(",")) {
                            String[] stmLab = stmStr.split(",");
                            for (String stm : stmLab) {
                                stmLabels.add(stm.trim());
                            }
                        }
                        else {
                            stmLabels.add(stmStr.trim());
                        }
                    }
		    // get a common set of stm modes supported by  workload and kms
		    stmLabels.retainAll(labels);

		    // no stm mode match between workload and kms
		    if(stmLabels.isEmpty()) {
			faults.add(new InvalidParameter("stm module requested by workload not supported by kms"));
		    }
                }
            }
            // Session-ID node is not mandatory. Validate if present
            if (!sessionId.isMissingNode()) {
                if (sessionId.getNodeType() != JsonNodeType.ARRAY || sessionId.size() == 0) {
                    faults.add(new InvalidParameter("Session-ID cannot be empty"));
                    return faults;
                }
                else {
                    // iterate through the list of session IDs to segregate session id and stm label
                    for (final JsonNode objNode : sessionId) {
                        String stmSessionStr = objNode.textValue();
                        if (stmSessionStr.contains(",")) {
                            String[] stmSessionList = stmSessionStr.split(",");
                            for (String stmSessionInstance : stmSessionList) {
                                retVal = isValidStmSessionIdPair(stmSessionInstance);
                                if (!retVal) {
                                    faults.add(new InvalidParameter("Session-ID should contain stm label and session id sepearated by ':' "));
                                    return faults;
                                }
                            }
                        }
                        else {
                            retVal = isValidStmSessionIdPair(stmSessionStr);
                            if (!retVal) {
                                faults.add(new InvalidParameter("Session-ID should contain stm label and session id sepearated by ':' "));
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            log.error("application key transfer json Request is not properly encoded");
        }
        return faults;
    }

    // GCMParameterSpec allows to specify the gcm authentication tag size
    // along with iv. hence prefer it over IvParameterSpec
    protected static GCMParameterSpec setAesGcmParam() {
        // for AES GCM mode, 12 byte IV is recommended for efficiency.
        final int IV_LENGTH = 12;
        // max supported authentication tag length for AES GCM is 128 bits
        final int AUTHENTICATION_TAG_BIT_LENGTH = 128;
        final byte[] iv = new byte[IV_LENGTH];
        final SecureRandom random = new SecureRandom();

        random.nextBytes(iv);
        return new GCMParameterSpec(AUTHENTICATION_TAG_BIT_LENGTH, iv);
    }

    /**
     * The Session is found to be active, hence fetch the application key corresonding to key id
     */
    protected KeyTransferAttributes fetchApplicationKey(String keyId) throws IOException {
        CipherKeyAttributes cipherKey = keyRepository.retrieve(keyId);
        if (cipherKey == null) {
            return null;
        }

        // get key attributes like algorithm and key length for corresponding key id
        KeyAttributes keyAttributes = new KeyAttributes();
        byte[] key;
        if (cipherKey instanceof CipherKey) {
            keyAttributes.copyFrom((CipherKey)cipherKey);
            key = ((CipherKey)cipherKey).getEncoded();
        } else {
            keyAttributes.copyFrom((AsymmetricKey)cipherKey);
            key = ((AsymmetricKey)cipherKey).getPrivateKey();
        }

        // get key transfer/usage policy id using key id
        String keyTransferPolicyId = keyAttributes.getTransferPolicy();
        String keyUsagePolicyId = keyAttributes.getUsagePolicyID();

        KeyTransferAttributes keyTransferAttributes = new KeyTransferAttributes(keyId);

        try {
            // retrieve the SWK key for the current active session from session map
            KeyTransferSession keyTransferSession = sessionMap.getObject(activeSessionId);
            byte[] swkKey = keyTransferSession.getSWK();

            // convert the raw byte array SWK to java secret key spec
            SecretKey swkKeySpec = new SecretKeySpec(swkKey, 0, swkKey.length, "AES");

            byte[] keyData = null;

            switch(activeStmLabel.toUpperCase()) {
                case "SW":
                    keyData = getKeyDataForSWMode(swkKey, key, keyAttributes.getAlgorithm());
                    break;
                case "SGX":
                    keyData = getKeyDataForSGXMode(swkKeySpec, key, keyAttributes.getAlgorithm());
                    break;
                default:
                    log.error("no active stm label found");
                    return null;
            }

            /** the wrappedAppKey bytearray now contains the wrapped app key+ 16 bytes of GCM Authentication
             *  tag appended after the wrapped key.
             */
            // base64 encode the app key payload before sending to workload
            keyTransferAttributes.setKeyData(Base64.getEncoder().encodeToString(keyData));
        }
        catch (Exception ex) {
            log.error("exception during application key wrapping. {}", ex.getMessage());
            return null;
        }
        keyTransferAttributes.setKeyAlgorithm(keyAttributes.getAlgorithm());
        keyTransferAttributes.setKeyLength(keyAttributes.getKeyLength());

        // generate json output tree as expected by workload
        JsonNode policyNode = mapper.createObjectNode();
        JsonNode linkNode = mapper.createObjectNode();
        JsonNode keyTransferPolicyNode = mapper.createObjectNode();
        JsonNode keyUsagePolicyNode = mapper.createObjectNode();

        String keyTransferPolicyUrl = String.format("%s/v1/key-transfer-policies/%s", createUrl(), keyTransferPolicyId);
        String keyUsagePolicyUrl = String.format("%s/v1/key-usage-policies/%s", createUrl(), keyUsagePolicyId);

        // populate key transfer/usage policy url details in output json to be sent to keyagent
        ((ObjectNode) keyTransferPolicyNode).put("href", keyTransferPolicyUrl);
        ((ObjectNode) keyTransferPolicyNode).put("method", "get");
        ((ObjectNode) linkNode).set("key-transfer", keyTransferPolicyNode);
        ((ObjectNode) keyUsagePolicyNode).put("href", keyUsagePolicyUrl);
        ((ObjectNode) keyUsagePolicyNode).put("method", "get");
        ((ObjectNode) linkNode).set("key-usage", keyUsagePolicyNode);
        ((ObjectNode) policyNode).set("link", linkNode);
        String policy = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(policyNode).trim();
        keyTransferAttributes.setPolicy(policy);

        Iso8601Date iso8601Date = new Iso8601Date(new Date());
        keyTransferAttributes.setCreatedAt(iso8601Date);

        return keyTransferAttributes;
    }

    protected boolean isSessionIdMapNullOrEmpty(final Map<String, String>map) {
        return map == null || map.isEmpty();
    }

    protected static List<Short> stringToShortList(String str) {
        List<Short> shortList = new ArrayList<Short>();

        if (str.length() == 0) {
            return shortList;
        }

	for (int index = 0; index < str.length(); index += 2){
    		shortList.add(Short.valueOf(str.substring(index, index+2)));
	}
        return shortList;
    }

    protected static String convertByteArrayToHexString(byte[] byteArray) {
	String hexString = null;
	try{
		hexString = new String(byteArray, "UTF-8");
	}catch(UnsupportedEncodingException e){
		log.error("Error in convertByteArrayToHexString: {}", e.getMessage());
		return null;
	}
	return hexString;
    }

    protected boolean validateSgxEnclaveIssuer(byte[] stmSgxEnclIssuer) {
        boolean retVal = false;

        if (stmSgxEnclIssuer.length == 0) {
            log.error("sgx_enclave_issuer missing from sgx attestation report");
            return retVal;
        }
        else {
            List<String> sgxEnclaveIssuer = keyTransferPolicyAttr.getSgxEnclaveIssuerAnyOf();
	    String stmSgxEnclaveIssuer = convertByteArrayToHexString(stmSgxEnclIssuer);

	    if (sgxEnclaveIssuer.contains(stmSgxEnclaveIssuer)) {
		log.debug("stm sgx_enclave_issuer matches with the key transfer policy");
		retVal = true;
 	    }
	    else {
		log.error("stm sgx_enclave_issuer does not match with the key transfer policy");
	    }
	}
        return retVal;
    }

    protected boolean validateSgxEnclaveIssuerProdId(List<Short> stmSgxEnclaveIssuerProdId) {
        boolean retVal = false;

        if (stmSgxEnclaveIssuerProdId.isEmpty()) {
            log.error("sgx_enclave_issuer_product_id missing from sgx attestation report");
            return retVal;
        }
        else {
            List<Short> sgxEnclaveIssuerProdId = keyTransferPolicyAttr.getSgxEnclaveIssuerProductIdAnyOf();
            for (Short stmSgxEnclProdId : stmSgxEnclaveIssuerProdId) {
                if (sgxEnclaveIssuerProdId.contains(stmSgxEnclProdId)) {
                    log.debug("stm sgx_enclave_issuer_product_id matches with the key transfer policy");
                    retVal = true;
                    return retVal;
                }
            }
            log.error("stm sgx_enclave_issuer_product_id does not match with the key transfer policy");
        }
        return retVal;
    }

    protected boolean validateSgxEnclaveIssuerExtProdId(byte[] stmSgxEnclIssuerExtProdId) {
        boolean retVal = false;

        List<String> sgxEnclaveIssuerExtProdId = keyTransferPolicyAttr.getSgxEnclaveIssuerExtendedProductIdAnyOf();
        if (stmSgxEnclIssuerExtProdId.length == 0 && sgxEnclaveIssuerExtProdId.isEmpty()) {
            retVal = true;
            return retVal;
        }
        else {
	    String stmSgxEnclaveIssuerExtProdId = convertByteArrayToHexString(stmSgxEnclIssuerExtProdId);
	    if (sgxEnclaveIssuerExtProdId.contains(stmSgxEnclaveIssuerExtProdId)) {
		log.debug("stm sgx_enclave_issuer_extended_product_id matches with the key transfer policy");
		retVal = true;
	    }
	    else {
		log.error("stm sgx_enclave_issuer_extended_product_id does not match with the key transfer policy");
	    }
        }
        return retVal;
    }

    protected boolean validateSgxEnclaveMeasurement(byte[] stmSgxEnclMeasurement) {
        boolean retVal = false;

        List<String> sgxEnclaveMeasurement = keyTransferPolicyAttr.getSgxEnclaveMeasurementAnyOf();
        if (stmSgxEnclMeasurement.length == 0 && sgxEnclaveMeasurement.isEmpty()) {
            retVal = true;
            return retVal;
        }
        else {
	    String stmSgxEnclaveMeasurement = convertByteArrayToHexString(stmSgxEnclMeasurement);
	    if (sgxEnclaveMeasurement.contains(stmSgxEnclaveMeasurement)) {
		log.debug("stm sgx_enclave_measurement matches with the key transfer policy");
		retVal = true;
                }
	    else {
		log.error("stm sgx_enclave_measurement does not match with the key transfer policy");
	    }
        }
        return retVal;
    }

    protected boolean validateSgxConfigId(byte[] stmSgxConfId) {
        boolean retVal = false;

        List<String> sgxConfigId = keyTransferPolicyAttr.getSgxConfigIdAnyOf();
        if (stmSgxConfId.length == 0 && sgxConfigId.isEmpty()) {
            retVal = true;
            return retVal;
        }
        else {
	    String stmSgxConfigId = convertByteArrayToHexString(stmSgxConfId);
	    if (sgxConfigId.contains(stmSgxConfigId)) {
		log.debug("stm sgx_config_id matches with the key transfer policy");
		retVal = true;
	    }
	    else {
		log.error("stm sgx_config_id does not match with the key transfer policy");
	    }
        }
        return retVal;
    }

    protected boolean SgxStmVerifyAttributes(String sessionId, ArrayList<Fault> faults) {
        boolean retVal = false;

        QuoteVerifyResponseAttributes stmAttr = sessionResMap.getAttrVal(sessionId);
	if(stmAttr == null) {
	    faults.add(new InvalidAttributesFault("not-found", "sgx attribute not found"));
	}

	byte[] stmSgxEnclaveIssuer = stmAttr.getEnclaveIssuer().getBytes(Charset.forName("UTF-8"));
	List<Short> stmSgxEnclaveIssuerProdId = stringToShortList(stmAttr.getEnclaveIssuerProdID());
	byte[] stmSgxEnclaveMeasurement = stmAttr.getEnclaveMeasurement().getBytes(Charset.forName("UTF-8"));
	byte[] stmSgxEnclaveIssuerExtProdId = stmAttr.getEnclaveIssuerExtProdID().getBytes(Charset.forName("UTF-8"));
	Short stmSgxConfigIdSvn =  stringToShortList(stmAttr.getConfigSvn()).get(0);
	Short stmSgxEnclaveSvnMinimum =  stringToShortList(stmAttr.getIsvSvn()).get(0);
	byte[] stmSgxConfigId = stmAttr.getConfigId().getBytes(Charset.forName("UTF-8"));

        boolean enforceTcbUptoDate = keyTransferPolicyAttr.getEnforceTcb();
	String tcbLevel = stmAttr.getTcbLevel();

	if (enforceTcbUptoDate && tcbLevel.equals("OutOfDate")) {
		faults.add(new InvalidAttributesFault("not-found", "Platform TCB Status is Out of Date"));
		return retVal; 
	}
        int sgxEnclaveSvnMinimum = keyTransferPolicyAttr.getSgxEnclaveSvnMinimum();
        int sgxConfigIdSvn = keyTransferPolicyAttr.getSgxConfigIdSvn();

        if (validateSgxEnclaveIssuer(stmSgxEnclaveIssuer) &&
                validateSgxEnclaveIssuerProdId(stmSgxEnclaveIssuerProdId) &&
                validateSgxEnclaveIssuerExtProdId(stmSgxEnclaveIssuerExtProdId) &&
                validateSgxEnclaveMeasurement(stmSgxEnclaveMeasurement) &&
                validateSgxConfigId(stmSgxConfigId) &&
                (sgxEnclaveSvnMinimum == stmSgxEnclaveSvnMinimum) &&
                (sgxConfigIdSvn == stmSgxConfigIdSvn)) {
            log.debug("all sgx attributes in stm attestation report match key transfer policy");
            retVal = true;
        }
	else {
	    faults.add(new InvalidAttributesFault("not-found", "sgx attribute validation failed"));
	}
        return retVal;
    }

    /**
     * checks if a session id is present in the transfer request header or in
     * the session map structure. else inform keyagent to initiate a new session
     */
    protected boolean isValidSession(ArrayList<Fault> faults) {
        boolean sessionFound = false;
        boolean retVal = false;
        String sessionId = "";

        if (isSessionIdMapNullOrEmpty(sessionIdMap)) {
            log.error("no existing sessions info found");
        }
        else {
            for (final Map.Entry<String, String> sessionInstance: sessionIdMap.entrySet()) {
                sessionId = sessionInstance.getValue();
                // check if the session is already present in the session map
                sessionFound = sessionMap.containsSession(sessionId);
                if (sessionFound) {
                    break;
                }
            }

            if (sessionFound) {
                KeyTransferSession keyTransferSession = sessionMap.getObject(sessionId);
                String certSHA = keyTransferSession.getClientCertHash();
                if (clientCertSHA.equals(certSHA)) {
                    if (activeStmLabel.equalsIgnoreCase("SGX")) {
                        retVal = SgxStmVerifyAttributes(sessionId, faults);
                        if (retVal) {
                            // found the current active seesion id. store it
                            activeSessionId = sessionId;
                            retVal = true;
                        } else {
				log.error("sgx stm values don't match with transfer policy");
				return true;
			}
		    }
                    else {
                        activeSessionId = sessionId;
                        retVal = true;
                    }
                }
                else {
                    log.error("workload cert SHA value for active session not matching with the one provided during new session");
                    return false;
                }
            }
        }
        return retVal;
    }

    protected String generateStmChallenge() {
        String encChallenge = "";

        try {
		String sessionId = new UUID().toString();
                log.debug("Session Id: {}", sessionId);
                encChallenge = Base64.getEncoder().encodeToString(sessionId.getBytes("utf-8"));
                // add session id to session object map for session api code to retrieve later
                KeyTransferSession keyTransferSession = new KeyTransferSession();
                // store the session id and client certificate SHA256 value for a new session
                // these will be used to validate the workload later when key transfer is
                // again requested for an active session
                keyTransferSession.setSessionId(encChallenge);
                keyTransferSession.setClientCertHash(clientCertSHA);
                keyTransferSession.setStmLabel(activeStmLabel);
                sessionMap.addSession(encChallenge, keyTransferSession);
        } catch (IOException ex) {
            log.error("Exception while base64 encoding challenge string {}", ex.getMessage());
        }
        return encChallenge;
    }

    /**
     * extract the hostname and KMS secure port details to be populated
     * and sent for keyagent to establish a session with keyserver
     */
    protected String createUrl() {
        String httpsPort = "";
        String hostName = "";

        try {
            InetAddress localhost = InetAddress.getLocalHost();
            hostName = localhost.getHostName().trim();
        } catch (UnknownHostException ex) {
            log.error("Exception while reading hostname info {}", ex.getMessage());
        }

        try {
            httpsPort = getConfiguration().get("jetty.secure.port", "");
        } catch(IOException ex) {
            log.error("Exception while reading jetty.secure.port {}", ex.getMessage());
        }
        String baseUrl = String.format("https://%s:%s", hostName, httpsPort);
        return baseUrl;
    }

    /**
     * no valid session found between keyagent and keyserver.
     * send 401 Unauthorized error to keyagent to initiate new session
     */
    protected ChallengeRequest buildChallengeJsonRequest() {
        ChallengeRequest challengeReq = new ChallengeRequest();
        ArrayList<Fault> faults = new ArrayList<>();

        faults.add(new NotAuthorizedFault("not-authorized"));
        challengeReq.setOperation("transfer key");
        challengeReq.setStatus("failure");
        challengeReq.getFaults().addAll(faults);
	challengeReq.setChallengeType(activeStmLabel);

        try {
            String sessionId = generateStmChallenge();
            if(sessionId != null && !sessionId.isEmpty()) {
                challengeReq.setChallenge(sessionId);

                JsonNode linkNode = mapper.createObjectNode();
                JsonNode challengeReplyToNode = mapper.createObjectNode();

                // keyagent should initiate a new session using href url and http post method
                String sessionUrl = String.format("%s/v1/session", createUrl());

                ((ObjectNode) challengeReplyToNode).put("href", sessionUrl);
                ((ObjectNode) challengeReplyToNode).put("method", "post");
                ((ObjectNode) linkNode).set("challenge-replyto", challengeReplyToNode);
                String link = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(linkNode).trim();
                challengeReq.setLink(link);
            }
            else {
                log.error("KMS stm failed to generate challenge");
                return null;
            }
        } catch (IOException ex) {
            log.error("Error while generating Challenege Request json {}", ex.getMessage());
            return null;
        }
        return challengeReq;
    }

	protected List<String> addContextToArray(String contextString) {
        String ContextArray[] = contextString.split(",");
	for (int i=0; i<ContextArray.length; i++) {
		ContextArray[i] = ContextArray[i].trim();
	}
        List<String> contextList = new ArrayList<String>();
        contextList = Arrays.asList(ContextArray);
        return contextList;
    }

    protected boolean isValidClient(String keyId) {
        boolean retVal = false;
        CipherKeyAttributes cipherKey = keyRepository.retrieve(keyId);

        if (cipherKey == null) {
            log.error("could not retrive key details (null returned) for the key id provided");
            return retVal;
        }

        try {
            // get key attributes like algorithm and key length for corresponding key id
            KeyAttributes keyAttributes = new KeyAttributes();
            if (cipherKey instanceof CipherKey) {
                keyAttributes.copyFrom((CipherKey)cipherKey);
            } else {
                keyAttributes.copyFrom((AsymmetricKey)cipherKey);
            }

            // get key transfer/usage policy id using key id
            String keyTransferPolicyId = keyAttributes.getTransferPolicy();
            String keyUsagePolicyId = keyAttributes.getUsagePolicyID();

            // read key transfer policy details
            KeyTransferPolicy transferPolicy = new KeyTransferPolicy();
            Response response  = transferPolicy.readKeyTransferPolicy(keyTransferPolicyId);
            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                ReadKeyTransferPolicyResponse policyResponse =
                    (ReadKeyTransferPolicyResponse)(response.getEntity());
                keyTransferPolicyAttr = (KeyTransferPolicyAttributes) policyResponse.getData().get(0);
            }
            else {
                log.error("could not read key transfer policy");
                return retVal;
            }
        } catch (IOException ex) {
            log.error("exception {}", ex.getMessage());
        }

        retVal = doesCertIssuerCNMatchKeyTransferPolicy();
        if (retVal) {
            retVal = doesAttestTypeMatchKeyTransferPolicy();
            if (retVal) {
                retVal = doesCertcontextListMatchKeyTransferPolicy();
            }
        }
        return retVal;
    }

    /** 
     * validate workload certificate issuer CN against key transfer policy 
     * tls_client_certificate_issuer_cn_anyof 
     */
    protected boolean doesCertIssuerCNMatchKeyTransferPolicy() {
        boolean retVal = false;

        if (commonNames.isEmpty()) {
            log.error("issuer common name is missing in workload certificate. required");
            return retVal;
        }

        List<String> clientCertIssuerCNAnyOf = keyTransferPolicyAttr.getTlsClientCertificateIssuerCNAnyOf();

        if (clientCertIssuerCNAnyOf.isEmpty()) {
            log.error("workload certificate contains issuer common_name, but missing in key transfer policy");
            return retVal;
        }
        else {
            for (String cn : commonNames) {
                if (clientCertIssuerCNAnyOf.contains(cn)) {
                    log.debug("issuer common_name in workload certificate matches with the key transfer policy");
                    return true;
                }
            }
        }
        log.error("issuer common_name in workload certificate does not match with key transfer policy");
        return retVal;
    }

    /** 
     * validate workload Context list retrieved from AAS DB against key transfer policy 
     * client_permissions_anyof/client_permissions_allof
     */
    protected boolean doesCertcontextListMatchKeyTransferPolicy() {
        boolean retVal = false;

        if (contextList.isEmpty()) {
            log.error("Context list in workload role is empty. required");
            return retVal;
        }

        List<String> clientCertContextAnyOf = keyTransferPolicyAttr.getTlsClientCertificateSanAnyOf();
        List<String> clientCertContextAllOf = keyTransferPolicyAttr.getTlsClientCertificateSanAllOf();

        if (!clientCertContextAnyOf.isEmpty()) {
            for (String context : contextList) {
                if (clientCertContextAnyOf.contains(context)) {
                    log.debug("context list in workload certificate matches with the key transfer policy");
                    return true;
                }
            }
        }
        else if (!clientCertContextAllOf.isEmpty()) {
            if (contextList.containsAll(clientCertContextAllOf)) {
                log.debug("Context list in workload role matches that of key transfer policy");
                return true;
            }
            else {
                log.error("Context list in workload role does not match that of key transfer policy");
            }
        }
        else {
            log.error("workload role contains Context info, but missing in key transfer policy");
        }
        return retVal;
    }

    /** 
     * validate transfer request Accept-Challenge against
     * key transfer policy attestation_type_anyof
     */
    protected boolean doesAttestTypeMatchKeyTransferPolicy() {
        boolean retVal = false;
        List<String> attestType = keyTransferPolicyAttr.getAttestationTypeAnyOf();

        if (attestType.isEmpty()) {
            log.error("transfer key request contains accept-challenge, but attestationType missing in key transfer policy");
            return retVal;
        }
        else {
	    if (stmLabels.size() > 1) {
		stmLabels.retainAll(attestType);
		if(stmLabels.size() == 0) {
		    log.error("stm label in request does not match with key transfer policy");
		}
		else {
		    log.debug("stm label (attestation type) matches with the key transfer policy");
		    activeStmLabel = PrioratizeStms(stmLabels);
		    retVal = true;
		}
	    }
	    else {
                if (attestType.containsAll(stmLabels)) {
		    log.debug("stm label (attestation type) matches with the key transfer policy");
		    activeStmLabel = stmLabels.get(0);
		    retVal = true;
		}
		else {
		    log.error("stm label in request does not match with key transfer policy");
		}
	    }
        }
        return retVal;
    }

    @Path("/{id: [0-9a-zA-Z-]+}/dhsm2-transfer")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:transfer")
    public Response TransferApplicationKey(@PathParam("id") String keyId, 
            @Context HttpServletRequest request, @Context HttpHeaders httpHeader) {

		log.debug("workload requested  for transfer of application key");
		ArrayList<Fault> faults = new ArrayList<>();
		KeyTransferAttributes keyTransferAttributes = new KeyTransferAttributes();
		KeyTransferResponse response = new KeyTransferResponse();
		boolean retVal = false;

		if (keyId == null || keyId.length() == 0 || !isUUID(keyId)) {
			log.error("invalid key id specified");
			faults.add(new NotFoundFault("not-found", keyId));
			response.setOperation("transfer key");
			response.setStatus("failure");
			response.getFaults().addAll(faults);
			//propagate back fault description along with NOT_FOUND HTTP status code
			return Response.status(Response.Status.NOT_FOUND).entity(response).build();
		}

		try {
			//extract the http headers and pass it for validation
			String inputReq = mapper.writeValueAsString(httpHeader.getRequestHeaders());
			faults.addAll(validateKeyTransferRequest(inputReq));

			// input validation failed. post error json output 
			if (!faults.isEmpty()) {
				faults.add(new NotFoundFault("not-found", keyId));
				response.setOperation("transfer key");
				response.setStatus("failure");
				response.getFaults().addAll(faults);
				// propagate back fault description along with NOT_FOUND HTTP status code
				return Response.status(Response.Status.NOT_FOUND).entity(response).build();
			}

			// extract the client certificate from certificate chain in request header
			X509Certificate[] clientCertChain = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
			X509Certificate clientCert = clientCertChain[0];

			// extract the CN(common name) info from client certificate
			X500Name x500name = new JcaX509CertificateHolder(clientCert).getIssuer();
			RDN[] commonNameList = x500name.getRDNs(BCStyle.CN);
			if (0 != commonNameList.length) {
				for (int i = 0; i != commonNameList.length; i++) {
					commonNames.add(IETFUtils.valueToString(commonNameList[i].getFirst().getValue()));
				}
			} else {
				log.error("common_name attribute missing from workload certificate issuer string");
			}
			///Get the roles from AAS for this CN. Verify if any of the roles has keyTransfer.
			TlsPolicy tlsPolicy = TlsPolicyBuilder.factory().strictWithKeystore(TokenFetcher.getTrustStorePath(), "changeit").build();
			x500name = new JcaX509CertificateHolder(clientCert).getSubject();
			RDN cn = x500name.getRDNs(BCStyle.CN)[0];
			String common_name = IETFUtils.valueToString(cn.getFirst().getValue());
			if (!TokenFetcher.setPropertyForFetchingAASAttributes()) {
				log.error("configuration needed");
				faults.add(new NotFoundFault("aas configurations not-found", "configuration"));
				response.setOperation("transfer key");
				response.setStatus("failure");
				response.getFaults().addAll(faults);
				//propagate back fault description along with NOT_FOUND HTTP status code
				return Response.status(Response.Status.NOT_FOUND).entity(response).build();
			}

			String url = TokenFetcher.properties.getProperty("aas.api.url");
			AASClient aasClient = new AASClient(TokenFetcher.properties, new TlsConnection(new URL(url), tlsPolicy));
			log.debug("fetch the userid and roles for user: {}", common_name);
			Response aasResponse = aasClient.getUserID(common_name);
			String id = "";
			String jsonString = "";
			if ((aasResponse.getStatus() == 200) && (aasResponse.hasEntity())) {
				jsonString = aasResponse.readEntity(String.class);
				JSONArray jsonarray = new JSONArray(jsonString);
				for (int i = 0; i < jsonarray.length(); i++) {
					JSONObject jsonobject = jsonarray.getJSONObject(i);
					id = jsonobject.getString("user_id");
				}
			} else if (aasResponse.getStatus() == 401) {
					if (!TokenFetcher.updateToken()) {
						int status = aasResponse.getStatusInfo().getStatusCode();
						String reasonforFailure = aasResponse.getStatusInfo().getReasonPhrase();
						log.error("AAS returned the response code: {}", status);
						log.error("Transfer failed: {}", reasonforFailure);
						return (setErrorMesage(response, faults));
					}
					aasClient = new AASClient(TokenFetcher.properties, new TlsConnection(new URL(url), tlsPolicy));
					aasResponse = aasClient.getUserID(common_name);
					if ((aasResponse.getStatus() == 200) && (aasResponse.hasEntity())) {
						jsonString = aasResponse.readEntity(String.class);
						JSONArray jsonarray = new JSONArray(jsonString);
						for (int i = 0; i < jsonarray.length(); i++) {
							JSONObject jsonobject = jsonarray.getJSONObject(i);
							id = jsonobject.getString("user_id");
						}
					} else {
						int status = aasResponse.getStatusInfo().getStatusCode();
						String reasonforFailure = aasResponse.getStatusInfo().getReasonPhrase();
						log.error("AAS returned the response code: {}", status);
						log.error("Transfer failed: {}", reasonforFailure);
						return setErrorMesage(response, faults);
					}
			}
			else {
					return setErrorMesage(response, faults);
			}

			aasResponse = aasClient.getRoles(id);
			if ((aasResponse.getStatus() == 200) && (aasResponse.hasEntity())) {
				jsonString = aasResponse.readEntity(String.class);
			} else {
				log.error("workload is not authorised for application key transfer");
				return setErrorMesage(response, faults);
			}
			///Check if the role_name has keyTrasnfer role in it.
			JSONArray jsonarray = new JSONArray(jsonString);
			boolean retValue = false;
			for (int i = 0; i < jsonarray.length(); i++) {
				JSONObject jsonobject = jsonarray.getJSONObject(i);
				String name = jsonobject.getString("name");
				String service = jsonobject.getString("service");
				String context = jsonobject.getString("context");
				log.debug("context: {}", context);
				if (name.equals("KeyTransfer") && service.equals("KMS")) {
					Matcher m = Pattern.compile(KEY_ID_REGEX).matcher(context);
					if (m.matches()) {
						String listOfContexts = m.group(2);
						log.debug("listOfContexts: {}", listOfContexts);
						contextList = addContextToArray(listOfContexts);
						retValue = true;
					}
					else {
						log.error("keyTransfer role is not created as expected");
                                                retValue = false;
                                        }
					break;
				}
			}
			if (!retValue) {
				log.error("workload is not authorised for application key transfer");
				return setErrorMesage(response, faults);
			}

                clientCertSHA = DigestUtils.sha256Hex(clientCert.getEncoded());

                /**
                 * validate the workload certificate as follows
                 * 1. check if the certificate issuer common name against the key transfer policy
                 * 2. check if the certificate SAN attributes against the key transfer policy
                 * 3. check if the STM label in the transfer request matches the key transfer policy
                 */
                retVal = isValidClient(keyId);
                if (retVal) {
                    /** check if session initiated by workload is active by searching session map
                     *  for existing session id. Also the workload certificate SHA256 value is
                     * checked against the SHA256 value stored in the session map
                     */
                    retVal = isValidSession(faults);
                    if (retVal) {
                        log.debug("session is validated and active");
			// Session is active but we need to check if there was any fault while
			// verifying sgx atttributes
			if (!faults.isEmpty()) {
			    log.error("sgx attributes verification failed");
			    response.setOperation("transfer key");
			    response.setStatus("failure");
			    response.getFaults().addAll(faults);
			    return Response.status(Response.Status.NOT_FOUND).entity(response).build();
			}
                        // we found an active session and workload certifcate is already validated.
                        // proceed to fetch the application key.
                        keyTransferAttributes = fetchApplicationKey(keyId);
                        if (keyTransferAttributes != null) {
                            KeyTransferResponse keyResponse = new KeyTransferResponse(keyTransferAttributes);
                            keyResponse.setOperation("transfer key");
                            keyResponse.setStatus("success");
                            String sessionId = new String(Base64.getDecoder().decode(activeSessionId));
                            String sessionIdStr = String.format("%s:%s", activeStmLabel, sessionId);
                            return Response.status(Response.Status.OK).header("Session-ID", sessionIdStr).entity(keyResponse).build();
                        }
                        else {
                            log.error("key id is not found");
                            faults.add(new NotFoundFault("not-found", keyId));
                            response.setOperation("transfer key");
                            response.setStatus("failure");
                            response.getFaults().addAll(faults);
                            return Response.status(Response.Status.NOT_FOUND).entity(response).build();
                        }
                    }
		    else {
                        /** no existing session found (new session flow)
                         *  send 401 UNAUTHORIZED error to workload along with challenge
                         *  workload should initiate a new session with challenge provided
                         */
                        ChallengeRequest req = buildChallengeJsonRequest();
                        if (req != null) {
                            return Response.status(Response.Status.UNAUTHORIZED).entity(req).build();
                        }
                        else {
                            log.error("could not build challenge request");
                            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
                        }
                    }
                }
                else {
                    // workload certificate validation failed. deny application key request
                    log.error("workload is not authorised for application key transfer");
                    response.setOperation("transfer key");
                    response.setStatus("failure");
                    faults.add(new NotAuthorizedFault("not-authorized"));
                    response.getFaults().addAll(faults);
                    return Response.status(Response.Status.FORBIDDEN).entity(response).build();
                }
            } catch(Exception ex) {
                log.error("Exception while transferring application key", ex);
                response.setOperation("transfer key");
                response.setStatus("failure");
                response.getFaults().add(new Fault(ex.getCause(), "received exception during key transfer"));
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
            }
	}

	private Response setErrorMesage(KeyTransferResponse response, ArrayList<Fault> faults) {
			response.setOperation("transfer key");
			response.setStatus("failure");
			faults.add(new NotAuthorizedFault("not-authorized"));
			response.getFaults().addAll(faults);
			return Response.status(Response.Status.FORBIDDEN).entity(response).build();

	}

public byte[] getKeyDataForSGXMode(SecretKey swkKeySpec, byte[] key, String algorithm) {

        byte[] keyData = null;
        try {
            /**
             * Bouncycastle crypto apis are used as AES GCM mode does not work with JCE
             */
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

            // set an IV Buffer of size 12 bytes and set GCM authentication tag size to 16 bytes
            final GCMParameterSpec gcmParam = setAesGcmParam();
            final int ivLength = gcmParam.getIV().length;

            cipher.init(Cipher.WRAP_MODE, swkKeySpec, gcmParam);

            // get the raw application key byte array and convert it to java secret key format
            // wrap the application key with the SWK
            byte[] wrappedAppKey;
            if (algorithm.equalsIgnoreCase("AES")) {
                SecretKey sKeySpec = new SecretKeySpec(key, 0, key.length, algorithm);
                wrappedAppKey = cipher.wrap(sKeySpec);
            } else {
                PrivateKey privateKey;
                if (algorithm.equalsIgnoreCase("RSA")) {
                    privateKey = RsaUtil.decodeDerPrivateKey(key);
                } else {
                    privateKey = EcUtil.decodeDerPrivateKey(key);
                }
                wrappedAppKey = cipher.wrap(privateKey);
            }

            /**
             * construct a bytearray structure of the form
             * {
             *	    int iv_length (initialization vector length in bytes)
             *	    int tag_size (gcm authentication tag size in bytes)
             *	    int wrap_size (wrapped application key length in Bytes)
             *	    byte[] iv (iv bytearray)
             *	    byte[] wrappedAppkey (Wrapped Application Key, contains wrapped key + 16 bytes of gcm authentication tag)
             *	}
             * Convert the int values to byte array using bytebuffer class
             * and combine this byte array with IV and app key array using arraycopy
             */
            final int ivSize = 4;
            final int tagSize = 4;
            final int wrapSize = 4;
            final int keyMetaDataSize = ivSize + tagSize + wrapSize;
            byte[] keyMetaData = new byte[keyMetaDataSize];

            ByteBuffer b = ByteBuffer.allocate(keyMetaDataSize);
            b.order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(ivLength);
            b.putInt(gcmParam.getTLen()/8); // gcm authentication tag length returned is in bits.
            b.putInt(wrappedAppKey.length);  // Wrapped App Key length
            keyMetaData = b.array();

            keyData = new byte[keyMetaDataSize + ivLength + wrappedAppKey.length];
            System.arraycopy(keyMetaData, 0, keyData, 0, keyMetaDataSize);
            System.arraycopy(gcmParam.getIV(), 0, keyData, keyMetaDataSize, ivLength);
            System.arraycopy(wrappedAppKey, 0, keyData, keyMetaDataSize + ivLength, wrappedAppKey.length);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException | CryptographyException ex) {
            log.error("exception during application key wrapping. {}", ex.getMessage());
            return null;
        }
        return keyData;
    }

    public byte[] getKeyDataForSWMode(byte[] kek, byte[] key, String algorithm) {

        byte[] wrappedAppKey;
        KeyParameter keyParam = new KeyParameter(kek);
        AESWrapEngine engine = new AESWrapEngine();
        engine.init(true, keyParam);
        int alignement = (key.length)%8;
        if (alignement != 0) {
            ZeroBytePadding padding = new ZeroBytePadding();
            byte[] paddedArr = new byte[key.length + (8 - key.length % 8)];
            System.arraycopy(key, 0, paddedArr, 0, key.length);
            padding.addPadding(paddedArr, key.length);
            wrappedAppKey = engine.wrap(paddedArr, 0, paddedArr.length);
        } else {
            wrappedAppKey = engine.wrap(key, 0, key.length);
        }

        /**
         * construct a bytearray structure of the form
         * {
         *	    int iv_length (initialization vector length in bytes)
         *	    int tag_size (gcm authentication tag size in bytes)
         *	    int wrap_size (wrapped application key length in Bytes)
         *	    byte[] iv (iv bytearray)
         *	    byte[] wrappedAppkey (Wrapped Application Key)
         *	}
         * Convert the int values to byte array using bytebuffer class
         * and combine this byte array with IV and app key array using arraycopy
         */
        final int ivSize = 4;
        final int tagSize = 4;
        final int wrapSize = 4;
        final int ivLength = 0;
        final int tagLength = 0;
        final int keyMetaDataSize = ivSize + tagSize + wrapSize;
        byte[] keyMetaData = new byte[keyMetaDataSize];

        ByteBuffer b = ByteBuffer.allocate(keyMetaDataSize);
        b.order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(ivLength); ///for SW mode it will be 0
        b.putInt(tagLength); // for SW mode it will be 0
        b.putInt(wrappedAppKey.length);  // Wrapped App Key length
        keyMetaData = b.array();

        byte[] keyData = new byte[keyMetaDataSize + ivLength + wrappedAppKey.length];
        System.arraycopy(keyMetaData, 0, keyData, 0, keyMetaDataSize);
        System.arraycopy(wrappedAppKey, 0, keyData, keyMetaDataSize + ivLength, wrappedAppKey.length);

        return keyData;
    }
}
