/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore.dhsm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyManagerHook;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterAsymmetricKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.kms.dhsm2.usage.policy.KeyUsagePolicy;
import com.intel.kms.dhsm2.usage.policy.ReadKeyUsagePolicyResponse;
import com.intel.kms.dhsm2.transfer.policy.KeyTransferPolicy;
import com.intel.kms.dhsm2.transfer.policy.ReadKeyTransferPolicyResponse;
import javax.ws.rs.core.Response;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.ArrayUtils;

/**
 * Implements specific validation needed for DHSM related CRUD APIs.
 * @author @shefalik 
 */
public class DhsmKeyManagerHook implements KeyManagerHook{

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DhsmKeyManagerHook.class);
    final private ObjectMapper mapper;
    final private Configuration configuration;

    public DhsmKeyManagerHook() throws IOException {
        mapper = JacksonObjectMapperProvider.createDefaultMapper();
        configuration = ConfigurationFactory.getConfiguration();
    }

    /**
     *
     * @Override
     * @param createKeyRequest
     * @return a list of faults with the request, or an empty list if the
     * request is valid
     */
    public List<Fault> beforeCreateKey(CreateKeyRequest createKeyRequest) {
        log.debug("in beforeCreateKey method");
        ArrayList<Fault> faults = new ArrayList<>();
        try {
                String keyTransferPolicy = createKeyRequest.getTransferPolicy();
                if (keyTransferPolicy == null || keyTransferPolicy.isEmpty()) {
                    log.debug("validation error in transfer policy");
                    faults.add(new MissingRequiredParameter("transfer_policy"));
                    return faults;
                } else {
                    KeyTransferPolicy transferPolicy = new KeyTransferPolicy();
                    Response response  = transferPolicy.readKeyTransferPolicy(keyTransferPolicy);
                    if (response.getStatus() != Response.Status.OK.getStatusCode()) {
                        log.debug("the Transfer policy ID is not prrsent in KMS");
                        ReadKeyTransferPolicyResponse policyResponse = 
                                                    (ReadKeyTransferPolicyResponse)(response.getEntity());
                        if (policyResponse.getFaults() != null) {
                            faults.addAll(policyResponse.getFaults());
                            return faults;
                        }
                    }
                }
                String keyUsagePolicy = createKeyRequest.getUsagePolicyID();
                log.debug("keyUsagePolicy: {}", keyUsagePolicy);
                if ((keyUsagePolicy != null) && (!keyUsagePolicy.isEmpty())) {
                     KeyUsagePolicy usagePolicy = new KeyUsagePolicy();
                     Response response  = usagePolicy.readKeyUsagePolicy(keyUsagePolicy);
		     if (response.getStatus() != Response.Status.OK.getStatusCode()) {
			 ReadKeyUsagePolicyResponse policyResponse = 
						     (ReadKeyUsagePolicyResponse)(response.getEntity());
			 if (policyResponse.getFaults() != null) {
			     faults.addAll(policyResponse.getFaults());
			     return faults;
			 }
                    }
                }
                String keyAlgorithm = createKeyRequest.getAlgorithm();
               log.debug("keyAlgorithm: {}", keyAlgorithm);
                
                if (keyAlgorithm == null || keyAlgorithm.isEmpty()) {
                    faults.add(new MissingRequiredParameter("algorithm"));
                    return faults;
                }
	        if (!CreateKeyRequest.allowedAlgorithms.contains(keyAlgorithm)) {
		    faults.add(new InvalidParameter("algorithm", 
						new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
		    return faults;
	        }
                
                if ((createKeyRequest.getKeyLength() == null) && (!keyAlgorithm.equalsIgnoreCase("EC"))) {
                   faults.add(new MissingRequiredParameter("keyLength"));
                   return faults;
                }
	        // check AES specific parameters
	        if (keyAlgorithm.equalsIgnoreCase("AES")) {
		    if (!ArrayUtils.contains(new int[]{128, 192, 256}, createKeyRequest.getKeyLength())) {
		        faults.add(new InvalidParameter("keyLength"));
		        return faults;
		    }
	        } else if (keyAlgorithm.equalsIgnoreCase("RSA")) {
                    if (!ArrayUtils.contains(new int[]{1024, 2048, 3072, 7680, 15360}, createKeyRequest.getKeyLength())) {
                        faults.add(new InvalidParameter("keyLength"));
                        return faults;
                    }
                } else if (keyAlgorithm.equalsIgnoreCase("EC")) {
                    String CurveType = createKeyRequest.getCurveType();
                    if ((CurveType == null) || (CurveType.isEmpty())) {
                        faults.add(new MissingRequiredParameter("curveType"));
                        return faults;
                    } else if (!CreateKeyRequest.allowedCurveTypes.contains(CurveType)) {
		        faults.add(new InvalidParameter("curve_type"));
                    }
               }
        } catch (Exception e) {
                log.error("Error while validating input parameters.", e);
                faults.add(new Fault("Error while validating input parameters."));
        }
        return faults;
    }

    public void afterCreateKey(CreateKeyRequest createKeyRequest,
                        CreateKeyResponse createKeyResponse) {
        log.debug("in afterCreateKey");
        
        if (!createKeyResponse.getFaults().isEmpty()) {
        createKeyResponse.setStatus("failure");
        } else {
            createKeyResponse.setStatus("success");
	    KeyAttributes created = createKeyResponse.getData().get(0);
	    if (created.map().containsKey("descriptor_uri")) {
		created.remove("descriptor_uri");
	    }
	    createKeyResponse.getExtensions().exclude("descriptor_uri");
        }
        createKeyResponse.setOperation("create key");
    }

    public List<Fault> beforeRegisterKey(RegisterKeyRequest registerKeyRequest) {
        log.debug("in beforeRegisterKey");
	ArrayList<Fault> faults = new ArrayList<>();
	try {
            String keyTransferPolicy = (String)(registerKeyRequest.getDescriptor().
                                                getContent().get("transferPolicy"));
	    if (keyTransferPolicy == null || keyTransferPolicy.isEmpty()) {
		log.debug("validation error in transfer policy");
		faults.add(new MissingRequiredParameter("transfer_policy"));
		return faults;
	    } else {
		KeyTransferPolicy transferPolicy = new KeyTransferPolicy();
		Response response  = transferPolicy.readKeyTransferPolicy(keyTransferPolicy);
		if (response.getStatus() != Response.Status.OK.getStatusCode()) {
		    log.debug("the Transfer policy ID is not prrsent in KMS");
		    ReadKeyTransferPolicyResponse policyResponse = 
						(ReadKeyTransferPolicyResponse)(response.getEntity());
		    if (policyResponse.getFaults() != null) {
			faults.addAll(policyResponse.getFaults());
			return faults;
		    }
		}
	    }
        } catch (Exception e) {
            log.error("Error while validating input parameters.", e);
            faults.add(new Fault("Error while validating input parameters."));
        }
        return faults;
    }

    public List<Fault> beforeRegisterKey(RegisterAsymmetricKeyRequest registerKeyRequest) {
	log.debug("in beforeRegisterKey for asymmetric keys");
	ArrayList<Fault> faults = new ArrayList<>();

        String privateKeyStr = registerKeyRequest.getPrivateKey();
        if ((privateKeyStr == null) || (privateKeyStr.isEmpty())) {
	    faults.add(new MissingRequiredParameter("transfer_policy"));
         }

	try {
	    String keyTransferPolicy = registerKeyRequest.getTransferPolicy();
            if (keyTransferPolicy == null || keyTransferPolicy.isEmpty()) {
		log.debug("validation error in transfer policy");
		faults.add(new MissingRequiredParameter("transfer_policy"));
		return faults;
	    } else {
		KeyTransferPolicy transferPolicy = new KeyTransferPolicy();
		Response response  = transferPolicy.readKeyTransferPolicy(keyTransferPolicy);
		if (response.getStatus() != Response.Status.OK.getStatusCode()) {
		    log.debug("the Transfer policy ID is not prrsent in KMS");
		    ReadKeyTransferPolicyResponse policyResponse = 
						(ReadKeyTransferPolicyResponse)(response.getEntity());
		    if (policyResponse.getFaults() != null) {
			faults.addAll(policyResponse.getFaults());
			return faults;
		    }
		}
	    }

	    String keyUsagePolicy = registerKeyRequest.getUsagePolicyID();
	    log.debug("keyUsagePolicy: {}", keyUsagePolicy);
	    if ((keyUsagePolicy != null) && (!keyUsagePolicy.isEmpty())) {
		 KeyUsagePolicy usagePolicy = new KeyUsagePolicy();
		 Response response  = usagePolicy.readKeyUsagePolicy(keyUsagePolicy);
		 if (response.getStatus() != Response.Status.OK.getStatusCode()) {
		     ReadKeyUsagePolicyResponse policyResponse = 
						 (ReadKeyUsagePolicyResponse)(response.getEntity());
		     if (policyResponse.getFaults() != null) {
			 faults.addAll(policyResponse.getFaults());
			 return faults;
		     }
		}
	    }

            String keyAlgorithm = registerKeyRequest.getAlgorithm();
	    log.debug("keyAlgorithm: {}", keyAlgorithm);
	    
	    if (keyAlgorithm == null || keyAlgorithm.isEmpty()) {
		faults.add(new MissingRequiredParameter("algorithm"));
		return faults;
	    }
	    if ((!keyAlgorithm.equalsIgnoreCase("EC")) && (!keyAlgorithm.equalsIgnoreCase("RSA"))) {
		faults.add(new InvalidParameter("algorithm", 
					    new UnsupportedAlgorithm(registerKeyRequest.getAlgorithm())));
		return faults;
	    }
	    if (keyAlgorithm.equalsIgnoreCase("EC")) {
		String CurveType = registerKeyRequest.getCurveType();
		if ((CurveType == null) || (CurveType.isEmpty())) {
		    faults.add(new MissingRequiredParameter("curveType"));
		    return faults;
		} else if (!registerKeyRequest.allowedCurveTypes.contains(CurveType)) {
		    faults.add(new InvalidParameter("curve_type"));
		}
	   }
	} catch (Exception e) {
	    log.error("Error while validating input parameters.", e);
	    faults.add(new Fault("Error while validating input parameters."));
	}
	return faults;
    }

    public void afterRegisterKey(RegisterKeyRequest registerKeyRequest,
			  RegisterKeyResponse registerKeyResponse) {
       log.debug("in afterRegisterKey"); 
    }

    public void afterRegisterKey(RegisterAsymmetricKeyRequest registerKeyRequest,
                          RegisterKeyResponse registerKeyResponse) {
       log.debug("in afterRegisterKey for asymmetric keys"); 

        if (!registerKeyResponse.getFaults().isEmpty()) {
        registerKeyResponse.setStatus("failure");
        } else {
            registerKeyResponse.setStatus("success");
        }
        registerKeyResponse.setOperation("register key");
    }

    public List<Fault> beforeDeleteKey(DeleteKeyRequest deleteKeyRequest) {
        log.debug("in beforeDeleteKey method");
        ArrayList<Fault> faults = new ArrayList<>();
        return faults;
    }

    public void afterDeleteKey(DeleteKeyRequest deleteKeyRequest,
                        DeleteKeyResponse deleteKeyResponse) {
        log.debug("in afterDeleteKey");
    }

    public List<Fault> beforeTransferKey(TransferKeyRequest transferKeyRequest) { 
        log.debug("In beforeTransferKey");
        ArrayList<Fault> faults = new ArrayList<>();
        try {
            String keyTransferPolicy = (String)transferKeyRequest.map().get("transfer_policy");
            if (keyTransferPolicy == null || keyTransferPolicy.isEmpty()) {
                log.debug("validation error in transfer policy");
                faults.add(new MissingRequiredParameter("transfer_policy"));
            } else {
	        log.debug("transfer_policy: {}", keyTransferPolicy);
	        KeyTransferPolicy transferPolicy = new KeyTransferPolicy();
	        Response response  = transferPolicy.readKeyTransferPolicy(keyTransferPolicy);
	        if (response.getStatus() != Response.Status.OK.getStatusCode()) {
		    log.debug("the Transfer policy ID is not prrsent in KMS");
		    ReadKeyTransferPolicyResponse policyResponse = 
					    (ReadKeyTransferPolicyResponse)(response.getEntity());
		    if (policyResponse.getFaults() != null) {
		        faults.addAll(policyResponse.getFaults());
		        return faults;
		    }
	        }
	    }
        ///TODO:Following APIs are yet to be developed and will be called here.
        ///Load the transfer Policy
        /// Check the  client attributes against the key transfer policy
        /// Check if the completed a remote attestation for the technology specified in the key transfer policy.
	} catch (Exception e) {
		log.error("Error while validating input parameters in beforeTransferKey", e);
		faults.add(new Fault("Error while validating input parameters."));
	}
	return faults;
    }

    public void afterTransferKey(TransferKeyRequest transferKeyRequest,
                          TransferKeyResponse transferKeyResponse) {
        log.debug("In afterTransferKey");
        ///Check if transferKeyResponse contains remote attestation challenge fault.
        ///If yes add HTTP headers to the response object with the remote attestation challenge.
    }

    public void afterGetKeyAttributes(GetKeyAttributesRequest getKeyAttributesRequest, 
                               GetKeyAttributesResponse getKeyAttributesResponse) {
        log.debug("In afterGetKeyAttributes");
        if (!getKeyAttributesResponse.getFaults().isEmpty()) {
            getKeyAttributesResponse.getData().setStatus("failure");
        } else {
            getKeyAttributesResponse.getData().setStatus("success");
        }
        getKeyAttributesResponse.getData().setOperation("read key");
    }

    public void afterSearchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest, 
                                  KeyAttributes searchKeyAttributesResponse) {
        log.debug("In afterSearchKeyAttributes");
        searchKeyAttributesResponse.setStatus("success");
        searchKeyAttributesResponse.setOperation("read all keys");
    }

    public String getDescriptorUri() {
        return ("urn:intel:dhsm2:crypto-schema:storage"); 
    }
}
