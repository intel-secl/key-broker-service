/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.dcsg.cpg.validation.Fault;
import java.util.ArrayList;
import java.io.IOException;

/**
 * Brief: This is a custom deserializer that parses incoming JSON for Transfer Policy for SKC
 * It is written so as not to change behaviour of common Java. The default Deserializer is not covering 
 * validations for arrays. Hence a custom one is written here.
 * @author skamal 
 */
public class CustomJsonDeserializerForKeyTransferPolicy extends JsonDeserializer<CreateKeyTransferPolicyRequest> {
	final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CustomJsonDeserializerForKeyTransferPolicy.class);
	final private ObjectMapper mapper;

	public CustomJsonDeserializerForKeyTransferPolicy() throws IOException {
		this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
	}

	/**
	 * Brief: This is a customized deserializer.This deserializes the incoming JSON request 
	 * It validates the request and accordingly create the object.
	 * Output: CreateKeyTransferPolicyRequest object containing the request parameters to be used.
	 */
	@Override
	public CreateKeyTransferPolicyRequest deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		log.debug("in CustomJsonDeserializerForKeyTransferPolicy");
		ArrayList<Fault> faults = new ArrayList<>();
		CreateKeyTransferPolicyRequest ktpRequest = new CreateKeyTransferPolicyRequest();
		try {
			JsonNode rootNode = mapper.readTree(jp);
			// read all Json Nodes in the input create policy JSON request
			JsonNode sgxEnclaveIssuer = rootNode.path("sgx_enclave_issuer_anyof");
			JsonNode sgxEnclaveIssuerProductId = rootNode.path("sgx_enclave_issuer_product_id_anyof");
			JsonNode sgxEnclaveIssuerExtendedProductId = rootNode.path("sgx_enclave_issuer_extended_product_id_anyof");
			JsonNode sgxEnclaveMeasurement = rootNode.path("sgx_enclave_measurement_anyof");
			JsonNode sgxConfigIdSvn = rootNode.path("sgx_config_id_svn");
			JsonNode sgxEnclaveSvnMinimum = rootNode.path("sgx_enclave_svn_minimum");
			JsonNode kpt2Issuer = rootNode.path("kpt2_issuer_anyof");
			JsonNode sgxConfigId = rootNode.path("sgx_config_id_anyof");
			JsonNode tlsClientCertificateIssuerCN = rootNode.path("tls_client_certificate_issuer_cn_anyof");
			JsonNode tlsClientCertificateSan = rootNode.path("client_permissions_anyof");
			JsonNode tlsClientCertificateSanAll = rootNode.path("client_permissions_allof");
			JsonNode attestationType = rootNode.path("attestation_type_anyof");
			JsonNode enforceTcbUptoDate = rootNode.path("sgx_enforce_tcb_up_to_date");

			// Either sgxEnclaveIssuer or sgxEnclaveIssuerProductId json nodes are mandatory in input request
			if (sgxEnclaveIssuer.isMissingNode() && sgxEnclaveIssuerProductId.isMissingNode()) {
				faults.add(new MissingRequiredParameter("sgx_enclave_issuer_anyof and sgx_enclave_issuer_product_id_anyof both are missing"));
			}
			if (!KeyTransferPolicyValidation.isValidArrayOfHexStrings(sgxEnclaveIssuer)) {
				faults.add(new InvalidParameter("sgx_enclave_issuer_anyof not a valid array"));
			} else {
				ArrayList<String> sgxEnclIssuer = KeyTransferPolicyValidation.getStringList(sgxEnclaveIssuer);
				ktpRequest.setSgxEnclaveIssuerAnyOf(sgxEnclIssuer);
			}
			if (!KeyTransferPolicyValidation.isValidShortArray(sgxEnclaveIssuerProductId)) {
				faults.add(new InvalidParameter("sgx_enclave_issuer_product_id_anyof not a valid array"));
			} else {
				ArrayList<Short> sgxEnclIssuerProdId = KeyTransferPolicyValidation.getShortIntList(sgxEnclaveIssuerProductId);
				ktpRequest.setSgxEnclaveIssuerProductIdAnyOf(sgxEnclIssuerProdId);
			}
			// following nodes are not mandatory. Validate if present
			if (!KeyTransferPolicyValidation.isValidArrayOfHexStrings(sgxEnclaveIssuerExtendedProductId)) {
				log.debug("in faults");
				faults.add(new InvalidParameter("sgx_enclave_issuer_extended_product_id_anyof not a valid array"));
			} else {
				ArrayList<String> extProdId = KeyTransferPolicyValidation.getStringList(sgxEnclaveIssuerExtendedProductId);
				ktpRequest.setSgxEnclaveIssuerExtendedProductIdAnyOf(extProdId);
			}
			if (!KeyTransferPolicyValidation.isValidArrayOfHexStrings(sgxEnclaveMeasurement)) {
				faults.add(new InvalidParameter("sgx_enclave_measurement_anyof not a valid array"));
			} else {
				ArrayList<String> sgxEnclMeasure = KeyTransferPolicyValidation.getStringList(sgxEnclaveMeasurement);
				ktpRequest.setSgxEnclaveMeasurementAnyOf(sgxEnclMeasure);
			}
			if (!sgxEnclaveSvnMinimum.isMissingNode()) {
				if (sgxEnclaveSvnMinimum.getNodeType() != JsonNodeType.NUMBER) {
					faults.add(new InvalidParameter("sgx_enclave_svn_minimum not a number"));
				} else {
					Short sgxEncSvnMin  = sgxEnclaveSvnMinimum.shortValue();
					ktpRequest.setSgxEnclaveSvnMinimum(sgxEncSvnMin);
				}
			}
			if (!KeyTransferPolicyValidation.isValidArrayOfHexStrings(sgxConfigId)) {
				faults.add(new InvalidParameter("sgx_config_id_anyof not a valid array"));
			} else {
				ArrayList<String> sgxConfId = KeyTransferPolicyValidation.getStringList(sgxConfigId);
				ktpRequest.setSgxConfigIdAnyOf(sgxConfId);
			}
			if (!sgxConfigIdSvn.isMissingNode()) {
				if (sgxConfigIdSvn.getNodeType() != JsonNodeType.NUMBER) {
					faults.add(new InvalidParameter("sgx_config_id_svn not a number"));
				} else {
					Short sgxConfIdSvn  = sgxConfigIdSvn.shortValue();
					ktpRequest.setSgxConfigIdSvn(sgxConfIdSvn);
				}
			}
			if (!KeyTransferPolicyValidation.isValidAlphaNumStringArray(kpt2Issuer)) {
				faults.add(new InvalidParameter("kpt2_issuer_anyof not a valid array"));
			} else {
				ArrayList<String> kptIssuer = KeyTransferPolicyValidation.getStringList(kpt2Issuer);
				ktpRequest.setKpt2IssuerAnyOf(kptIssuer);
			}
			if (!KeyTransferPolicyValidation.isValidAlphaNumStringArray(tlsClientCertificateIssuerCN)) {
				faults.add(new InvalidParameter("tls_client_certificate_issuer_cn_anyof not a valid array"));
			} else {
				ArrayList<String> tlsclCertIssuer = KeyTransferPolicyValidation.getStringList(tlsClientCertificateIssuerCN);
				ktpRequest.setTlsClientCertificateIssuerCNAnyOf(tlsclCertIssuer);
			}

			if (!KeyTransferPolicyValidation.isValidAlphaNumStringArray(tlsClientCertificateSan)) {
				faults.add(new InvalidParameter("client_permissions_anyof not a valid array"));
			} else {
				ArrayList<String> tlsclCertSan = KeyTransferPolicyValidation.getStringList(tlsClientCertificateSan);
				ktpRequest.setTlsClientCertificateSanAnyOf(tlsclCertSan);
			}
			if (!KeyTransferPolicyValidation.isValidArrayOfCanonicalName(tlsClientCertificateSanAll)) {
				faults.add(new InvalidParameter("client_permissions_allof not a valid array"));
			} else {
				ArrayList<String> tlsclCertSanAll = KeyTransferPolicyValidation.getStringList(tlsClientCertificateSanAll);
				ktpRequest.setTlsClientCertificateSanAllOf(tlsclCertSanAll);
			}
			if (!KeyTransferPolicyValidation.isValidAlphaNumStringArray(attestationType)) {
				faults.add(new InvalidParameter("attestation_type_anyof not a valid array"));
			} else {
				ArrayList<String> attType = KeyTransferPolicyValidation.getStringList(attestationType);
				ktpRequest.setAttestationTypeAnyOf(attType);
			}
			if (!enforceTcbUptoDate.isMissingNode()) {
				if (enforceTcbUptoDate.getNodeType() != JsonNodeType.BOOLEAN) {
					faults.add(new InvalidParameter("sgx_enforce_tcb_up_to_date not a boolean"));
				} else {
					boolean enforceTcb = enforceTcbUptoDate.booleanValue();
					ktpRequest.setEnforceTcb(enforceTcb);
				}
			}
			else {
				faults.add(new InvalidParameter("sgx_enforce_tcb_up_to_date field is missing"));
			}
			} catch (IOException e) {
				faults.add(new InvalidParameter("JSON request is not properly encoded"));
				log.error("CreateKeyTransferPolicy JSON Request is not properly encoded");
				throw e;
			}
			///If there are no faults values should be added
			if (faults.isEmpty()) {
				log.debug("no faults while deserializing.");
			} else {
				ktpRequest.setFaults(faults);
			}
			return ktpRequest;
		}
	}
