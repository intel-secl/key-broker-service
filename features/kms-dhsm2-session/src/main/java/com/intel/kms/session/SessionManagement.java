/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.sessionManagement;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import javax.ws.rs.core.Response;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.RemoteAttestationFault;
import com.intel.kms.api.fault.SWKUnsuccessfulFault;
import com.intel.kms.dhsm2.common.CommonSession.KeyTransferSession;
import com.intel.kms.dhsm2.common.CommonSession.SessionMap;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * This class is to validate and create a new session. The new session credentials are
 * returned to the key agent.
 * Input: Requet Json containing:
 * "challenge_type": "SGX" or "KPT2",
 * "challenge": base64 encoded challenge string,
 * "quote": String that is verified by STM,
 * "certificate_chain": PEM
 *
 * OUTPUT: SWK AES256 symmetric wrapping key, which will be used to wrap requested application keys.
 * @author shefalik
 */
@V2
@Path ("/session")
public class SessionManagement {

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SessionManagement.class);
    final private ObjectMapper mapper;
    final private SessionMap sessionMapObj;
    final private SessionResponseMap responseMap;

    public SessionManagement() throws IOException {
	this.sessionMapObj = new SessionMap();
	this.responseMap = new SessionResponseMap();
	this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
    }

    public List<Fault> validateSessionCreationRequest(String inputReq) {
	ArrayList<Fault> faults = new ArrayList<>();

	try {
	    JsonNode rootNode = mapper.readTree(inputReq);
	    JsonNode challengeType = rootNode.path("challenge_type");
	    JsonNode challenge = rootNode.path("challenge");
	    JsonNode quote = rootNode.path("quote");

	    if (challengeType.isMissingNode() || challenge.isMissingNode() || quote.isMissingNode()) {
		faults.add(new MissingRequiredParameter("challenge_type/challenge parameters are missing"));
		return faults;
	    }
	    if (challengeType.getNodeType() != JsonNodeType.STRING ||
		challenge.getNodeType() != JsonNodeType.STRING ||
		quote.getNodeType() != JsonNodeType.STRING) {
		faults.add(new InvalidParameter("one of the requests is not a valid string"));
		return faults;
	    }
	} catch (IOException e) {
	    log.error("Error in Session Management Request");
	}
	return faults;
    }
    
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("key-session-api:create")
    public Response createSession(SessionManagementRequest sessionManagementRequest) {
	ArrayList<Fault> faults = new ArrayList<>();
	try {
	    String inputReq = mapper.writeValueAsString(sessionManagementRequest);
	    log.debug("sessionManagementRequest input: {}", inputReq);
	    faults.addAll(validateSessionCreationRequest(inputReq));

	    if (!faults.isEmpty()) {
		log.debug("Session request input validation failed");
		SessionManagementResponse response = new SessionManagementResponse();
		response.setOperation("establish session key");
		response.setStatus("failure");
		response.getFaults().addAll(faults);
		return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
	    } else {
		SessionManagementAttributes attribute = new SessionManagementAttributes();
		attribute.copyFrom(sessionManagementRequest);
		byte[] Quote = Base64.getDecoder().decode(attribute.getQuote());
		String challenge = attribute.getChallenge();
		KeyTransferSession sessionObj = sessionMapObj.getObject(challenge);

		if (sessionObj == null || !sessionMapObj.containsSession(challenge)) {
		    log.debug("Session ID not found: {}", challenge);
		    faults.add(new InvalidParameter("Invalid Session-ID provided in input"));
		    SessionManagementResponse response = new SessionManagementResponse();
		    response.setOperation("establish session key");
		    response.setStatus("failure");
		    response.getFaults().addAll(faults);
		    return Response.status(Response.Status.UNAUTHORIZED).entity(response).build();
		}

		String activeStmLabel = "";
		if(sessionObj != null) {
		    activeStmLabel = sessionObj.getStmLabel();
		}
	       
		QuoteVerifyOperations verify = new QuoteVerifyOperations(activeStmLabel);
		QuoteVerifyResponseAttributes responseAttributes = verify.verifySKCQuote(attribute.getQuote());
		if (responseAttributes == null) {
		    log.error("remote attestaion failed");
		    faults.add(new RemoteAttestationFault("remote attestation for new session failed"));
		    SessionManagementResponse response = new SessionManagementResponse();
		    response.setOperation("establish session key");
		    response.setStatus("failure");
		    response.getFaults().addAll(faults);
		    return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
		}
		log.debug("remote attestaion successful");
		responseMap.addAttrMapToSession(challenge, responseAttributes);
		SessionWrappedSwk SessionWrappedSwkObj = new SessionWrappedSwk();
		byte[] SessionWrappedSwk;

		if (SessionWrappedSwkObj.SessionCreateAndWrapSwk(responseAttributes.getChallengeKeyType(),
				responseAttributes.getChallengeRsaPublicKey())) {
		    log.debug("wrapping of swk key successful");
		    SessionWrappedSwk = SessionWrappedSwkObj.getWrappedSwkKey();
		    sessionObj.setSWK(SessionWrappedSwkObj.getSwkKey());
		} else {
		    log.error("wrapping unsuccessful");
		    faults.add(new SWKUnsuccessfulFault("wrapping of SWK is unsuccessful"));
		    SessionManagementResponse response = new SessionManagementResponse();
		    response.setOperation("establish session key");
		    response.setStatus("failure");
		    response.getFaults().addAll(faults);
		    return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
		}
		SessionManagementAttributes created = new SessionManagementAttributes();
		created.setSWK(SessionWrappedSwk);
		created.setAlgoType(SessionWrappedSwkObj.getSwkKeyType(activeStmLabel));
		SessionManagementResponse responseCreate = new SessionManagementResponse(created);
		responseCreate.setOperation("establish session key");
		responseCreate.setStatus("success");
		String Resp = mapper.writeValueAsString(responseCreate);
		log.debug("SessionManagementResponse output: {}", Resp);
		return Response.status(Response.Status.CREATED).header("Session-ID", attribute.getChallengeType()+ ":"+attribute.getChallenge()).entity(responseCreate).build();
	    }
	} catch(NullPointerException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidKeySpecException | JsonProcessingException  e) {
	    log.error("Exception while trying to create a session in KMS", e);
	    SessionManagementResponse response = new SessionManagementResponse();
	    response.getFaults().add(new Fault(e.getCause(), "received exception"));
	    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
	}catch ( Exception e){
	    log.error("Generic Exception while trying to create a session in KMS");
            SessionManagementResponse response = new SessionManagementResponse();
            response.getFaults().add(new Fault(e.getCause(), "Generic: received exception"));
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
	}
    }
}
