/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.sessionManagement;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
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
import com.intel.kms.stmlib.StmChallengeResponseVerify;
import com.intel.kms.stmlib.StmWrappedSwk;
import com.intel.kms.stmlib.StmAttributesMap;
import com.intel.kms.dhsm2.common.CommonSession.KeyTransferSession;
import com.intel.kms.dhsm2.common.CommonSession.SessionMap;

import static com.intel.mtwilson.configuration.ConfigurationFactory.getConfiguration;

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
 * @author @shefalik
 */
@V2
@Path ("/session")
public class SessionManagement {

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SessionManagement.class);
    final private ObjectMapper mapper;
    final private SessionMap sessionMapObj;
    final private StmAttributesMap stmAttrMap;

    public SessionManagement() throws IOException {
	this.sessionMapObj = new SessionMap();
	this.stmAttrMap = new StmAttributesMap();
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
		StmChallengeResponseVerify StmChallengeObj = new StmChallengeResponseVerify();
		String challenge = attribute.getChallenge();
		KeyTransferSession sessionObj = sessionMapObj.getObject(challenge);
		String activeStmLabel = "";
		if(sessionObj != null) {
		    activeStmLabel = sessionObj.getStmLabel();
		}
		if (sessionObj == null || !sessionMapObj.containsSession(challenge)) {
		    log.debug("Session ID not found: {}", challenge);
		    faults.add(new InvalidParameter("Invalid Session-ID provided in input"));
		    SessionManagementResponse response = new SessionManagementResponse();
		    response.setOperation("establish session key");
		    response.setStatus("failure");
		    response.getFaults().addAll(faults);
		    return Response.status(Response.Status.UNAUTHORIZED).entity(response).build();
		}
		if (!StmChallengeObj.StmChallengeVerifyResponse(Quote, activeStmLabel)) {
		    log.error("remote attestaion failed");
		    faults.add(new RemoteAttestationFault("remote attestation for new session failed"));
		    SessionManagementResponse response = new SessionManagementResponse();
		    response.setOperation("establish session key");
		    response.setStatus("failure");
		    response.getFaults().addAll(faults);
		    return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
		}
		log.debug("remote attestaion successful");
		stmAttrMap.addAttrMapToSession(challenge, StmChallengeObj.getMap());
		StmWrappedSwk StmWrappedSwkObj = new StmWrappedSwk();
		byte[] StmWrappedSwk;

		if (StmWrappedSwkObj.StmCreateAndWrapSwk(StmChallengeObj.getKeyType(),
				StmChallengeObj.getPublicKey())) {
		    log.debug("wrapping of swk key successful");
		    StmWrappedSwk = StmWrappedSwkObj.getWrappedSwkKey();
		    sessionObj.setSWK(StmWrappedSwkObj.getSwkKey());
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
		created.setSWK(StmWrappedSwk);
		created.setAlgoType(StmWrappedSwkObj.getSwkKeyType(activeStmLabel));
		SessionManagementResponse response = new SessionManagementResponse(created);
		response.setOperation("establish session key");
		response.setStatus("success");
		String Resp = mapper.writeValueAsString(response);
		log.debug("SessionManagementResponse output: {}", Resp);
		return Response.status(Response.Status.CREATED).header("Session-ID", attribute.getChallengeType()+ ":"+attribute.getChallenge()).entity(response).build();
	    }
	} catch(Exception e) {
	    log.error("Exception while trying to create a session in KMS");
	    SessionManagementResponse response = new SessionManagementResponse();
	    response.getFaults().add(new Fault(e.getCause(), "received exception"));
	    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
	}
    }
}
