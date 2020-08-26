/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.usage.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.kms.api.fault.MissingAttributesFault;
import com.intel.kms.api.fault.InvalidAttributesFault;
import com.intel.kms.api.fault.NotFoundFault;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.MediaType;
import java.io.File;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.List;
import java.util.ArrayList;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author rbhat
 */
@V2
@Path("/key-usage-policies")
public class KeyUsagePolicy {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyUsagePolicy.class);
 
    final private ObjectMapper mapper;
    final protected FileRepository repository;

    public KeyUsagePolicy() throws IOException {
	this(getKeyUsagePolicyRepository());
    }
    
    public KeyUsagePolicy(FileRepository repository) throws IOException {
	this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
	this.repository = repository;
    }
   
    private static FileRepository getKeyUsagePolicyRepository() throws FileNotFoundException {
        File keysUsagePolicyDirectory = new File(Folders.repository("keys-usage-policy"));
        if (!keysUsagePolicyDirectory.exists()) {
            if (!keysUsagePolicyDirectory.mkdirs()) {
                log.error("Cannot create keys-usage-policy directory");
            }
        }
        return new FileRepository(keysUsagePolicyDirectory);
    }

    public boolean isUUID(String s){
	return s.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }

    /**
     *  DateTimeFormatter will parse the input string to validate
     *  if its a iso80601 date, else it will raise exception
     */
    boolean isValidIsoDateTime(String date) {
	try {
	    DateTimeFormatter.ISO_DATE_TIME.parse(date);
	    return true;
	} catch (DateTimeParseException ex) {
	    log.error("unable to parse input iso8601 date: {}", ex.getMessage());
	    return false;
	}
    }

    private List<Fault> validateCreateKeyUsagePolicy(String inputReq) {
	log.debug("validateCreateKeyUsagePolicy");
        ArrayList<Fault> faults = new ArrayList<>();

	try {
	    JsonNode rootNode = mapper.readTree(inputReq);

	    // read all Json Nodes in the input create policy JSON request
	    JsonNode notAfter = rootNode.path("not_after");
	    JsonNode notBefore = rootNode.path("not_before");
	    JsonNode leaseTimeLimit = rootNode.path("lease_time_limit");

	    // either notAfter or notBefore json nodes are mandatory in input request
	    if (notAfter.isMissingNode() && notBefore.isMissingNode()) {
                faults.add(new MissingAttributesFault("missing-attributes", "not_after and not_before both are missing"));
		return faults;
	    }
	    if (!notAfter.isMissingNode()) {
		if (notAfter.getNodeType() != JsonNodeType.STRING || notAfter.textValue().length() == 0) {
		    faults.add(new MissingAttributesFault("missing-attribute", "not_after"));
		    return faults;
		}
		else {
		    if (!isValidIsoDateTime(notAfter.textValue())) {
			faults.add(new InvalidAttributesFault("invalid-attribute", "not_after"));
			return faults;
		    }
		}
	    }
	    if (!notBefore.isMissingNode()) {
		if (notBefore.getNodeType() != JsonNodeType.STRING || notBefore.textValue().length() == 0) {
		    faults.add(new MissingAttributesFault("missing-attribute", "not_before"));
		    return faults;
		}
		else {
		    if (!isValidIsoDateTime(notBefore.textValue())) {
			faults.add(new InvalidAttributesFault("invalid-attribute", "not_before"));
			return faults;
		    }
		}
	    }
	    if (!leaseTimeLimit.isMissingNode()) {
		if (leaseTimeLimit.getNodeType() != JsonNodeType.NUMBER) {
		    faults.add(new InvalidAttributesFault("invalid-attribute", "lease_time_limit"));
		    return faults;
		}
	    }
	} catch (IOException e) {
            log.error("CreateKeyUsagePolicy JSON Request is not properly encoded: {}", e.getMessage());
	}
	return faults;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("key-usage-policies:create")
    public Response createKeyUsagePolicy(CreateKeyUsagePolicyRequest createKeyUsagePolicyRequest) {
        log.debug("createKeyUsagePolicy");
        ArrayList<Fault> faults = new ArrayList<>();

	try {
	    String inputReq = mapper.writeValueAsString(createKeyUsagePolicyRequest);
	    log.debug("createKeyUsagePolicyRequest input: {}", inputReq);

	    faults.addAll(validateCreateKeyUsagePolicy(inputReq));
	    // errors were detected during create usage policy request validation
            if (!faults.isEmpty()) {
                CreateKeyUsagePolicyResponse response = new CreateKeyUsagePolicyResponse();
		response.setOperation("create key usage policy");
		response.setStatus("failure");
		response.getFaults().addAll(faults);
		// propagate back fault description along with BAD_REQUEST HTTP status code
		return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
	    }
	    else {
		KeyUsagePolicyAttributes created = new KeyUsagePolicyAttributes();
		// copy the validated input request to be stored in backend
		created.copyFrom(createKeyUsagePolicyRequest);
		repository.store(created);
		CreateKeyUsagePolicyResponse response = new CreateKeyUsagePolicyResponse(created);
		response.setOperation("create key usage policy");
		response.setStatus("success");
		return Response.status(Response.Status.OK).entity(response).build();
	    }
	} catch(Exception e) {
	    log.error("Exception while trying to create a Key Usage Policy: {}", e.getMessage());
	    CreateKeyUsagePolicyResponse response = new CreateKeyUsagePolicyResponse();
	    response.setOperation("create key usage policy");
	    response.setStatus("failure");
	    response.getFaults().add(new Fault(e.getCause(), "received exception"));
	    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
	}
    }
  
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/{id}")
    @RequiresPermissions("key-usage-policies:retrieve")
    public Response readKeyUsagePolicy(@PathParam("id") String keyUsagePolicyId) {
        log.debug("readKeyUsagePolicy: " + keyUsagePolicyId);
        ArrayList<Fault> faults = new ArrayList<>();
        ReadKeyUsagePolicyResponse response = new ReadKeyUsagePolicyResponse();
	// check if input id is UUID type
	if (keyUsagePolicyId == null || keyUsagePolicyId.length() == 0 || isUUID(keyUsagePolicyId) == false) {
	    log.error("key usage policy id is not proper UUID");
	    response.setOperation("read key usage policy");
	    response.setStatus("failure");
	    faults.add(new NotFoundFault("not-found", keyUsagePolicyId));
	    response.getFaults().addAll(faults);
	    return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
	} else {
	    KeyUsagePolicyAttributes key = repository.retrieve(keyUsagePolicyId);
	    // cannot find the requested key usage policy in the backend
	    if (key == null) {
		log.error("no key usage policy record with Id : " + keyUsagePolicyId);
		response.setOperation("read key usage policy");
		response.setStatus("failure");
		faults.add(new NotFoundFault("not-found", keyUsagePolicyId));
		response.getFaults().addAll(faults);
		return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
	    } else {
		response.setOperation("read key usage policy");
		response.setStatus("success");
		KeyUsagePolicyAttributes keyUsagePolicyAttributes = new KeyUsagePolicyAttributes();
		keyUsagePolicyAttributes.copyFrom(key);
		response.getData().add(keyUsagePolicyAttributes);
		return Response.status(Response.Status.OK).entity(response).build();
	    }
	}
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("key-usage-policies:search")
    public Response readAllKeyUsagePolicies() {
	log.debug("readAllKeyUsagePolicies");
	ArrayList<Fault> faults = new ArrayList<>();
	ReadKeyUsagePolicyResponse response = new ReadKeyUsagePolicyResponse();

	File directory = new File(Folders.repository("keys-usage-policy"));

	if (directory.list().length == 0) {
	    log.error("no key usage policies exist");
	    response.setOperation("read all key usage policies");
	    response.setStatus("failure");
	    faults.add(new Fault("no key usage policies found"));
	    response.getFaults().addAll(faults);
	    return Response.status(Response.Status.NOT_FOUND).entity(response).build();
	} else {
	    // get a list of all key usage policy records from backend
	    String[] keyIds = directory.list();
	    response.setOperation("read all key usage policies");
	    response.setStatus("success");
	    for (String keyId : keyIds) {
		// iterate through each key usage policy and retrive attributes
		KeyUsagePolicyAttributes key = repository.retrieve(keyId);
		KeyUsagePolicyAttributes keyUsagePolicyAttributes = new KeyUsagePolicyAttributes();
		keyUsagePolicyAttributes.copyFrom(key);
		response.getData().add(keyUsagePolicyAttributes);
	    }
	}
	return Response.status(Response.Status.OK).entity(response).build();
    }

    @DELETE
    @Path("/{id}")
    @RequiresPermissions("key-usage-policies:delete")
    public Response deleteKeyUsagePolicy(@PathParam("id") String keyUsagePolicyId) {
	log.debug("deleteKeyUsagePolicy:  " + keyUsagePolicyId);
	ArrayList<Fault> faults = new ArrayList<>();
	DeleteKeyUsagePolicyResponse response = new DeleteKeyUsagePolicyResponse();

	// check if input id is UUID type
	if (keyUsagePolicyId == null || keyUsagePolicyId.length() == 0 || isUUID(keyUsagePolicyId) == false) {
	    log.error("key usage policy id is not proper UUID");
	    response.setOperation("delete key usage policy");
	    response.setStatus("failure");
	    faults.add(new NotFoundFault("not-found", keyUsagePolicyId));
	    response.getFaults().addAll(faults);
	    return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
	} else {
	    KeyUsagePolicyAttributes key = repository.retrieve(keyUsagePolicyId);
	    // cannot find the requested key usage policy in the backend
	    if (key == null) {
		log.error("no key usage policy record with Id : " + keyUsagePolicyId);
		response.setOperation("delete key usage policy");
		response.setStatus("failure");
		faults.add(new NotFoundFault("not-found", keyUsagePolicyId));
		response.getFaults().addAll(faults);
		return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
	    }
	    else {
		repository.delete(keyUsagePolicyId);
		log.debug("deleteKeyUsagePolicy: deleted key usage policy id:"  + keyUsagePolicyId);
		response.setOperation("delete key usage policy");
		response.setStatus("success");
		return Response.status(Response.Status.NO_CONTENT).entity(response).build();
	    }
	}
    }
}
