/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.kms.api.fault.InvalidParameter;
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
import java.util.ArrayList;

/**
 *
 * @author rbhat
 */
@V2
@Path("/key-transfer-policies")
public class KeyTransferPolicy {
	final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyTransferPolicy.class);
	final private static String uuidRegex = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

	final private ObjectMapper mapper;
	final protected FileRepository repository;

	public KeyTransferPolicy() throws IOException {
		this(getKeyTransferPolicyRepository());
	}

	public KeyTransferPolicy(FileRepository repository) throws IOException {
		this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
		this.repository = repository;
	}

	private static FileRepository getKeyTransferPolicyRepository() throws FileNotFoundException {
		File keysTransferPolicyDirectory = new File(Folders.repository("keys-transfer-policy"));
		if (!keysTransferPolicyDirectory.exists()) {
			if (!keysTransferPolicyDirectory.mkdirs()) {
				log.error("Cannot create keys-transfer-policy directory");
			}
		}
		return new FileRepository(keysTransferPolicyDirectory);
	}

	public boolean isUUID(String s){
		return s.matches(uuidRegex);
	}

	@POST
		@Consumes(MediaType.APPLICATION_JSON)
		@Produces(MediaType.APPLICATION_JSON)
		public Response createKeyTransferPolicy(CreateKeyTransferPolicyRequest createKeyTransferPolicyRequest) {
			log.debug("createKeyTransferPolicy");
			try {
				String inputReq = mapper.writeValueAsString(createKeyTransferPolicyRequest);
				log.debug("createKeyTransferPolicyRequest Json input is : {}", inputReq);

				ArrayList<Fault> faults = createKeyTransferPolicyRequest.getFaults();
				if (!faults.isEmpty()) {
					log.debug("faults found during deserialiazation");
					CreateKeyTransferPolicyResponse response = new CreateKeyTransferPolicyResponse();
					response.setOperation("create key transfer policy");
					response.setStatus("failure");
					response.getFaults().addAll(faults);
					return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
				}

				// copy the validated input request to be stored in backend
				KeyTransferPolicyAttributes created = new KeyTransferPolicyAttributes();
				created.copyFrom(createKeyTransferPolicyRequest);
				repository.store(created);
				CreateKeyTransferPolicyResponse response = new CreateKeyTransferPolicyResponse(created);
				response.setOperation("create key transfer policy");
				response.setStatus("success");
				return Response.status(Response.Status.OK).entity(response).build();
			} catch(Exception e) {
				log.error("Exception while trying to create a Key Transfer Policy");
				CreateKeyTransferPolicyResponse response = new CreateKeyTransferPolicyResponse();
				response.setOperation("create key transfer policy");
				response.setStatus("failure");
				response.getFaults().add(new Fault(e.getCause(), "received exception"));
				return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
			}
		}

	@GET
		@Produces(MediaType.APPLICATION_JSON)
		@Path("/{id}")
		public Response readKeyTransferPolicy(@PathParam("id") String keyTransferPolicyId) {
			log.debug("readKeyTransferPolicy: " + keyTransferPolicyId);
			ArrayList<Fault> faults = new ArrayList<>();
			ReadKeyTransferPolicyResponse response = new ReadKeyTransferPolicyResponse();
			// check if input id is UUID type
			if (keyTransferPolicyId == null || keyTransferPolicyId.length() == 0 || !isUUID(keyTransferPolicyId)) {
				log.error("invalid key tranfer Policy id specified");
				response.setKeyId(keyTransferPolicyId);
				response.setOperation("read key transfer policy");
				response.setStatus("failure");
				faults.add(new InvalidParameter("key transfer policy id is invalid"));
				response.getFaults().addAll(faults);
				return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
			} else {
				KeyTransferPolicyAttributes key = repository.retrieve(keyTransferPolicyId);
				// cannot find the requested key transfer policy in the backend
				if (key == null) {
					log.error("no key transfer policy record with Id : " + keyTransferPolicyId);
					response.setKeyId(keyTransferPolicyId);
					response.setOperation("read key transfer policy");
					response.setStatus("failure");
					faults.add(new InvalidParameter("no such key transfer policy id"));
					response.getFaults().addAll(faults);
					return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
				}
				else {
					response.setOperation("read key transfer policy");
					response.setStatus("success");
					KeyTransferPolicyAttributes keyTransferPolicyAttributes = new KeyTransferPolicyAttributes();
					keyTransferPolicyAttributes.copyFrom(key);
					response.getData().add(keyTransferPolicyAttributes);
					return Response.status(Response.Status.OK).entity(response).build();
				}
			}
		}

	@GET
		@Produces(MediaType.APPLICATION_JSON)
		public Response readAllKeyTransferPolicies() {
			log.debug("readAllKeyTransferPolicies");
			ArrayList<Fault> faults = new ArrayList<>();
			ReadKeyTransferPolicyResponse response = new ReadKeyTransferPolicyResponse();

			File directory = new File(Folders.repository("keys-transfer-policy"));

			if (directory.list().length == 0) {
				log.error("no key transfer policies exist");
				response.setOperation("read all key transfer policies");
				response.setStatus("failure");
				faults.add(new Fault("no key transfer policies found"));
				response.getFaults().addAll(faults);
				return Response.status(Response.Status.NOT_FOUND).entity(response).build();
			} else {
				// get a list of all key transfer policy records from backend
				String[] keyIds = directory.list();
				response.setOperation("read all key transfer policies");
				response.setStatus("success");
				for (String keyId : keyIds) {
					// iterarte through each key transfer policy and retrive attributes
					KeyTransferPolicyAttributes key = repository.retrieve(keyId);
					KeyTransferPolicyAttributes keyTransferPolicyAttributes = new KeyTransferPolicyAttributes();
					keyTransferPolicyAttributes.copyFrom(key);
					response.getData().add(keyTransferPolicyAttributes);
				}
			}
			return Response.status(Response.Status.OK).entity(response).build();
		}

	@DELETE
		@Path("/{id}")
		public Response deleteKeyTransferPolicy(@PathParam("id") String keyTransferPolicyId) {
			log.debug("deleteKeyTransferPolicy:  " + keyTransferPolicyId);
			ArrayList<Fault> faults = new ArrayList<>();
			DeleteKeyTransferPolicyResponse response = new DeleteKeyTransferPolicyResponse();

			// check if input id is UUID type
			if (keyTransferPolicyId == null || keyTransferPolicyId.length() == 0 || !isUUID(keyTransferPolicyId)) {
				log.error("key transfer Policy id is not a proper UUID");
				response.setKeyId(keyTransferPolicyId);
				response.setOperation("delete key transfer policy");
				response.setStatus("failure");
				faults.add(new InvalidParameter("key transfer policy id is invalid"));
				response.getFaults().addAll(faults);
				return Response.status(Response.Status.BAD_REQUEST).entity(response).build();
			} else {
				KeyTransferPolicyAttributes key = repository.retrieve(keyTransferPolicyId);
				// cannot find the requested key usage policy in the backend
				if (key == null) {
					log.error("no key transfer policy record with Id : " + keyTransferPolicyId);
					response.setKeyId(keyTransferPolicyId);
					response.setOperation("delete key transfer policy");
					response.setStatus("failure");
					faults.add(new InvalidParameter("no such key transfer policy id"));
					response.getFaults().addAll(faults);
					return Response.status(Response.Status.NOT_FOUND).entity(response).build();
				}
				else {
					repository.delete(keyTransferPolicyId);
					log.debug("deleteKeyTransferPolicy: deleted key transfer policy id:"  + keyTransferPolicyId);
					response.setOperation("delete key transfer policy");
					response.setStatus("success");
					return Response.status(Response.Status.NO_CONTENT).entity(response).build();
				}
			}
		}
}
