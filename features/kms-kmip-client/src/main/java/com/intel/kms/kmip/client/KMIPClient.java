package com.intel.kms.kmip.client;


import ch.ntb.inf.kmip.container.KMIPContainer;
import ch.ntb.inf.kmip.stub.KMIPStubInterface;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.kmip.client.exception.KMIPClientException;
import com.intel.kms.kmip.client.operation.OperationRequestGenerator;
import com.intel.kms.kmip.client.util.KMIPApiUtil;
import com.intel.kms.kmip.stub.KMIPKmsStub;
import java.io.IOException;

/**
 * KMIPClient connects to server using stub and perform create,get,register and
 * delete operations
 * 
 * @author aakashmX
 */
public class KMIPClient {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KMIPClient.class);
	private static KMIPStubInterface stub;
	private static KMIPClient kmipClient;

	public KMIPClient() {
	}

	public static KMIPClient getKMIPClient(Configuration configuration)
			throws KMIPClientException {
		if (kmipClient == null) {
			kmipClient = new KMIPClient();
		}
		stub = new KMIPKmsStub(configuration);
		return kmipClient;
	}

	/**
	 * Creates secret from createkeyRequest
	 * 
	 * 
	 * @param createKeyRequest
	 * @return TransferKeyResponse with the URL \
	 * @throws BarbicanClientException
	 */
	public TransferKeyResponse createSecret(CreateKeyRequest createKeyRequest)
			throws KMIPClientException {

		KMIPContainer createRequest = OperationRequestGenerator
				.createKMIPRequest(createKeyRequest);

		KMIPContainer response = stub.processRequest(createRequest);
		if (response == null) {
			throw new KMIPClientException(new IOException(
					"createSecret: The createrResponse is null"));
		}

		log.debug("Create operation response: {}",response);
		if (KMIPApiUtil.checkStatus(response)) {

			String uid = KMIPApiUtil.fetchUid(response);
			TransferKeyRequest transferKeyRequest = new TransferKeyRequest(uid);
			TransferKeyResponse transferKeyResponse = retrieveSecret(transferKeyRequest);
			return transferKeyResponse;

		} else {
			throw new KMIPClientException(
					"createSecret::Opertion CREATE failed");
		}

	}

	/**
	 * Based on uid inside transferKeyRequest retrieves key
	 * 
	 * @param transferKeyRequest
	 * @return TransferKeyResponse with the key populated
	 * @throws KMIPClientException
	 */

	public TransferKeyResponse retrieveSecret(
			TransferKeyRequest transferKeyRequest) throws KMIPClientException {
		String uid = transferKeyRequest.getKeyId();
		KMIPContainer getRequest = OperationRequestGenerator
				.getKMIPRequest(uid);
		KMIPContainer getResponse = stub.processRequest(getRequest);
		log.debug("Get Operation Response: {}", getResponse.toString());

		if (KMIPApiUtil.checkStatus(getResponse)) {
			TransferKeyResponse transferKeyResponse = KMIPApiUtil
					.mapGetSymmetricResponseToTransferKeyResponse(getResponse,
							transferKeyRequest);
			return transferKeyResponse;
		} else {
			throw new KMIPClientException(
					"retrieveSecret:: Opertion GET failed");
		}

	}

	/**
	 * 
	 * Registers secret into kmip server
	 * 
	 * @param registerKeyRequest
	 * @return RegisterKeyResponse
	 * @throws KMIPClientException
	 */
	public RegisterKeyResponse registerSecret(
			RegisterKeyRequest registerKeyRequest) throws KMIPClientException {

		KMIPContainer registerRequest = OperationRequestGenerator
				.registerSymmetricKeyKMIPRequest(registerKeyRequest);

		KMIPContainer registerResponse = stub.processRequest(registerRequest);
		if (registerResponse == null) {
			throw new KMIPClientException(new IOException(
					"registerSecret: The registerResponse is null"));
		}
		log.debug("Register Operation Response: {}", registerResponse.toString());
		if (KMIPApiUtil.checkStatus(registerResponse)) {

			RegisterKeyResponse registerKeyResponse = KMIPApiUtil
					.mapRegisterResponseToRegisterKeyResponse(registerResponse,
							registerKeyRequest);
			return registerKeyResponse;

		} else {
			throw new KMIPClientException(
					"registerSecret::Opertion Register failed");
		}

	}

	/**
	 * Deletes secret from kmip server
	 * 
	 * @param request
	 * @return
	 * @throws KMIPClientException
	 */
	public DeleteKeyResponse deleteSecret(DeleteKeyRequest request)
			throws KMIPClientException {
		DeleteKeyResponse response;

		String uid = request.getKeyId();

		KMIPContainer deleteRequest = OperationRequestGenerator
				.deleteKMIPRequest(uid);

		KMIPContainer deleteResponse = stub.processRequest(deleteRequest);
		log.debug("Delete Operation Response: {}", deleteResponse.toString());

		if (KMIPApiUtil.checkStatus(deleteResponse)) {
			response = KMIPApiUtil
					.mapDeleteResponseToDeleteKeyResponse(deleteResponse);
			return response;
		} else {
			throw new KMIPClientException("deleteSecret:: Opertion GET failed");
		}
	}

}
