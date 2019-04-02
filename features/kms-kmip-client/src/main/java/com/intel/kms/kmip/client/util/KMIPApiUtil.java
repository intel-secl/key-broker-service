/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.kmip.client.util;

import ch.ntb.inf.kmip.attributes.UniqueIdentifier;
import ch.ntb.inf.kmip.container.KMIPBatch;
import ch.ntb.inf.kmip.container.KMIPContainer;
import ch.ntb.inf.kmip.kmipenum.EnumResultStatus;
import ch.ntb.inf.kmip.objects.base.Attribute;
import ch.ntb.inf.kmip.objects.managed.ManagedObject;
import ch.ntb.inf.kmip.objects.managed.SymmetricKey;

import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.kmip.client.exception.KMIPClientException;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;

/**
 * 
 * @author aakashmX
 */
public class KMIPApiUtil {

	/**
	 * Map the response of get operation to the generic transfer object
	 * 
	 * @param getresponse
	 * @param transferKeyRequest
	 * @return TransferKeyResponse
	 * @throws KMIPClientException
	 */
	public static TransferKeyResponse mapGetSymmetricResponseToTransferKeyResponse(
			KMIPContainer getResponse, TransferKeyRequest transferKeyRequest)
			throws KMIPClientException {
		if (getResponse == null) {
			throw new KMIPClientException(
					new NullPointerException(
							"mapGetResponseToTransferKeyResponse: GET operation response is null"));
		}
		KMIPBatch getResponsebatch = getResponse.getBatch(0);
		ManagedObject mob = getResponsebatch.getManagedObject();
		if (mob instanceof SymmetricKey) {

			SymmetricKey sKey = (SymmetricKey) mob;
			byte[] byteString = sKey.getKeyBlock().getKeyValue()
					.getKeyMaterial().getKeyMaterialByteString().getValue();
			TransferKeyResponse transferKeyResponse = new TransferKeyResponse();
			transferKeyResponse.setKey(byteString);
			KeyDescriptor descriptor = new KeyDescriptor();
			CipherKeyAttributes contentAttributes = new CipherKeyAttributes();
			contentAttributes.setKeyId(transferKeyRequest.getKeyId());
			descriptor.setContent(contentAttributes);
			transferKeyResponse.setDescriptor(descriptor);
			return transferKeyResponse;

		} else {
			throw new KMIPClientException(
					"mapGetSymmetricResponseToTransferKeyResponse: Not a symmetric key response ");
		}

	}

	/**
	 * Map the kmip delete response to the generic delete object
	 * 
	 * @param deleteSecretRequest
	 * @return DeleteKeyResponse
	 * @throws KMIPClientException
	 */
	public static DeleteKeyResponse mapDeleteResponseToDeleteKeyResponse(
			KMIPContainer deleteResponse) throws KMIPClientException {
		if (deleteResponse == null) {
			throw new KMIPClientException(
					new NullPointerException(
							"mapDeleteResponseToDeleteKeyResponse: The deleteResponse is null"));
		}
		DeleteKeyResponse deleteKeyResponse = new DeleteKeyResponse();

		deleteKeyResponse.getHttpResponse().setStatusCode(200);
		return deleteKeyResponse;
	}

	/**
	 * Map register Response to Register Key response
	 * 
	 * @param registerResponse
	 * @param registerKeyRequest
	 * @return
	 * @throws KMIPClientException
	 */
	public static RegisterKeyResponse mapRegisterResponseToRegisterKeyResponse(
			KMIPContainer registerResponse,
			RegisterKeyRequest registerKeyRequest) throws KMIPClientException {
		if (registerResponse == null) {
			throw new KMIPClientException(
					new NullPointerException(
							"mapRegisterResponseToRegisterKeyResponse: The registerResponse is null"));
		}

		String uid = fetchUid(registerResponse);
		KeyAttributes attributes = new KeyAttributes();
		CipherKeyAttributes encryption = registerKeyRequest.getDescriptor()
				.getEncryption();
		attributes.setAlgorithm(encryption.getAlgorithm());
		attributes.setKeyLength(encryption.getKeyLength());
		attributes.setKeyId(uid);
		RegisterKeyResponse registerKeyResponse = new RegisterKeyResponse(
				attributes);
		return registerKeyResponse;
	}

	/**
	 * Map register key response to create key response
	 * 
	 * @param registerKeyResponse
	 * @return
	 * @throws KMIPClientException
	 */
	public static CreateKeyResponse mapRegisterKeyResponseToCreateKeyResponse(
			RegisterKeyResponse registerKeyResponse) throws KMIPClientException {
		if (registerKeyResponse == null) {
			throw new KMIPClientException(
					new NullPointerException(
							"mapRegisterKeyResponseToCreateKeyResponse: The registerKeyResponse is null"));
		}

		CreateKeyResponse createKeyResponse = new CreateKeyResponse(
				registerKeyResponse.getData().get(0));
		return createKeyResponse;
	}

	/**
	 * Check status of Response returned by server
	 * 
	 * @param kmipContainer
	 * @return boolean
	 * @throws KMIPClientException
	 */
	public static boolean checkStatus(KMIPContainer response)
			throws KMIPClientException {
		if (response == null) {
			throw new KMIPClientException(new NullPointerException(
					"checkStatus method, response is null"));
		}

		KMIPBatch batch = response.getBatch(0);
		if ((EnumResultStatus.Success) == batch.getResultStatus().getValue())
			return true;
		else
			return false;

	}

	/**
	 * Fetches uid from the response
	 * 
	 * @param kmipContainer
	 * @return String
	 * @throws KMIPClientException
	 */
	public static String fetchUid(KMIPContainer kmipContainer)
			throws KMIPClientException {
		String uid = null;
		if (kmipContainer == null) {
			throw new KMIPClientException(new NullPointerException(
					"fetchUid method, response is null"));
		}
		if (kmipContainer.getBatch(0).getAttributes().size() != 0) {
			Attribute attr = kmipContainer.getBatch(0).getAttributes().get(0);
			if (attr instanceof UniqueIdentifier) {
				uid = ((attr.getValues()[0])).getValueString();
			}
		}
		return uid;
	}

}
