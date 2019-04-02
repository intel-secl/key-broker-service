package com.intel.kms.kmip.client.operation;

import java.util.ArrayList;

import ch.ntb.inf.kmip.attributes.CryptographicAlgorithm;
import ch.ntb.inf.kmip.attributes.CryptographicLength;
import ch.ntb.inf.kmip.attributes.CryptographicUsageMask;
import ch.ntb.inf.kmip.attributes.ObjectType;
import ch.ntb.inf.kmip.attributes.UniqueIdentifier;
import ch.ntb.inf.kmip.container.KMIPBatch;
import ch.ntb.inf.kmip.container.KMIPContainer;
import ch.ntb.inf.kmip.kmipenum.EnumCryptographicAlgorithm;
import ch.ntb.inf.kmip.kmipenum.EnumObjectType;
import ch.ntb.inf.kmip.kmipenum.EnumOperation;
import ch.ntb.inf.kmip.objects.KeyMaterial;
import ch.ntb.inf.kmip.objects.base.Attribute;
import ch.ntb.inf.kmip.objects.base.KeyBlock;
import ch.ntb.inf.kmip.objects.base.KeyValue;
import ch.ntb.inf.kmip.objects.base.TemplateAttribute;
import ch.ntb.inf.kmip.objects.base.TemplateAttributeStructure;
import ch.ntb.inf.kmip.objects.managed.SymmetricKey;
import ch.ntb.inf.kmip.types.KMIPByteString;
import ch.ntb.inf.kmip.utils.KMIPUtils;

import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.kmip.client.exception.KMIPClientException;

/**
 * 
 * @author aakashmX
 */
public class OperationRequestGenerator {

	/**
	 * Generates CREATE operation kmip request
	 * 
	 * @param createKeyRequest
	 * @return KMIPContainer
	 * @throws KMIPClientException
	 */
	public static KMIPContainer createKMIPRequest(
			CreateKeyRequest createKeyRequest) throws KMIPClientException {
		// Create Container with one Batch
		if (createKeyRequest == null) {
			throw new KMIPClientException(new NullPointerException(
					"createKMIPRequest: The createKeyRequest is null"));
		}
		KMIPContainer container = new KMIPContainer();
		KMIPBatch batch = new KMIPBatch();
		container.addBatch(batch);
		container.calculateBatchCount();
		// Set Operation and Attribute
		batch.setOperation(EnumOperation.Create);
		batch.addAttribute(new ObjectType(EnumObjectType.SymmetricKey));

		// Set TemplateAttribute with Attributes
		ArrayList<Attribute> templateAttributes = new ArrayList<Attribute>();
		templateAttributes
				.add(new CryptographicAlgorithm(
						(new EnumCryptographicAlgorithm(createKeyRequest
								.getAlgorithm())).getValue()));
		templateAttributes.add(new CryptographicLength(createKeyRequest
				.getKeyLength()));
		templateAttributes.add(new CryptographicUsageMask(0x0C));
		TemplateAttributeStructure tas = new TemplateAttribute();
		tas.setAttributes(templateAttributes);
		batch.addTemplateAttributeStructure(tas);

		return container;
	}

	/**
	 * Generates DESTROY operation request for kmip
	 * 
	 * @param uid
	 * @return KMIPContainer
	 * @throws KMIPClientException
	 */
	public static KMIPContainer deleteKMIPRequest(String uid)
			throws KMIPClientException {
		if (uid == null) {
			throw new KMIPClientException(new NullPointerException(
					"deleteKMIPRequest:  uid is null"));
		}
		KMIPContainer container = new KMIPContainer();
		KMIPBatch batch = new KMIPBatch();
		container.addBatch(batch);
		container.calculateBatchCount();
		batch.setOperation(EnumOperation.Destroy);
		Attribute a = new UniqueIdentifier();
		a.setValue(uid, null);
		batch.addAttribute(a);
		return container;
	}

	/**
	 * Generates GET operation request for kmip
	 * 
	 * @param uid
	 * @return
	 * @throws KMIPClientException
	 */
	public static KMIPContainer getKMIPRequest(String uid)
			throws KMIPClientException {
		if (uid == null) {
			throw new KMIPClientException(new NullPointerException(
					"getKMIPRequest:  uid is null"));
		}
		KMIPContainer container = new KMIPContainer();
		KMIPBatch batch = new KMIPBatch();
		container.addBatch(batch);
		container.calculateBatchCount();
		batch.setOperation(EnumOperation.Get);
		Attribute a = new UniqueIdentifier();
		a.setValue(uid, null);
		batch.addAttribute(a);
		return container;
	}

	/**
	 * Generates REGISTER operation kmip request
	 * 
	 * @param registerKeyRequest
	 * @return
	 * @throws KMIPClientException
	 */
	public static KMIPContainer registerSymmetricKeyKMIPRequest(
			RegisterKeyRequest registerKeyRequest) throws KMIPClientException {
		if (registerKeyRequest == null) {
			throw new KMIPClientException(
					new NullPointerException(
							"registerSymmetricKeyKMIPRequest: The registerKeyRequest is null"));
		}
		if (registerKeyRequest.getKey() == null) {
			throw new KMIPClientException(new NullPointerException(
					"registerSymmetricKeyKMIPRequest: The key data is null"));
		}

		KMIPContainer container = new KMIPContainer();
		KMIPBatch batch = new KMIPBatch();
		container.addBatch(batch);
		container.calculateBatchCount();
		batch.setOperation(EnumOperation.Register);

		batch.addAttribute(new ObjectType(EnumObjectType.SymmetricKey));

		SymmetricKey sKey = new SymmetricKey();
		batch.setManagedObject(sKey);
		KeyBlock keyBlock = new KeyBlock();

		sKey.setKeyBlock(keyBlock);
		keyBlock.setKeyFormatType("1");
		KeyValue keyValue = new KeyValue();
		keyBlock.setKeyValue(keyValue);

		keyValue.setKeyMaterial(new KeyMaterial(new KMIPByteString(
				registerKeyRequest.getKey())));

		keyBlock.addAttribute(new CryptographicAlgorithm(
				(new EnumCryptographicAlgorithm(registerKeyRequest
						.getDescriptor().getEncryption().getAlgorithm()))
						.getValue()));
		keyBlock.addAttribute(new CryptographicLength(registerKeyRequest
				.getDescriptor().getEncryption().getKeyLength()));
		return container;
	}

}
