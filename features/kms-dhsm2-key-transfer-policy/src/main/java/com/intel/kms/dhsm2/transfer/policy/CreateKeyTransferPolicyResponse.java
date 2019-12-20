/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.fasterxml.jackson.annotation.JsonInclude;
/**
 * The CreateKeyTransferPolicyResponse contains either key Transfer Policy
 * attributes or any faults that prevented the key transfer policy from being
 * created. 
 *
 * @author rbhat
 */
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
	public class CreateKeyTransferPolicyResponse extends ReadKeyTransferPolicyResponse {

		public CreateKeyTransferPolicyResponse() {
			super();
		}

		public CreateKeyTransferPolicyResponse(KeyTransferPolicyAttributes created) {
			super();
			getData().add(created);
		}
	}
