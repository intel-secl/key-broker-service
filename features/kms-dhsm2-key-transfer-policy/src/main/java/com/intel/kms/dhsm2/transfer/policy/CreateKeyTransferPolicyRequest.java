/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.intel.dcsg.cpg.validation.Fault;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.util.ArrayList;


/**
 * To request the key server to create a new key Transfer Policy, the key request
 * is essentially the set of key Transfer Policy attributes that the key should
 * have. 
 * 
 * @author rbhat
 */
@JsonDeserialize(using = CustomJsonDeserializerForKeyTransferPolicy.class)
	public class CreateKeyTransferPolicyRequest extends KeyTransferPolicyAttributes {

		private ArrayList<Fault> faults = new ArrayList<>();

		public CreateKeyTransferPolicyRequest() {
			super();
		}

		void setFaults(ArrayList<Fault> faults1) {
			faults = faults1;
		}

		ArrayList<Fault> getFaults() {
			return faults;
		}
	}
