/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.intel.dcsg.cpg.io.Attributes;
import com.intel.dcsg.cpg.io.Copyable;
import com.intel.dcsg.cpg.iso8601.Iso8601Date;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.ArrayList;

/**
 *
 * @author rbhat
 */

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
	public class KeyTransferPolicyAttributes extends Attributes implements Copyable {

		private String keyTransferPolicyId;
		private List<String> sgxEnclaveIssuerAnyOf = new ArrayList<>();
		private List<Short> sgxEnclaveIssuerProductIdAnyOf = new ArrayList<>();
		private List<String> sgxEnclaveIssuerExtendedProductIdAnyOf = new ArrayList<>();
		private List<String> sgxEnclaveMeasurementAnyOf = new ArrayList<>();
		private Short sgxEnclaveSvnMinimum;
		private List<String> sgxConfigIdAnyOf = new ArrayList<>();
		private Short sgxConfigIdSvn;
		private List<String> kpt2IssuerAnyOf = new ArrayList<>();
		private List<String> tlsClientCertificateIssuerCNAnyOf = new ArrayList<>();
		private List<String> tlsClientCertificateSanAnyOf = new ArrayList<>();
		private List<String> tlsClientCertificateSanAllOf = new ArrayList<>();
		private List<String> attestationTypeAnyOf = new ArrayList<>();

		@JsonFormat(shape=JsonFormat.Shape.STRING, pattern="yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
			private Iso8601Date createdAt;

		protected void setKeyTransferPolicyId(String keyTransferPolicyId)
		{
			this.keyTransferPolicyId = keyTransferPolicyId;
		}

		@JsonProperty("id")
			public String getKeyTransferPolicyId()
			{
				return this.keyTransferPolicyId;
			}

		@JsonProperty("sgx_enclave_issuer_anyof")
			public ArrayList<String> getSgxEnclaveIssuerAnyOf()
			{
				ArrayList<String> sgxEnclIssuerAnyOf = new ArrayList<String>();
				for (String obj : this.sgxEnclaveIssuerAnyOf)
					sgxEnclIssuerAnyOf.add(obj);
				return sgxEnclIssuerAnyOf;
			}

		protected void setSgxEnclaveIssuerAnyOf(ArrayList<String> sgxEnclIssuerAnyOf)
		{
			for (String obj : sgxEnclIssuerAnyOf)
				this.sgxEnclaveIssuerAnyOf.add(obj);
		}

		@JsonProperty("sgx_enclave_issuer_product_id_anyof")
			public ArrayList<Short> getSgxEnclaveIssuerProductIdAnyOf()
			{
				ArrayList<Short> sgxEnclIssuerProdIdAnyOf = new ArrayList<Short>();
				for (Short obj : this.sgxEnclaveIssuerProductIdAnyOf)
					sgxEnclIssuerProdIdAnyOf.add(obj);
				return sgxEnclIssuerProdIdAnyOf;
			}

		protected void setSgxEnclaveIssuerProductIdAnyOf(ArrayList<Short> sgxEnclIssuerProdIdAnyOf)
		{
			for (Short obj : sgxEnclIssuerProdIdAnyOf)
				this.sgxEnclaveIssuerProductIdAnyOf.add(obj);
		}

		@JsonProperty("sgx_enclave_issuer_extended_product_id_anyof")
			public ArrayList<String> getSgxEnclaveIssuerExtendedProductIdAnyOf()
			{
				ArrayList<String> sgxEnclIssuerExtProdIdAnyOf = new ArrayList<String>();
				for (String obj : this.sgxEnclaveIssuerExtendedProductIdAnyOf)
					sgxEnclIssuerExtProdIdAnyOf.add(obj);
				return sgxEnclIssuerExtProdIdAnyOf;
			}

		protected void setSgxEnclaveIssuerExtendedProductIdAnyOf(ArrayList<String> sgxEnclIssuerExtProdIdAnyOf)
		{
			for (String obj : sgxEnclIssuerExtProdIdAnyOf)
				this.sgxEnclaveIssuerExtendedProductIdAnyOf.add(obj);
		}

		@JsonProperty("sgx_enclave_measurement_anyof")
			public ArrayList<String> getSgxEnclaveMeasurementAnyOf()
			{
				ArrayList<String> sgxEnclMeasureAnyOf = new ArrayList<String>();
				for (String obj : this.sgxEnclaveMeasurementAnyOf)
					sgxEnclMeasureAnyOf.add(obj);
				return sgxEnclMeasureAnyOf;
			}

		protected void setSgxEnclaveMeasurementAnyOf(ArrayList<String> sgxEnclMeasureAnyOf)
		{
			for (String obj : sgxEnclMeasureAnyOf)
				this.sgxEnclaveMeasurementAnyOf.add(obj);
		}

		protected void setSgxEnclaveSvnMinimum(Short sgxEnclaveSvnMin)
		{
			this.sgxEnclaveSvnMinimum = sgxEnclaveSvnMin;
		}

		@JsonProperty("sgx_enclave_svn_minimum")
			public Short getSgxEnclaveSvnMinimum()
			{
				return this.sgxEnclaveSvnMinimum;
			}

		protected void setSgxConfigIdAnyOf(ArrayList<String> sgxConfIdAnyOf)
		{
			for (String obj : sgxConfIdAnyOf)
				this.sgxConfigIdAnyOf.add(obj);
		}

		@JsonProperty("sgx_config_id_anyof")
			public ArrayList<String> getSgxConfigIdAnyOf()
			{
				ArrayList<String> sgxConfIdAnyOf = new ArrayList<String>();
				for (String obj : this.sgxConfigIdAnyOf)
					sgxConfIdAnyOf.add(obj);
				return sgxConfIdAnyOf;
			}

		protected void setSgxConfigIdSvn(Short sgxConfIdSvn)
		{
			this.sgxConfigIdSvn = sgxConfIdSvn;
		}

		@JsonProperty("sgx_config_id_svn")
			public Short getSgxConfigIdSvn()
			{
				return this.sgxConfigIdSvn;
			}

		@JsonProperty("kpt2_issuer_anyof")
			public ArrayList<String> getKpt2IssuerAnyOf()
			{
				ArrayList<String> kpt2IssuerAnyOf = new ArrayList<String>();
				for (String obj : this.kpt2IssuerAnyOf)
					kpt2IssuerAnyOf.add(obj);
				return kpt2IssuerAnyOf;
			}

		protected void setKpt2IssuerAnyOf(ArrayList<String> kpt2IssuerAnyOf)
		{
			for (String obj : kpt2IssuerAnyOf)
				this.kpt2IssuerAnyOf.add(obj);
		}

		@JsonProperty("tls_client_certificate_issuer_cn_anyof")
			public ArrayList<String> getTlsClientCertificateIssuerCNAnyOf()
			{
				ArrayList<String> tlsClientCertIssuerCNAnyOf = new ArrayList<String>();
				for (String obj : this.tlsClientCertificateIssuerCNAnyOf)
					tlsClientCertIssuerCNAnyOf.add(obj);
				return tlsClientCertIssuerCNAnyOf;
			}

		protected void setTlsClientCertificateIssuerCNAnyOf(ArrayList<String> tlsClientCertIssuerCNAnyOf)
		{
			for (String obj : tlsClientCertIssuerCNAnyOf)
				this.tlsClientCertificateIssuerCNAnyOf.add(obj);
		}

		@JsonProperty("tls_client_certificate_san_anyof")
			public ArrayList<String> getTlsClientCertificateSanAnyOf()
			{
				ArrayList<String> tlsClientCertSanAnyOf = new ArrayList<String>();
				for (String obj : this.tlsClientCertificateSanAnyOf)
					tlsClientCertSanAnyOf.add(obj);
				return tlsClientCertSanAnyOf;
			}

		protected void setTlsClientCertificateSanAnyOf(ArrayList<String> tlsClientCertSanAnyOf)
		{
			for (String obj : tlsClientCertSanAnyOf)
				this.tlsClientCertificateSanAnyOf.add(obj);
		}

		@JsonProperty("tls_client_certificate_san_allof")
			public ArrayList<String> getTlsClientCertificateSanAllOf()
			{
				ArrayList<String> tlsClientCertSanAllOf = new ArrayList<String>();
				for (String obj : this.tlsClientCertificateSanAllOf)
					tlsClientCertSanAllOf.add(obj);
				return tlsClientCertSanAllOf;
			}

		protected void setTlsClientCertificateSanAllOf(ArrayList<String> tlsClientCertSanAllOf)
		{
			for (String obj : tlsClientCertSanAllOf)
				this.tlsClientCertificateSanAllOf.add(obj);
		}

		@JsonProperty("attestation_type_anyof")
			public ArrayList<String> getAttestationTypeAnyOf()
			{
				ArrayList<String> attestTypeAnyOf = new ArrayList<String>();
				for (String obj : this.attestationTypeAnyOf)
					attestTypeAnyOf.add(obj);
				return attestTypeAnyOf;
			}

		protected void setAttestationTypeAnyOf(ArrayList<String> attestTypeAnyOf)
		{
			for (String obj : attestTypeAnyOf)
				this.attestationTypeAnyOf.add(obj);
		}

		protected void setCreatedAt(Iso8601Date createdAt)
		{
			this.createdAt = createdAt;
		}

		public Iso8601Date getCreatedAt()
		{
			return this.createdAt;
		}

		public void copyFrom(KeyTransferPolicyAttributes source) {
			super.copyFrom(source);

			this.setKeyTransferPolicyId(source.getKeyTransferPolicyId());

			this.setSgxEnclaveIssuerAnyOf(source.getSgxEnclaveIssuerAnyOf());
			this.setSgxEnclaveIssuerProductIdAnyOf(source.getSgxEnclaveIssuerProductIdAnyOf());
			this.setSgxEnclaveIssuerExtendedProductIdAnyOf(source.getSgxEnclaveIssuerExtendedProductIdAnyOf());
			this.setSgxEnclaveMeasurementAnyOf(source.getSgxEnclaveMeasurementAnyOf());
			this.setSgxEnclaveSvnMinimum(source.getSgxEnclaveSvnMinimum());
			this.setSgxConfigIdAnyOf(source.getSgxConfigIdAnyOf());
			this.setSgxConfigIdSvn(source.getSgxConfigIdSvn());
			this.setKpt2IssuerAnyOf(source.getKpt2IssuerAnyOf());
			this.setTlsClientCertificateIssuerCNAnyOf(source.getTlsClientCertificateIssuerCNAnyOf());
			this.setTlsClientCertificateSanAnyOf(source.getTlsClientCertificateSanAnyOf());
			this.setTlsClientCertificateSanAllOf(source.getTlsClientCertificateSanAllOf());
			this.setAttestationTypeAnyOf(source.getAttestationTypeAnyOf());

			this.setCreatedAt(source.getCreatedAt());
		}
	}
