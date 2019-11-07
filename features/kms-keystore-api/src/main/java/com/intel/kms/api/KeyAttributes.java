/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.api;

import com.intel.dcsg.cpg.io.Copyable;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.AsymmetricKey;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.HashSet;

/**
 *
 * @author jbuhacoff
 */
public class KeyAttributes extends CipherKeyAttributes implements Copyable {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyAttributes.class);

    private String username;
    private String transferPolicy;
    private String usagePolicy;
    private URL transferLink;
    private URL usageLink;
    private String ckaLabel;
    private String createdDate;
    private String operation;
    private String status;
    private String keyType;
    private byte[] publicKey;
    private String curveType;
    static final public List<String> allowedAlgorithms = Arrays.asList("AES", "RSA", "EC");
    static final public List<String> allowedCurveTypes = Arrays.asList("secp256k1", "secp384r1", "secp521r1", "prime256v1");

    /**
     * Optional user-provided description of the key.
     */
    private String description;

    /**
     * Optional user-provided role name indicates the use of the key. For
     * example: data encryption, key encryption, signatures, key derivation
     */
    private String role;

    /**
     * Digest algorithm used in conjunction with this key. Optional.
     */
    private String digestAlgorithm;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * URI of a transfer policy to apply to this key. The KMS requires a
     * transfer policy for every key but may support a default policy for new
     * key requests which omit this attribute and/or a global (fixed) policy for
     * all key requests (where specifying the attribute would be an error
     * because it would be ignored). The policy itself is a separate document
     * that describes who may access the key under what conditions (trusted,
     * authenticated, etc)
     *
     * Example: urn:intel:trustedcomputing:keytransferpolicy:trusted might
     * indicate that a built-in policy will enforce that the key is only
     * released to trusted clients, and leave the definition of trusted up to
     * the trust attestation server.
     *
     * Example: http://fileserver/path/to/policy.xml might indicate that the
     * fileserver has a file policy.xml which is signed by this keyserver and
     * contains the complete key transfer policy including what is a trusted
     * client, what is the attestation server trusted certificate, etc.
     *
     */
    public String getTransferPolicy() {
        return transferPolicy;
    }
    public String getUsagePolicyID() {
        return usagePolicy;
    }

    public void setTransferPolicy(String transferPolicy) {
        this.transferPolicy = transferPolicy;
    }
    public void setUsagePolicyID(String usagePolicy) {
        this.usagePolicy = usagePolicy;
    }

    public URL getTransferLink() {
        return transferLink;
    }

    public URL getUsageLink() {
        return usageLink;
    }

    public void setTransferLink(URL transferLink) {
        this.transferLink = transferLink;
    }

    public void setUsageLink(URL usageLink) {
        this.usageLink = usageLink;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getCkaLabel() {
        return ckaLabel;
    }

    public void setCkaLabel(String ckaLabel) {
        this.ckaLabel = ckaLabel;
    }

    public String getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(String createdDate) {
        this.createdDate = createdDate;
    }
    
    public String getOperation() { 
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }
    
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] key) {
        this.publicKey = key;
    }

    public String  getCurveType() {
        return curveType;
    }

    public void setCurveType(String curveType) {
        this.curveType = curveType;
    }

    @Override
    public KeyAttributes copy() {
        KeyAttributes newInstance = new KeyAttributes();
        newInstance.copyFrom(this);
        return newInstance;
    }

    public void copyFrom(KeyAttributes source) {
        super.copyFrom(source);
        log.debug("Copying algorithm {} from source", source.getAlgorithm());
        this.setAlgorithm(source.getAlgorithm());
        this.setMode(source.getMode());
        this.setKeyLength(source.getKeyLength());
        this.setPaddingMode(source.getPaddingMode());
        this.digestAlgorithm = source.digestAlgorithm;
        this.username = source.username;
        this.description = source.description;
        this.role = source.role;
        this.transferPolicy = source.transferPolicy;
        this.transferLink = source.transferLink;
        this.setUsagePolicyID(source.getUsagePolicyID());
        this.setCkaLabel(source.getCkaLabel());
        this.createdDate = source.getCreatedDate();
        this.publicKey = source.getPublicKey();
        this.curveType = source.getCurveType();
    }

    public void copyFrom(CipherKeyAttributes source) {
        this.setAlgorithm(source.getAlgorithm());
        this.setMode(source.getMode());
        this.setKeyLength(source.getKeyLength());
        this.setPaddingMode(source.getPaddingMode());
        this.setKeyId(source.getKeyId());
        if (source instanceof AsymmetricKey) {
            this.setPublicKey(((AsymmetricKey)source).getPublicKey());
            this.setCurveType(((AsymmetricKey)source).getCurveType());
        }

        // copy user-defined attributes except the ones we handle specifically below
        HashSet<String> knownAttributes = new HashSet<>();
        knownAttributes.addAll(Arrays.asList(new String[] { "transferPolicy", "transferLink","usage_policy" }));
        HashSet<String> extendedAttributes = new HashSet<>();
        extendedAttributes.addAll(source.map().keySet());
        extendedAttributes.removeAll(knownAttributes);
        for( String attr : extendedAttributes) {
            log.debug("Copying extended attribute: {}", attr);
            attributes.put(attr, source.get(attr));
        }
        
        // special handling for these user-defined attributes
        Object transferPolicyObject = source.get("transferPolicy");
        if (transferPolicyObject != null && transferPolicyObject instanceof String) {
            log.debug("copyFrom transferPolicy {}", source.get("transferPolicy"));
            this.setTransferPolicy((String) source.get("transferPolicy"));
        }
        if (source.get("transferLink") != null) {
            Object transferLinkObject = source.get("transferLink");
            if (transferLinkObject != null) {
                if (transferLinkObject instanceof URL) {
                    this.setTransferLink((URL) transferLinkObject);
                } else if (transferLinkObject instanceof String) {
                    try {
                        this.setTransferLink(new URL((String) transferLinkObject));
                    } catch (MalformedURLException e) {
                        log.error("Cannot set transfer policy for key", e);
                    }
                } else {
                    log.debug("copyFrom transferLink object class {} value {}", transferLinkObject.getClass().getName(), transferLinkObject.toString());
                }
            } else {
                log.debug("copyFrom transferLink is null");
            }
        }

	Object usagePolicyObject = source.get("usage_policy");
	if (usagePolicyObject!= null && usagePolicyObject instanceof String) {
	    log.debug("copyFrom usagePolicy{}", source.get("usage_policy"));
	    this.setUsagePolicyID((String) source.get("usage_policy"));
	}

	Object ckaLabelObject = source.get("ckaLabel");
	if (ckaLabelObject!= null && ckaLabelObject instanceof String) {
	    log.debug("copyFrom ckaLabelObject{}", source.get("ckaLabel"));
	    this.setCkaLabel((String) source.get("ckaLabel"));
	}

	Object createdDateObject = source.get("createdAt");
	if (createdDateObject != null && createdDateObject instanceof String) {
	    log.debug("copyFrom createdAt{}", source.get("createdAt"));
	    this.setCreatedDate((String) source.get("createdAt"));
	}
    }
}
