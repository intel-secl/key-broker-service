/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.ws.v2.api;

import com.intel.dcsg.cpg.validation.Regex;
import com.intel.mtwilson.jaxrs2.AbstractDocument;
import java.net.URL;

/**
 *
 * @author jbuhacoff
 */
public class Key extends AbstractDocument {
    private String algorithm;
    private Integer keyLength;
    private String mode;
    private String paddingMode;
    private String username;
    private String transferPolicy;
    private String usagePolicy;
    private URL transferLink;
    private URL usageLink;
    private String description;
    private String role;
    private String digestAlgorithm;
    private String kmipId;
    private String ckaLabel;
    private String createdDate;
    private byte[] publicKey;
    private String privateKey;
    private String curveType;

    @Regex("[a-zA-Z0-9_-]+")
    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    @Regex("[a-zA-Z0-9_-]+")
    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getPaddingMode() {
        return paddingMode;
    }

    public void setPaddingMode(String paddingMode) {
        this.paddingMode = paddingMode;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Regex("[a-zA-Z0-9/,:_-]*")
    public String getTransferPolicy() {
        return transferPolicy;
    }

    public void setTransferPolicy(String transferPolicy) {
        this.transferPolicy = transferPolicy;
    }

    public URL getTransferLink() {
        return transferLink;
    }

    public void setTransferLink(URL transferLink) {
        this.transferLink = transferLink;
    }

    @Regex("[a-zA-Z0-9/,:_-]*")
    public String getUsagePolicy() {
	return usagePolicy;
    }

    public void setUsagePolicy(String usagePolicy) {
	this.usagePolicy = usagePolicy;
    }

    public URL getUsageLink() {
	return usageLink;
    }

    public void setUsageLink(URL usageLink) {
	this.usageLink = usageLink;
    }
    
    public String getDescription() {
        return description;
    }

    @Regex("[a-zA-Z0-9 \\r\\n/,:_-]*")
    public void setDescription(String description) {
        this.description = description;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getKmipId() {
        return kmipId;
    }

    @Regex("[a-zA-Z0-9 \\r\\n/,:_-]*")
    public void setKmipId(String kmipId) {
        this.kmipId = kmipId;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getCkaLabel() {
        return ckaLabel;
    }

    public String getCreatedDate() {
        return createdDate;
    }

    public void setCkaLabel(String ckaLabel) {
        this.ckaLabel = ckaLabel;
    }

    public void setCreatedDate(String createdDate) {
        this.createdDate = createdDate;
    }

    public void setPublicKey(byte[] key) {
        this.publicKey = key;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    @Regex("(?s).*")
    public String getPrivateKey() {
	return privateKey;
    }

    public void setPrivateKey(String key) {
	this.privateKey = key;
    }

    public void setCurveType(String curveType) {
        this.curveType = curveType;
    }

    @Regex("[a-zA-Z0-9]*")
    public String getCurveType() {
        return curveType;
    }
}
