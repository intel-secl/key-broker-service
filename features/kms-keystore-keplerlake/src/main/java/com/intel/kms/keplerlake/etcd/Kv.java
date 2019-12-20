/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake.etcd;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author kchinnax
 */
public class Kv {

    private String key;
    
    @JsonProperty("create_revision")
    private Integer createRevision;
    @JsonProperty("mod_revision")
    private Integer modRevision;
    private Integer version;
    
    private String value;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public Integer getCreateRevision() {
        return createRevision;
    }

    public void setCreateRevision(Integer createRevision) {
        this.createRevision = createRevision;
    }

    public Integer getModRevision() {
        return modRevision;
    }

    public void setModRevision(Integer modRevision) {
        this.modRevision = modRevision;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

}
