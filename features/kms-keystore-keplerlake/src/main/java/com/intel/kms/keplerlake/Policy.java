/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author nallux
 */
public class Policy implements Serializable {

    @JsonProperty("meta")
    private Meta meta;

    @JsonProperty("label")
    private String label;

    @JsonProperty("description")
    private String description;

    @JsonProperty("validity")
    private Map<String, String> validity;

    @JsonProperty("permission")
    private LinkedHashMap<?, ?> permissions;

    @JsonProperty("allOf")
    private List<PolicyUri> allOf;

    public List<PolicyUri> getAllOf() {
        return allOf;
    }

    public void setAllOf(List<PolicyUri> allOf) {
        this.allOf = allOf;
    }

    public LinkedHashMap<?, ?> getPermissions() {
        return permissions;
    }

    public void setPermissions(LinkedHashMap<?, ?> permissionsList) {
        this.permissions = permissionsList;
    }

    public Meta getMeta() {
        return meta;
    }

    public void setMeta(Meta meta) {
        this.meta = meta;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Map<String, String> getValidity() {
        return validity;
    }

    public void setValidity(Map<String, String> validity) {
        this.validity = validity;
    }

}
