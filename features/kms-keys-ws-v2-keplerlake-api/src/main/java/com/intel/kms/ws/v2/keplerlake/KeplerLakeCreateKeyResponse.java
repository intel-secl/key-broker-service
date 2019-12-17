/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.ws.v2.keplerlake;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.intel.kms.api.util.AbstractResponse;
import com.intel.kms.ws.v2.api.Key;
import java.util.List;

/**
 *
 * @author shashank
 */
public class KeplerLakeCreateKeyResponse extends AbstractResponse {
    
    @JsonProperty("data")
    private List<Key> data;
    
    /**
     * @return the data
     */
    public List<Key> getData() {
        return data;
    }

    /**
     * @param data the data to set
     */
    public void setData(List<Key> data) {
        this.data = data;
    }

}
