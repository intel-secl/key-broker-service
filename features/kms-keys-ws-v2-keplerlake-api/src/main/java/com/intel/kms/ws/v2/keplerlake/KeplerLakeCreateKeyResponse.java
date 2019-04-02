/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
