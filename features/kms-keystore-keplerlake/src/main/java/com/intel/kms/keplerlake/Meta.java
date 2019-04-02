/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.keplerlake;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author sshekhex
 */
public class Meta {
    private final Map<String, Object> meta = new HashMap();

    @JsonAnyGetter
    public Map<String, Object> any() {
        return meta;
    }

    @JsonAnySetter
    public void set(String name, Object value) {
        meta.put(name, value);
    }
}
