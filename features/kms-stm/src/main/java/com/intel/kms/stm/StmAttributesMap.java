/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */

package com.intel.kms.stmlib;

import java.util.Map;
import java.util.HashMap;

/**
 * Class represent a map containing Session object corrsponding to a particular session.
 * Key is Session ID.
 * Value is object of KeyTransferSession.
 * @author @rbhat
 */
public class StmAttributesMap {
    static final private Map<String, Map<String, byte[]>> stmAttr = new HashMap<String, Map<String, byte[]>>();

    public void addAttrMapToSession(String key, Map<String, byte[]> value) {
        stmAttr.put(key, value);
    }

    public Map<String, byte[]> getAttrVal(String key) {
        return stmAttr.get(key);
    }

    public boolean containsAttr(String key) {
        return (stmAttr.containsKey(key));
    }
}
