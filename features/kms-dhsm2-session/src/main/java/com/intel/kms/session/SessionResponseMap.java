/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.kms.dhsm2.sessionManagement;

import java.util.Map;
import java.util.HashMap;

/**
 * Class represent a map containing Session object corrsponding to a particular session.
 * Key is Session ID.
 * Value is object of KeyTransferSession.
 * @author @srajen4x
 */
public class SessionResponseMap {
    static final private Map<String, QuoteVerifyResponseAttributes> stmAttr = new HashMap<String, QuoteVerifyResponseAttributes>();

    public void addAttrMapToSession(String key, QuoteVerifyResponseAttributes value) {
        stmAttr.put(key, value);
    }

    public QuoteVerifyResponseAttributes getAttrVal(String key) {
        return stmAttr.get(key);
    }

    public boolean containsAttr(String key) {
        return (stmAttr.containsKey(key));
    }
}
