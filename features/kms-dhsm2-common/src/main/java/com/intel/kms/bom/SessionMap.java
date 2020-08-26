/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.common.CommonSession;

import java.util.Map;
import java.util.HashMap;

/**
 * Class represent a map containing Session object corrsponding to a particular session.
 * Key is Session ID.
 * Value is object of KeyTransferSession.
 * @author @shefalik 
 */
public class SessionMap {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SessionMap.class);
    static final private Map<String, KeyTransferSession> SessionMapObj = new HashMap<String, KeyTransferSession>();

    public void addSession(String key, KeyTransferSession value) {
        SessionMapObj.put(key, value);
    }

    public KeyTransferSession getObject(String key) {
        return SessionMapObj.get(key);
    }
 
    public boolean containsSession(String key) {
        return (SessionMapObj.containsKey(key));
    }
    public static Map<String, KeyTransferSession> getMap() {
        return SessionMapObj;
   }
}
