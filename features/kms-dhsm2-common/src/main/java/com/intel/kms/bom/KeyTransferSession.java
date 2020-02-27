/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.kms.dhsm2.common.CommonSession;

/**
 * Class represents Client Session Information including:
 * session_id: Unique identifier of session, set to challenge issued by STM
 * client_cert_hash: SHA256 hash of Client X509 Certificate
 * SWK: AES256 symmetric wrapping key, which will be used to wrap requested application keys
 * @author @shefalik 
 */
public class KeyTransferSession {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyTransferSession.class);
    private byte[] SWK;
    private String client_cert_hash;
    private String session_id;
    private String stmLabel;

    public void setSWK(byte[] SWKKey) {
        this.SWK = SWKKey;
    }

    public byte[] getSWK() {
        return SWK;
    }

    public void setClientCertHash(String clientCertHash) {
        this.client_cert_hash = clientCertHash;
    }

    public String getClientCertHash() {
        return client_cert_hash;
    }

    public void setSessionId(String sessionID) {
        this.session_id = sessionID;
    }

    public String getSessionId() {
        return session_id;
    }

    public void setStmLabel(String stmLabel) {
        this.stmLabel = stmLabel;
    }

    public String getStmLabel() {
        return stmLabel;
    }
}
