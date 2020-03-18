/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.kmip.exception;

public class KMIPClientException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    public KMIPClientException() {
    }

    public KMIPClientException(String message) {
        super(message);
    }

    public KMIPClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public KMIPClientException(Throwable cause) {
        super(cause);
    }

    public KMIPClientException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
