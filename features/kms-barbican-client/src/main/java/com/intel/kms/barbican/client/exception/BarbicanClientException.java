package com.intel.kms.barbican.client.exception;

public class BarbicanClientException extends Exception {

    public BarbicanClientException() {
    }

    public BarbicanClientException(String message) {
        super(message);
    }

    public BarbicanClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public BarbicanClientException(Throwable cause) {
        super(cause);
    }

    public BarbicanClientException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
