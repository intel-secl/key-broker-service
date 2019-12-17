/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake.exception;

/**
 *
 * @author kchinnax
 */
public class CustomException extends Exception {

    public CustomException(String message) {
        super(message);
    }
    
     public CustomException() {
        super();
    }
    public CustomException(Throwable cause) {
        super(cause);
    }
   
    public CustomException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
