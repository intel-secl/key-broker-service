/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
