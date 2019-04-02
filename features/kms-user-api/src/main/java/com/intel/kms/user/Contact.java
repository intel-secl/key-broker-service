/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user;

import com.intel.dcsg.cpg.validation.InputValidator;
import com.intel.dcsg.cpg.validation.Validator;
import org.apache.commons.validator.routines.EmailValidator;

/**
 *
 * @author jbuhacoff
 */
public class Contact {
    private String firstName;
    private String lastName;
    private String emailAddress;

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    @Validator(EmailInputValidator.class)
    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }
    
    public static class EmailInputValidator extends InputValidator<String> {

        @Override
        protected void validate() {
            if( !EmailValidator.getInstance().isValid(getInput()) ) {
                fault("Invalid email");
            }
        }
        
    }
}
