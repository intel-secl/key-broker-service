/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake;

/**
 *
 * @author nallux
 */
public class CreateUserRequest {

    String userID = "";
    String email = "";
    
    String password = "";

    public void setEmail(String iEmail) {
        this.email = iEmail;
    }

    public void setPassword(String iPassword) {
        this.password = iPassword;
    }

    public String getEmail() {
        return this.email;
    }

    public String getPassword() {
        return this.password;
    }
     public String getUserID() {
        return this.userID;
    }

    public void setUserID(String iUserID) {
         this.userID = iUserID;
    }
}
