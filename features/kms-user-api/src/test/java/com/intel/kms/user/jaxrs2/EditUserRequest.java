/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.user.Contact;
import com.intel.kms.user.User;
import java.security.PublicKey;

/**
 *
 * @author jbuhacoff
 */
public class EditUserRequest extends User {
    public EditUserRequest() {
        super();
    }
    public EditUserRequest(User edited) {
        super();
        setId(edited.getId());
        setUsername(edited.getUsername());
        setContact(edited.getContact());
        setTransferKeyPem(edited.getTransferKeyPem());
    }
    public EditUserRequest(UUID userId, PublicKey transferKey) {
        super();
        setId(userId);
        setUsername(null);
        setContact(null);
        setTransferKey(transferKey);
    }
    public EditUserRequest(UUID userId, Contact contact) {
        super();
        setId(userId);
        setUsername(null);
        setContact(contact);
        setTransferKeyPem(null);
    }
    
}
