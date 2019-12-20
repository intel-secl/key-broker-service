/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs;

import com.intel.kms.user.User;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.repository.Locator;
import javax.ws.rs.PathParam;

/**
 *
 * @author jbuhacoff
 */
public class UserLocator implements Locator<User>{

    @PathParam("id")
    public UUID id;

    @Override
    public void copyTo(User item) {
        if( id != null ) {
            item.setId(id);
        }
    }
    
}
