/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * The RegisterKeyResponse contains either key attributes and a link to the
 * registered key, or any faults that prevented the key from being registered.
 * The RegisterKeyResponse never includes the created key itself.
 *
 * When successful, the "data" list of the SearchKeyAttributesResponse
 * superclass is populated with the complete set of attributes for the registered
 * key; this will reflect attributes specified by the client (and permitted by
 * policy) as well as any attributes added automatically by the server. The
 * attributes are the same as what would be received if the client were to issue
 * a follow-up request to /keys/{keyId}, and they are provided to allow the
 * client to avoid making the extra request.
 *
 * @author jbuhacoff
 */
public class RegisterKeyResponse extends SearchKeyAttributesResponse {

    public RegisterKeyResponse() {
        super();
    }

    public RegisterKeyResponse(KeyAttributes registered) {
        super();
        getData().add(registered);
    }
}