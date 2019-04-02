/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * The CreateKeyResponse contains either key attributes and a link to the
 * created key, or any faults that prevented the key from being created. The
 * CreateKeyResponse never includes the created key itself.
 *
 * When successful, the "data" list of the SearchKeyAttributesResponse
 * superclass is populated with the complete set of attributes for the created
 * key; this will reflect attributes specified by the client (and permitted by
 * policy) as well as any attributes added automatically by the server. The
 * attributes are the same as what would be received if the client were to issue
 * a follow-up request to /keys/{keyId}, and they are provided to allow the
 * client to avoid making the extra request.
 *
 * @author jbuhacoff
 */
public class CreateKeyResponse extends SearchKeyAttributesResponse {

    public CreateKeyResponse() {
        super();
    }

    public CreateKeyResponse(KeyAttributes created) {
        super();
        getData().add(created);
    }
}
