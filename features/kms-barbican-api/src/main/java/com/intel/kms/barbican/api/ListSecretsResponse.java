/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public class ListSecretsResponse {
    public Integer total;
    public String next;
    public List<GetSecretResponse> secrets;
}
