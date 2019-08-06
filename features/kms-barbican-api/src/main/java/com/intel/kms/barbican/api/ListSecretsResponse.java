/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
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
