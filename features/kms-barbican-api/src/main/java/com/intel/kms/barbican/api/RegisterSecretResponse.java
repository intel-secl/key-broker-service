/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.barbican.api;

/**
 * Reponse to {@code POST v1/secrets}
 * 
 * https://github.com/cloudkeep/barbican/wiki/Application-Programming-Interface
 *
 * @author jbuhacoff
 */
public class RegisterSecretResponse {
    public String secret_ref; // URL "http://localhost:8080/v1/secrets/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718"
}
