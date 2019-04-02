/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author jbuhacoff
 */
public class GetSecretResponse {
    public String status; // "ACTIVE"
    public String secret_type; // "symmetric"
    public String updated; // "2013-06-28T15:23:33.092660"
    public String name; // "AES key"
    public String created; // "2013-06-28T15:23:33.092660"
    public String algorithm; // "AES"
    public String mode; // "cbc"
    public Integer bit_length; // 256
    public Map<String, String> content_types; // { default: "application/octet-stream" }
    public String expiration; // "2013-05-08T16:21:38.134160"
    public String secret_ref; // URL "http://localhost:8080/v1/secrets/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718"
    public String creator_id;
}