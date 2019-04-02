/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import javax.ws.rs.HeaderParam;

/**
 * Represents message body for {@code POST v1/secrets}
 * 
 * https://github.com/cloudkeep/barbican/wiki/Application-Programming-Interface
 * 
 * @author jbuhacoff
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegisterSecretRequest {
    @HeaderParam("X-Project-Id")
    public String projectId; // from header X-Project-Id: {project_id}
    public String name; // "AES key"
    public String expiration; // "2014-02-28T19:14:44.180394"
    public String algorithm; // "aes"
    public Integer bit_length; // 256
    public String mode; // "cbc"
    public String payload;
    public String payload_content_type; // "application/octet-stream"    
    public String payload_content_encoding ; // "application/octet-stream"
    public String secretType; // "opaque"
    
}
