/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Random;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jbuhacoff
 */
public class TransferSecretResponseTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransferSecretResponseTest.class);

    /*
    @JsonValue
    public byte[] toByteArray() {
        return secret;
    }
     * 
     * 
     * 
    @Test
    public void testJsonUnwrappedByteArray() throws JsonProcessingException {
        TransferSecretResponse response = new TransferSecretResponse();
        response.secret = new byte[16]; 
        Random random = new Random();
        random.nextBytes(response.secret);
        log.debug("secret: {}", response.secret);
        ObjectMapper mapper = new ObjectMapper();
        String responseText = mapper.writeValueAsString(response); // {"secret":"6SAxzss6DYMz1ytEqSt7lQ=="}
        byte[] responseBytes = mapper.writeValueAsBytes(response);
        log.debug("response text: {}", responseText);
        log.debug("response bytes: {}", responseBytes);
        assertArrayEquals(response.secret, responseBytes);
    }
    */
}
