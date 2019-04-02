/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.user.jaxrs2.CreateRequest;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class UserJacksonTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(UserJacksonTest.class);
    private static ObjectMapper mapper = new ObjectMapper();
    
    @Test
    public void testCreateUser() throws JsonProcessingException {
        Contact contact = new Contact();
        contact.setFirstName("first");
        contact.setLastName("last");
        contact.setEmailAddress("email@example.com");
        User user = new User();
        user.setId(new UUID());
        user.setUsername(RandomUtil.randomHexString(8));
        user.setContact(contact);
        CreateRequest<User> request = new CreateRequest<>(user);
        log.debug("create request: {}", mapper.writeValueAsString(request));
        // create request: {"id":"88c917a3-af66-402b-b4cd-4be538f1c85f","username":"209917b7f7d69377","contact":{"firstName":"first","lastName":"last","emailAddress":"email@example.com"},"transferKeyPem":null}
    }
}
