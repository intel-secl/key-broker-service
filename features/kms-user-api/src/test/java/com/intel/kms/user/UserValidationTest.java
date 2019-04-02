/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.validation.ValidationUtil;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class UserValidationTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(UserValidationTest.class);

    @Test
    public void testUserValidation() throws NoSuchAlgorithmException {
        KeyPair keypair = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE);
        User user = new User();
        user.setId(new UUID());
        user.setUsername(RandomUtil.randomHexString(8));
        user.setTransferKeyPem(RsaUtil.encodePemPublicKey(keypair.getPublic()));
        ValidationUtil.validate(user);
    }
}
