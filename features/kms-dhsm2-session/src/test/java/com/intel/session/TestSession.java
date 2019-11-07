/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */

package com.intel.kms.session.TestSession;

import java.io.IOException;
import org.junit.Test;
import static org.junit.Assert.*;
import com.intel.dcsg.cpg.validation.Fault;
import java.util.List;

import com.intel.kms.dhsm2.sessionManagement.*;

    /**
     * @author skamal
     */
    public class TestSession {
        private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TestSession.class);
        /**
         * @throws IOException
         */
        @Test
        public void testValidInput () throws IOException {
            SessionManagement s1 = new SessionManagement();
            log.debug("in try block of junit");
            String str = "{" +
                    "\"certificate_chain\":\"HELLO1234\",\n" +
                    "\"challenge_type\":\"HELLO1234\",\n" +
                    "\"challenge\":\"HELLO1234\",\n" +
                    "\"quote\":\"Intel-SGX                                                                                           -----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzM6ujJ8EUrlyP/7DO6PH\\nOqG7QFz49zs/TF3mzPBZziZ3fjmw9oqzYzp2zhYOLFZefaH0z+42g5ebUrwjdgUJ\\nNkhzFxSWmK3ZU1qpWIE9soPfmQSGdR63gP/wydRAB3oal8lMSmJGqNc7PdToyaZl\\nipC8eSvB5kA5tx4efpEr+8D17J43CNxE4ylP1kAOO7MMOzlzRFbBFsoCg3mHelGf\\nJXn9D7AO3YWDPofXADvjcYmjT/F90lLBULaMpWtqUHTlI+yJfcGDNRdvniD4bj2Y\\nQByg4rM7OE4AgqsWcsI4aJ5f0+JTAoauHe5gSrY6WrjA54jHRELZZvEJL0x6YLYt\\n4wIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
                    "}\n";
            List<Fault> l1 = s1.validateSessionCreationRequest(str);
            log.debug("errors: {}", l1.size());
           assertTrue(l1.isEmpty());
           }

           /**
            * @throws IOException
            */
        @Test
        public void testInValidInput () throws IOException {
            SessionManagement s1 = new SessionManagement();
            String str = "{" +
                    "\"challenge_type\":\"HELLO1234\",\n" +
                    "\"challenge\":\"HELLO1234\",\n" +
                    "\"quote\":\"Intel-SGX                                                                                           -----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzM6ujJ8EUrlyP/7DO6PH\\nOqG7QFz49zs/TF3mzPBZziZ3fjmw9oqzYzp2zhYOLFZefaH0z+42g5ebUrwjdgUJ\\nNkhzFxSWmK3ZU1qpWIE9soPfmQSGdR63gP/wydRAB3oal8lMSmJGqNc7PdToyaZl\\nipC8eSvB5kA5tx4efpEr+8D17J43CNxE4ylP1kAOO7MMOzlzRFbBFsoCg3mHelGf\\nJXn9D7AO3YWDPofXADvjcYmjT/F90lLBULaMpWtqUHTlI+yJfcGDNRdvniD4bj2Y\\nQByg4rM7OE4AgqsWcsI4aJ5f0+JTAoauHe5gSrY6WrjA54jHRELZZvEJL0x6YLYt\\n4wIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
                    "}\n";
            List<Fault> l1 = s1.validateSessionCreationRequest(str);
            log.debug("errors: {}", l1.size());
            assertFalse(l1.isEmpty());
            }
     }
