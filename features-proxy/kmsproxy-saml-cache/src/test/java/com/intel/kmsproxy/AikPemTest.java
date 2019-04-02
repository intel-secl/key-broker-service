/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy;

import com.intel.dcsg.cpg.io.pem.Pem;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class AikPemTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AikPemTest.class);

    @Test
    public void testParsePemFile() throws IOException {
        try(InputStream in = getClass().getResourceAsStream("/aik.pem")) {
            String text = IOUtils.toString(in, Charset.forName("UTF-8"));
            Pem pem = Pem.valueOf(text);
            log.debug("pem: {}", pem.toString());
        }
    }
}
