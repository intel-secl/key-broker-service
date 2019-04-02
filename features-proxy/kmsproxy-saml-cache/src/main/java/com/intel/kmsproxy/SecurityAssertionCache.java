/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy;

import java.io.IOException;

/**
 *
 * @author jbuhacoff
 */
public interface SecurityAssertionCache {
    /**
     * Store the assertion of subject
     * 
     * @param subject
     * @param report 
     */
    public void storeAssertion(String subject, String saml) throws IOException;
}
