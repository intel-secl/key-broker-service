/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
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
