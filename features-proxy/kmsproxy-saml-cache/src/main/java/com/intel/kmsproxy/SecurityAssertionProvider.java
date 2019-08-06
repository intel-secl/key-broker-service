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
public interface SecurityAssertionProvider {
    /**
     * 
     * @param subject
     * @return the SAML assertion if there is a current one available, or null if there is no assertion or the stored assertion is expired
     */
    String getAssertionForSubject(String subject) throws IOException;
}
