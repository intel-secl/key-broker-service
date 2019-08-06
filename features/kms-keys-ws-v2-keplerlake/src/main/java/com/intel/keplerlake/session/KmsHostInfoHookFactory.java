/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.keplerlake.session;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import java.io.IOException;

/**
 *
 * @author jbuhacoff
 */
public class KmsHostInfoHookFactory implements HostInfoHookFactory {
    @Override
    public HostInfoHook newHostInfoHookInstance() throws IOException {
        Configuration configuration = ConfigurationFactory.getConfiguration();
        return new KmsHostInfoHook(configuration);
    }
}
