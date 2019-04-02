/*
 * Copyright 2016 Intel Corporation. All rights reserved.
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
