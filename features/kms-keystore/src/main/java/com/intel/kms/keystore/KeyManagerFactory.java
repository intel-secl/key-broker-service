/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.api.KeyManager;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import java.io.IOException;


/**
 *
 * @author jbuhacoff
 */
public class KeyManagerFactory {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyManagerFactory.class);
    private static KeyManager keyManager;
    private static Configuration configuration;
    
    public static KeyManager getKeyManager() throws IOException, ReflectiveOperationException {
        if( configuration == null ) {
            configuration = ConfigurationFactory.getConfiguration();
        }
        if (keyManager == null) {
            /**
             * get the key repository "driver" since there can be only one
             * configured key repository: local directory, kmip, or barbican.
             * it's a global setting.
             */
            Class delegateClass = Class.forName(configuration.get("key.manager.provider", "com.intel.kms.keystore.directory.DirectoryKeyManager"));
            KeyManager delegate = (KeyManager) delegateClass.newInstance();
            log.debug("KeyManager class: {}", delegate.getClass().getName());
            // wrap the key manager with a RemoteKeyManager which will properly wrap the key for TransferKeyResponse
            keyManager = new RemoteKeyManager(delegate);
        }
        return keyManager;
    }
    
}
