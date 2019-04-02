/*
 * Copyright (C) 2015 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.extensions.Plugins;
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
    
    public static KeyManager getKeyManager() throws IOException {
        if( configuration == null ) {
            configuration = ConfigurationFactory.getConfiguration();
        }
        if (keyManager == null) {
            /**
             * get the key repository "driver" since there can be only one
             * configured key repository: local directory, kmip, or barbican.
             * it's a global setting.
             */
            //keyManager = Extensions.require(KeyManager.class);
            KeyManager delegate = Plugins.findByAttribute(KeyManager.class, "class.name", configuration.get("key.manager.provider", "com.intel.kms.keystore.directory.DirectoryKeyManager"));
            log.debug("KeyManager class: {}", delegate.getClass().getName());
            // wrap the key manager with a RemoteKeyManager which will properly wrap the key for TransferKeyResponse
            keyManager = new RemoteKeyManager(delegate);
        }
        return keyManager;
    }
    
}
