/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore.directory.cmd;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.console.InteractiveCommand;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.kms.keystore.directory.EnvelopeKeyManager;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.util.List;
/**
 * Usage:
 * 
 * "kms envelope-keystore list" will display a list of envelope key ids
 * 
 * @author jbuhacoff
 */
public class EnvelopeKeystore extends InteractiveCommand {
    private String keystorePath;
    private String keystoreType;
    private File keystoreFile;
    private String keystorePasswordAlias;
    private Password keystorePassword;
    private Configuration configuration;

    @Override
    public void execute(String[] args) throws Exception {
        configuration = ConfigurationFactory.getConfiguration();
        if( args != null && args.length > 0 && args[0].equals("list") ) {
            list();
        }
        else {
            // print only base64-encoded key 
            System.err.println("Usage: kms envelope-keystore list");
        }
    }
    

    private void list() throws IOException, KeyStoreException {
        // from configure() method of EnvelopeKey setup task:
        keystorePath = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "envelope.p12");
        keystoreType = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_TYPE_PROPERTY, EnvelopeKeyManager.ENVELOPE_DEFAULT_KEYSTORE_TYPE);
        keystorePasswordAlias = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_PASSWORD_PROPERTY, "envelope_keystore");

        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                keystorePassword = passwordVault.get(keystorePasswordAlias);
            }
            keystoreFile = new File(keystorePath);
        }
        try (EnvelopeKeyManager envelopeKeyManager = new EnvelopeKeyManager(keystoreType, keystoreFile, keystorePassword.toCharArray())) {
            // list the aliases
            List<String> aliases = envelopeKeyManager.getKeystore().aliases();
            for(String alias : aliases) {
                System.out.println(alias);
            }
        }        
    }
    
}
