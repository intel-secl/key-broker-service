/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.keystore.tpm;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.keplerlake.io.ByteArrayRepository;
import com.intel.keplerlake.io.FileRepository;
import com.intel.kms.keystore.directory.DirectoryKeyManager;
import com.intel.kms.keystore.directory.JacksonFileRepository;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import java.io.File;
import java.io.IOException;

/**
 *
 * @author jbuhacoff
 */
public class DirectoryTpmSealedKeyManager extends DirectoryKeyManager {
    public DirectoryTpmSealedKeyManager() throws IOException {
        super(getTpmKeyRepository());
    }

    private static TpmKeyRepository getTpmKeyRepository() throws IOException {
        // get configuration sttings
        Configuration configuration = ConfigurationFactory.getConfiguration();
        String pcrlistcsv = configuration.get("tpm.seal.pcrs", "0,17,18,19");
        String[] pcrlist = pcrlistcsv.split(",");
        Integer[] pcrs = new Integer[pcrlist.length];
        for(int i=0; i<pcrlist.length; i++) {
            pcrs[i] = Integer.valueOf(pcrlist[i]);
        }
        // storage location for tpm-sealed master keys
        String masterKeyPath = Folders.repository("tpm-sealed-master-key");
        File masterKeyDirectory = new File(masterKeyPath);
        if( masterKeyDirectory.exists() && masterKeyDirectory.isFile() ) {
            throw new IllegalStateException("File present where directory is expected: "+masterKeyPath);
        }
        if( !masterKeyDirectory.exists() && !masterKeyDirectory.mkdirs() ) {
            throw new IllegalStateException("Failed to create directory: "+masterKeyPath);
        }
        // storage location for master-key wrapped user keys
        String userKeyPath = Folders.repository("keys"); // matches original kms "keys" directory from DirectoryKeyManager
        File userKeyDirectory = new File(userKeyPath);
        if( userKeyDirectory.exists() && userKeyDirectory.isFile() ) {
            throw new IllegalStateException("File present where directory is expected: "+userKeyPath);
        }
        if( !userKeyDirectory.exists() && !userKeyDirectory.mkdirs() ) {
            throw new IllegalStateException("Failed to create directory: "+userKeyPath);
        }
        JacksonFileRepository userKeyRepository = new JacksonFileRepository(userKeyDirectory);
        ByteArrayRepository masterKeyRepository = new FileRepository(masterKeyPath);
        return new TpmKeyRepository(userKeyRepository, masterKeyRepository, pcrs);
    }
    
}
