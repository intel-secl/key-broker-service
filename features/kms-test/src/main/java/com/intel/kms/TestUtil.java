/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms;

import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 *
 * @author jbuhacoff
 */
public class TestUtil {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TestUtil.class);
    
    public static void defineTest() throws IOException {
        String testId = RandomUtil.randomHexString(4);
        File testdir = new File("target"+File.separator+"test-data"+File.separator+testId);
        log.debug("Test directory: {}", testdir.getAbsolutePath());
        testdir.mkdirs();
        
        System.setProperty("mtwilson.environment.prefix", "TEST_"+testId+"_");
        System.setProperty("mtwilson.application.id", "test-"+testId);
        System.setProperty("mtwilson.configuration.file", "test.properties");
        System.setProperty("test-"+testId+".home", testdir.getAbsolutePath());
        
        // configuration
        File configurationFile = ConfigurationFactory.getConfigurationFile();
        configurationFile.getParentFile().mkdirs();
        
        log.debug("Test configuration file: {}", configurationFile.getAbsolutePath());
        // create a configuration file with the test id as the password vault key
        PropertiesConfiguration testconfig = new PropertiesConfiguration();
        testconfig.set("password.vault.key", testId);
        
        try(FileOutputStream out = new FileOutputStream(configurationFile)) {
            testconfig.getProperties().store(out, String.format("test id: %s", testId));
        }
        
    }
}
