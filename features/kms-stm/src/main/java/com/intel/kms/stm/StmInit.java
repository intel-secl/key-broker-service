/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.stmlib;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.ValveConfiguration;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.sun.jna.NativeLibrary;
import com.sun.jna.ptr.PointerByReference;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.setup.faults.FileNotFound;
import java.io.File;
import java.io.StringReader;
import java.util.Properties;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.Charset;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author rbhat
 */
public class StmInit extends AbstractSetupTask {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StmInit.class);
    public static final String CHALLENGE_TYPE = "dhsm2.challenge.type";
 
    private Configuration file;
    private Configuration environment;
    private String setting;
    private File stmIniFile;
    private static final int KEYSERVER_STM_MODE = 2;
    private String confDir;

    public StmInit() {
        super();
        setting = CHALLENGE_TYPE;
    }

    protected void setConfigDir(String confDir)
    {
	this.confDir = confDir;
    }

    public String getconfigDir()
    {
	return this.confDir;
    }

    @Override
    protected void configure() throws Exception {
        environment = getConfiguration();
        if( environment instanceof ValveConfiguration ) {
            file = ((ValveConfiguration)environment).getWriteTo();
        }
        else {
            file = ConfigurationFactory.getConfiguration();
        }
        stmIniFile = new File(Folders.configuration() + File.separator + "stm.ini");
        if (!stmIniFile.exists()) {
            configuration(new FileNotFound(stmIniFile.getAbsolutePath())); // "File not found: stm.ini"
        }
    }

    @Override
    protected void validate() throws Exception {
        String env = environment.get(setting);
        log.debug("Environment value for {} is {}", setting, env);
        if(env == null) {
            validation("challenge.type is not set yet");
	    return;
	}
	else {
            String conf = file.get(setting);
            log.debug("Configured value for {} is {}", setting, conf);
            if(conf == null ||  !env.equals(conf)) {
                validation(String.format("Configured value %s for %s does not match environment value %s", conf, setting, env));
	    }
	}
    }

    @Override
    protected void execute() throws Exception {
	Properties properties = new Properties();
        if( stmIniFile.exists() ) {
            properties.load(new StringReader(FileUtils.readFileToString(stmIniFile, Charset.forName("UTF-8"))));
        }
	confDir = properties.getProperty("stmconf.path");
	String sslLibPath = properties.getProperty("ssllib.path");

        NativeLibrary.addSearchPath("ssl", sslLibPath);
        NativeLibrary.addSearchPath("crypto", sslLibPath);

	StmLoadLibrary stmLoadLib = new StmLoadLibrary();
	List<StmLibrary> stmLibs = stmLoadLib.getStmLibInstances();

	if (stmLibs == null) {
	    log.error("no stm libs were found.");
	    return;
	}
        PointerByReference errPtrRef = new PointerByReference();
       ArrayList<String> techLabels = new ArrayList<String>();
	for (StmLibrary stmLib : stmLibs) {
	    // Access STM module through JNA and configure KMS STM in KEYSERVER_STM_MODE
	    String techLabel = stmLib.stm_init(confDir, KEYSERVER_STM_MODE, errPtrRef);
	    if(techLabel != null) {
		// store KeyAgent STM module label in dhsm2.challenge.type for subsequent use
		techLabels.add(techLabel);
	    }
	    else {
		log.error("stm_init failed with error {}", errPtrRef.getValue().getString(0));
	    }
	}
	getConfiguration().set(setting, StringUtils.join(techLabels, ","));
    }
}
