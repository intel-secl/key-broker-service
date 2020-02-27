/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.stmlib;

import com.sun.jna.Native;
import com.intel.mtwilson.Folders;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.Properties;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.Charset;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author rbhat
 */
public class StmLoadLibrary {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StmLoadLibrary.class);
    private static List<StmLibrary> stmLibs = new ArrayList<StmLibrary> ();
    private static StmLibrary cryptLib;
    private static StmLibrary swStmLib;
    private static StmLibrary sgxStmLib;
    private static File stmIniFile = null;

    public StmLibrary getSwStmLibInstance() {
	return this.swStmLib;
    }

    public StmLibrary getSgxStmLibInstance() {
	return this.sgxStmLib;
    }

    public StmLibrary getActiveStmLibInstance(String activeStmLabel) {
	if(activeStmLabel.equalsIgnoreCase("SGX")) {
	    return getSgxStmLibInstance();
	}
	else if(activeStmLabel.equalsIgnoreCase("SW")) {
	    return getSwStmLibInstance();
	}
	return null;
    }

    public List<StmLibrary> getStmLibInstances() {
	return stmLibs;
     }

    public StmLoadLibrary() {
	// load stm.ini file to read the stm config/library path
	if(stmIniFile == null) {
	    stmIniFile = new File(Folders.configuration() + File.separator + "stm.ini");
	    if (!stmIniFile.exists()) {
		return;
	    }
	}
       
	Properties properties = new Properties();
	try {
	    properties.load(new StringReader(FileUtils.readFileToString(stmIniFile, Charset.forName("UTF-8"))));
	} catch (IOException ex) {
	    log.error("exception while reading stm.ini file {}", ex.getMessage());
	}

	String swStm = properties.getProperty("sw_stm_lib");
	String sgxStm = properties.getProperty("sgx_stm_lib");
	String cryptoLib = properties.getProperty("crypto_lib");

	try {
	    cryptLib = (StmLibrary)Native.loadLibrary(cryptoLib, StmLibrary.class);
	    // try to load sw stm lib, only if its path is available in stm.ini
	    // and its not loaded already
	    if (!swStm.isEmpty() && swStmLib == null) {
		swStmLib = (StmLibrary)Native.loadLibrary(swStm, StmLibrary.class);
		stmLibs.add(swStmLib);
	    }
	} catch (UnsatisfiedLinkError err) {
	    log.error("cannot find sw stm lib", err);
	}
	try {
	    // try to load sgx stm lib, only if its path is available in stm.ini
	    // and its not loaded already
	    if (!sgxStm.isEmpty() && sgxStmLib == null) {
		sgxStmLib = (StmLibrary)Native.loadLibrary(sgxStm, StmLibrary.class);
		stmLibs.add(sgxStmLib);
	    }
	} catch (UnsatisfiedLinkError err) {
	    log.error("cannot find sgx stm lib", err);
	}
    }
}
