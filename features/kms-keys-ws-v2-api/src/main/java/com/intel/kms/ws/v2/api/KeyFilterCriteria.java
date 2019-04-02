/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.ws.v2.api;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.validation.Regex;
import com.intel.mtwilson.jaxrs2.DefaultFilterCriteria;
import com.intel.mtwilson.repository.FilterCriteria;
import javax.ws.rs.QueryParam;

/**
 *
 * @author jbuhacoff
 */
public class KeyFilterCriteria extends DefaultFilterCriteria implements FilterCriteria<Key> {
    @QueryParam("id")
    public UUID id;

    @QueryParam("algorithmEqualTo")
    public String algorithmEqualTo;
    @QueryParam("keyLengthEqualTo")
    public Integer keyLengthEqualTo;
    @QueryParam("modeEqualTo")
    public String modeEqualTo;
    @QueryParam("paddingModeEqualTo")
    public String paddingModeEqualTo;
    @QueryParam("usernameEqualTo")
    public String usernameEqualTo;
    @QueryParam("transferPolicyEqualTo")
    public String transferPolicyEqualTo;
    @QueryParam("descriptionContains")
    public String descriptionContains;
    @QueryParam("roleEqualTo")
    public String roleEqualTo;
    @QueryParam("digestAlgorithmEqualTo")
    public String digestAlgorithmEqualTo;
    @QueryParam("path")
    @Regex("[a-zA-Z0-9/.,:_-]*")
    public String extensions;
}
