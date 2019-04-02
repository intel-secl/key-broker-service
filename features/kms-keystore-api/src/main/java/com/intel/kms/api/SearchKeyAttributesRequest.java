/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.QueryParam;

/**
 * TENTATIVE because this is related to key management which the user can
 * get from the backend key server directly.
 * 
 * @author jbuhacoff
 */
public class SearchKeyAttributesRequest /*extends DefaultFilterCriteria (from mtwilson-util-jaxrs2) */ {
    
    @QueryParam("filter")
    @DefaultValue("true") // default for use by the jaxrs framework
    public boolean filter = true; // default for use when creating a filter criteria instance from application code
    @DefaultValue("10") // default for use by the jaxrs framework
    @QueryParam("limit") 
    public Integer limit = 10; 
    @QueryParam("page") 
    public Integer page; 
    
    @QueryParam("id")
    public String id;

    @QueryParam("name")
    public String name;

    @QueryParam("algorithm")
    public String algorithm;

    @QueryParam("keyLength")
    public String keyLength;

    @QueryParam("cipherMode")
    public String cipherMode;

    @QueryParam("paddingMode")
    public String paddingMode;
    
}
