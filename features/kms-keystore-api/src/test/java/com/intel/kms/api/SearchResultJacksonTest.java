/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import org.junit.Test;

/**
 * The AbstractResponse superclass is annotated with JsonInclude NON_EMPTY as
 * default behavior for all fields, but the SearachKeyAttributesResponse
 * class needs to include search results even when empty. This test confirms
 * it's working ok. 
 * 
 * @author jbuhacoff
 */
public class SearchResultJacksonTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SearchResultJacksonTest.class);

    @Test
    public void testEmptySearchResults() throws JsonProcessingException {
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        SearchKeyAttributesResponse response = new SearchKeyAttributesResponse();
        log.debug("empty search results: {}", mapper.writeValueAsString(response)); // {"data":[]}    works ok.
    }
}
