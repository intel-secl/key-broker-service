/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.ws.v2;

import com.intel.dcsg.cpg.validation.ValidationUtil;
import com.intel.kms.ws.v2.api.KeyFilterCriteria;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class KeyFilterCriteriaValidationTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyFilterCriteriaValidationTest.class);
    
    @Test
    public void testValidatePath() {
        KeyFilterCriteria criteria = new KeyFilterCriteria();
        criteria.extensions = "/path/with.dots";
        ValidationUtil.validate(criteria);
    }
}
