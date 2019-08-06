/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.util.filters;

import com.intel.mtwilson.pipe.Filter;

/**
 *
 * @author jbuhacoff
 */
public class BooleanFunctions {
 
    public static class Equals implements Filter<Boolean> {
        private Boolean test;

        public Equals(Boolean test) {
            this.test = test;
        }

        @Override
        public boolean accept(Boolean item) {
            return test.equals(item);
        }
        
    }
    
}
