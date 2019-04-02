/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.util.filters;

import com.intel.mtwilson.pipe.Filter;
import java.util.Date;

/**
 *
 * @author jbuhacoff
 */
public class DateFunctions {

    public static class Equals implements Filter<Date> {
        private Date test;
        public Equals(Date test) {
            this.test = test;
        }
        @Override
        public boolean accept(Date item) {
            return item.equals(test);
        }
    }
    
    public static class Before implements Filter<Date> {
        private Date test;
        public Before(Date test) {
            this.test = test;
        }
        @Override
        public boolean accept(Date item) {
            return item.before(test);
        }
    }
    
    public static class After implements Filter<Date> {
        private Date test;
        public After(Date test) {
            this.test = test;
        }
        @Override
        public boolean accept(Date item) {
            return item.after(test);
        }
    }
    
    public static class NotAfter implements Filter<Date> {
        private Date test;
        public NotAfter(Date test) {
            this.test = test;
        }
        @Override
        public boolean accept(Date item) {
            return !item.after(test);
        }
    }
    
    public static class NotBefore implements Filter<Date> {
        private Date test;
        public NotBefore(Date test) {
            this.test = test;
        }
        @Override
        public boolean accept(Date item) {
            return !item.before(test);
        }
    }
    

}
