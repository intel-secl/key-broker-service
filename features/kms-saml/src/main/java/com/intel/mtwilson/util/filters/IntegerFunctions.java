/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.util.filters;

import com.intel.mtwilson.pipe.Filter;

/**
 *
 * @author jbuhacoff
 */
public class IntegerFunctions {

    public static class Equals implements Filter<Integer> {
        private Integer test;
        public Equals(Integer test) {
            this.test = test;
        }
        @Override
        public boolean accept(Integer item) {
            return item.equals(test);
        }
    }
    
    public static class LessThan implements Filter<Integer> {
        private Integer test;
        public LessThan(Integer test) {
            this.test = test;
        }
        @Override
        public boolean accept(Integer item) {
            return item < test;
        }
    }
    
    public static class GreaterThan implements Filter<Integer> {
        private Integer test;
        public GreaterThan(Integer test) {
            this.test = test;
        }
        @Override
        public boolean accept(Integer item) {
            return item > test;
        }
    }
    
    // aka  GreaterThanOrEqualTo
    public static class NotLessThan implements Filter<Integer> {
        private Integer test;
        public NotLessThan(Integer test) {
            this.test = test;
        }
        @Override
        public boolean accept(Integer item) {
            return !(item < test);
        }
    }
    
    // aka  LessThanOrEqualTo
    public static class NotGreaterThan implements Filter<Integer> {
        private Integer test;
        public NotGreaterThan(Integer test) {
            this.test = test;
        }
        @Override
        public boolean accept(Integer item) {
            return !(item > test);
        }
    }
    
    // aka  NotLessThan(start) && NotGreaterThan(end)
    public static class InclusiveRange implements Filter<Integer> {
        private Integer testRangeStart, testRangeEnd;
        public InclusiveRange(Integer testRangeStart, Integer testRangeEnd) {
            this.testRangeStart = testRangeStart;
            this.testRangeEnd = testRangeEnd;
        }
        @Override
        public boolean accept(Integer item) {
            return (testRangeStart <= item) && (item <= testRangeEnd);
        }
    }
    


}
