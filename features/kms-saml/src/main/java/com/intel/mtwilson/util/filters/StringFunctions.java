/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.util.filters;

import com.intel.mtwilson.pipe.Filter;
import com.intel.mtwilson.pipe.Transformer;
import java.util.regex.Pattern;

/**
 *
 * @author jbuhacoff
 */
public class StringFunctions {

    public static class EqualsIgnoreCase implements Filter<String> {

        private String test;

        public EqualsIgnoreCase(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(String item) {
            return item.equalsIgnoreCase(test);
        }
    }

    public static class Contains implements Filter<String> {

        private String test;

        public Contains(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(String item) {
            return item.contains(test);
        }
    }

    public static class StartsWith implements Filter<String> {

        private String test;

        public StartsWith(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(String item) {
            return item.startsWith(test);
        }
    }

    public static class EndsWith implements Filter<String> {

        private String test;

        public EndsWith(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(String item) {
            return item.endsWith(test);
        }
    }

    public static class Matches implements Filter<String> {

        private Pattern test;

        public Matches(Pattern test) {
            this.test = test;
        }

        @Override
        public boolean accept(String item) {
            return test.matcher(item).matches();
        }
    }

    public static class LowerCase implements Transformer<String> {

        @Override
        public String transform(String input) {
            return input.toLowerCase();
        }
    }

    public static class UpperCase implements Transformer<String> {

        @Override
        public String transform(String input) {
            return input.toUpperCase();
        }
    }

    public static class ReplaceAll implements Transformer<String> {

        private String regex;
        private String replacement;

        public ReplaceAll(String regex, String replacement) {
            this.regex = regex;
            this.replacement = replacement;
        }

        @Override
        public String transform(String input) {
            return input.replaceAll(regex, replacement);
        }
    }

    public static class ReplaceFirst implements Transformer<String> {

        private String regex;
        private String replacement;

        public ReplaceFirst(String regex, String replacement) {
            this.regex = regex;
            this.replacement = replacement;
        }

        @Override
        public String transform(String input) {
            return input.replaceFirst(regex, replacement);
        }
    }
}
