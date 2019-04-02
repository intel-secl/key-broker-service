/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.util.filters;

import com.intel.dcsg.cpg.crypto.Md5Digest;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.mtwilson.pipe.Filter;
import java.util.Arrays;

/**
 *
 * @author jbuhacoff
 */
public class ByteArrayFunctions {
 
    public static class Equals implements Filter<byte[]> {
        private byte[] test;

        public Equals(byte[] test) {
            this.test = test;
        }

        @Override
        public boolean accept(byte[] item) {
            return Arrays.equals(test, item);
        }
        
    }
    
    public static class EqualsHex implements Filter<byte[]> {
        private String test;

        public EqualsHex(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(byte[] item) {
            return test.equalsIgnoreCase(org.apache.commons.codec.binary.Hex.encodeHexString(item));
        }
        
    }
    
    public static class EqualsBase64 implements Filter<byte[]> {
        private String test;

        public EqualsBase64(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(byte[] item) {
            return test.equalsIgnoreCase(org.apache.commons.codec.binary.Base64.encodeBase64String(item));
        }
        
    }

    public static class Md5EqualsHex implements Filter<byte[]> {
        private String test;

        public Md5EqualsHex(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(byte[] item) {
            return test.equalsIgnoreCase(Md5Digest.digestOf(item).toHexString());
        }
        
    }
    
    public static class Sha1EqualsHex implements Filter<byte[]> {
        private String test;

        public Sha1EqualsHex(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(byte[] item) {
            return test.equalsIgnoreCase(Sha1Digest.digestOf(item).toHexString());
        }
        
    }
    public static class Sha256EqualsHex implements Filter<byte[]> {
        private String test;

        public Sha256EqualsHex(String test) {
            this.test = test;
        }

        @Override
        public boolean accept(byte[] item) {
            return test.equalsIgnoreCase(Sha256Digest.digestOf(item).toHexString());
        }
        
    }
    
}
