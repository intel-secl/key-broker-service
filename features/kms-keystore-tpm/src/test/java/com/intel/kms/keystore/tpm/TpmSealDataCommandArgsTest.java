/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.keystore.tpm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class TpmSealDataCommandArgsTest {
    final private org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(getClass());
    
    private String[] concat(String[] array1, String[] array2) {
        String[] result = new String[array1.length+array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }
    
    private String[] getSealDataCommandPcrArguments(Set<Integer> pcrs) {
        ArrayList<Integer> pcrlist = new ArrayList<>();
        pcrlist.addAll(pcrs);
        Collections.sort(pcrlist);
        int pcrcount = pcrlist.size();
        String[] result = new String[pcrcount*2];
        for(int i=0; i<pcrcount; i++) {
            result[i*2] = "-p";
            result[i*2+1] = String.valueOf(pcrlist.get(i));
        }
        return result;
    }
    
    @Test
    public void testGenerateArgs() {
        HashSet<Integer> set = new HashSet<>();
        set.add(0);
        set.add(17);
        set.add(18);
        set.add(19);
        String[] result = concat(new String[] { "tpm","tpm_sealdata","-z"}, getSealDataCommandPcrArguments(set));
        for(int i=0; i<result.length; i++) {
        log.debug("result: index {} value {}", i, result[i]);
        }
    }
}
