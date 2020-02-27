/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.stmlib;

import com.sun.jna.Library;
import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.lang.reflect.Field;
import java.lang.String;
import java.util.List;
import java.util.ArrayList;

/**
 * StmLibrary interface provides class implementations for challenge_quote
 * and challene response structures used by STM and Keyagent Libraries
 *
 * @author rbhat
 */

public interface StmLibrary extends Library { 

    // simulate GByteArray Implementation of Glib2
    public static class StmByteArray extends Structure {
	public static class ByReference extends StmByteArray implements Structure.ByReference {}
	public Pointer data;
	public int length;
 
	@Override
        protected List<String> getFieldOrder() {
	    List<String> fields = new ArrayList<>();
	    for (final Field f : StmByteArray.class.getDeclaredFields()) {
		if (!f.isSynthetic())
		    fields.add(f.getName());
	    }
	    return fields;
	}
    }

    /**
     * simulate challenge quote structure in JNA to be sent to STM
     */
    public static class StmChallengeQuote extends Structure {
	public static class ByReference extends StmChallengeQuote implements Structure.ByReference {}
	public StmByteArray.ByReference bytes;

	@Override
        protected List<String> getFieldOrder() {
	    List<String> fields = new ArrayList<>();
	    for (final Field f : StmChallengeQuote.class.getDeclaredFields()) {
		if (!f.isSynthetic())
		    fields.add(f.getName());
	    }
	    return fields;
	}
    }
 
    /**
     * simulate STM challenge response structure (keyagent_attribute_set) in JNA
     */
    public static class StmBufferPtr extends Structure {
	public static class ByReference extends StmBufferPtr implements Structure.ByReference {}
	public StmByteArray.ByReference bytes;
	public int ref_count;

	@Override
        protected List<String> getFieldOrder() {
	    List<String> fields = new ArrayList<>();
	    for (final Field f : StmBufferPtr.class.getDeclaredFields()) {
		if (!f.isSynthetic())
		    fields.add(f.getName());
	    }
	    return fields;
	}
    }

    public static class StmGetAttrs extends Structure {
	public static class ByReference extends StmGetAttrs implements Structure.ByReference {}
	public String name;
	public StmBufferPtr.ByReference value;

	@Override
        protected List<String> getFieldOrder() {
	    List<String> fields = new ArrayList<>();
	    for (final Field f : StmGetAttrs.class.getDeclaredFields()) {
		if (!f.isSynthetic())
		    fields.add(f.getName());
	    }
	    return fields;
	}
    }

    public static class StmGetAttrSet extends Structure {
	public static class ByReference extends StmGetAttrSet implements Structure.ByReference {}
	public int ref_count;
	public int count;
	public int _count;
	public StmGetAttrs.ByReference attrs;
	
	@Override
        protected List<String> getFieldOrder() {
	    List<String> fields = new ArrayList<>();
	    for (final Field f : StmGetAttrSet.class.getDeclaredFields()) {
		if (!f.isSynthetic())
		    fields.add(f.getName());
	    }
	    return fields;
	}
    }

    /**
     * Define a Pointer to a pointer to a structure to retrieve individual attributes from challenge response
     */
    public static class StmChallengeGetAttrRes extends Structure {
	public static class ByReference extends StmChallengeGetAttrRes implements Structure.ByReference {}
	public StmGetAttrSet.ByReference refPtr;
	
	@Override
        protected List<String> getFieldOrder() {
	    List<String> fields = new ArrayList<>();
	    for (final Field f : StmChallengeGetAttrRes.class.getDeclaredFields()) {
		if (!f.isSynthetic())
		    fields.add(f.getName());
	    }
	    return fields;
	}
    }

    // define list of functions to be accessed from STM Module
    public String stm_init(String configDir, int stmMode, PointerByReference errVal);
    public boolean stm_challenge_generate_request(PointerByReference request, PointerByReference errVal);
    public boolean stm_challenge_verify(StmChallengeQuote.ByReference quote, StmChallengeGetAttrRes.ByReference challengeAttr, PointerByReference errVal);
}
