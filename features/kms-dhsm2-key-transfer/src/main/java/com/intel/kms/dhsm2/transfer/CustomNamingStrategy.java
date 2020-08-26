/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.key.transfer;

import com.fasterxml.jackson.databind.introspect.AnnotatedField;
import com.fasterxml.jackson.databind.introspect.AnnotatedMethod;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.cfg.MapperConfig;

/**
 * CustomNamingStrategy class converts input Json nodes as follows
 * Ex: Accept-Challenge to accept_challege which aligns with 
 * jackson property naming strategy
 */
public class CustomNamingStrategy extends PropertyNamingStrategy {
  
    @Override
    public String nameForField(MapperConfig config, AnnotatedField field, String fieldName) {
	return convert(fieldName);
    }

    @Override
    public String nameForGetterMethod(MapperConfig config, AnnotatedMethod method, String fieldName) {
	return convert(fieldName);
    }
  
    @Override
    public String nameForSetterMethod(MapperConfig config, AnnotatedMethod method, String fieldName) {
	return convert(fieldName); 
    }
  
    protected String convert(String fieldName) {
	char[] arr = fieldName.toCharArray();

	for (int i=0; i< arr.length; i++) {
	    if (Character.isUpperCase(arr[i])){
	        char lower = Character.toLowerCase(arr[i]);
	        arr[i] = lower;
	    }
	}
	String lowerCaseStr = new String(arr);
	String hyphenStr = lowerCaseStr.replace('-', '_');
	return hyphenStr;
    }
}
