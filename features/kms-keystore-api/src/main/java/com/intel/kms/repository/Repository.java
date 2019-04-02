/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.repository;

//import java.util.Collection;

import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import java.util.Collection;

//import java.util.Map;

/**
 * TODO: there is overlap between this interface and the repository used 
 * in the v2 jaxrs APIs (mtwilson-repository-api);  
 * maybe refactor into mtwilson-util-repository?   the mtwilson-repository-api
 * has an abstraction problem because it has create(CipherKey item) which means 
 * there can be no generic implementation that can get a locator out of item
 * and know what to do with it.  it maybe should have been create(item, locator)
 * and store(item, locator)  to match  retrieve(locator) and delete(locator).
 * 
 * @author jbuhacoff
 */
public interface Repository {
    /**
     * Creates a new key with the specified attributes.
     * Writes the new key id into the input object.
     * @param item 
     */
    void create(CipherKeyAttributes item);
    /**
     * Stores an existing key with the specified attributes.
     * Writes the new key id into the input object.
     * @param item 
     */
    void store(CipherKey item);
    /**
     * Retrieves key attributes for the specified key id.
     * @param id
     * @return 
     */
    CipherKeyAttributes getAttributes(String id);
    /**
     * Retrieves key and key attributes for the specified key id.
     * @param id
     * @return 
     */
    CipherKey retrieve(String id);
    /**
     * Deletes the key and key attributes for the specified key id.
     * @param id 
     */
    void delete(String id);
//    Collection<T> search(Map<String,String> criteria);  // should be in SearchableRepository interface
    
    /**
     *
     * @return list of all key id
     */
    Collection<String> list();
}
