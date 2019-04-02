/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore.directory;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.repository.Repository;
import com.intel.mtwilson.codec.JacksonCodec;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author jbuhacoff
 */
public class JacksonFileRepository implements Repository {
    final private File directory;
    final private JacksonCodec jackson;


    public JacksonFileRepository(File directory) {
        this.directory = directory;
        this.jackson = new JacksonCodec();
    }
    
    private File locate(String id) {
        return new File(directory.getAbsolutePath()+File.separator+id);
    }

    @Override
    public void create(CipherKeyAttributes item) {
        try {
            String id = item.getKeyId();
            if( id == null ) {
                id = new UUID().toString();
            }
            else {
                File file = locate(id);
                if( file.exists() ) {
                    throw new IllegalArgumentException("Key id already exists");
                }
            }
            item.setKeyId(id);
            byte[] json = jackson.encode(item); // writeValueAsString(item); // throws JsonProcessingException (subclass of IOException)
            FileUtils.writeByteArrayToFile(locate(id), json);
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void store(CipherKey item) {
        try {
            String id = item.getKeyId();
            if( id == null ) {
                id = new UUID().toString();
            }
            else {
                File file = locate(id);
                if( file.exists() ) {
                    throw new IllegalArgumentException("Key id already exists");
                }
            }
            item.setKeyId(id);
            byte[] json = jackson.encode(item); // writeValueAsString(item); // throws JsonProcessingException (subclass of IOException)
            FileUtils.writeByteArrayToFile(locate(id), json);
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public CipherKey retrieve(String id) {
        try {
            File file = locate(id);
            if( !file.exists() ) {
                return null;
            }
            byte[] json = FileUtils.readFileToByteArray(file);
            Object item = jackson.decode(json);
            return (CipherKey)item;
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public CipherKeyAttributes getAttributes(String id) {
        try {
            File file = locate(id);
            if( !file.exists() ) {
                return null;
            }
            byte[] json = FileUtils.readFileToByteArray(file);
            Object item = jackson.decode(json);
            return (CipherKey)item;
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void delete(String id) {
            File file = locate(id);
            if( !file.exists() ) {
                throw new IllegalArgumentException("Key does not exist");
            }
            file.delete();
    }
/*
    @Override
    public Collection search(Map criteria) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
 */

    @Override
    public Collection<String> list() {
        Collection<File> files = FileUtils.listFiles(directory, null, false);
        ArrayList<String> list = new ArrayList<>();
        for(File file : files) {
            list.add(file.getName());
        }
        return list;
    }
}
