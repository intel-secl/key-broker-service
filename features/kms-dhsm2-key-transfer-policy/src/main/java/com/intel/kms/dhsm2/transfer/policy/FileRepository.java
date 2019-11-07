/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.repository.Repository;
import com.intel.mtwilson.codec.JacksonCodec;
import com.intel.dcsg.cpg.iso8601.Iso8601Date;
import java.io.File;
import java.io.IOException;
import java.sql.Timestamp;    
import java.util.ArrayList;
import java.util.Date;
import java.util.Collection;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author rbhat
 */
public class FileRepository {
	final private File directory;
	final private JacksonCodec jackson;

	public FileRepository(File directory) {
		this.directory = directory;
		this.jackson = new JacksonCodec();
	}

	private File locate(String id) {
		return new File(directory.getAbsolutePath()+File.separator+id);
	}

	protected void store(KeyTransferPolicyAttributes item) {
		try {
			String id = item.getKeyTransferPolicyId();
			if( id == null ) {
				id = new UUID().toString();
			}
			else {
				File file = locate(id);
				if( file.exists() ) {
					throw new IllegalArgumentException("Key Transfer Policy id already exists");
				}
			}
			item.setKeyTransferPolicyId(id);
			Iso8601Date iso8601Date = new Iso8601Date(new Date());
			item.setCreatedAt(iso8601Date);
			byte[] json = jackson.encode(item);
			FileUtils.writeByteArrayToFile(locate(id), json);
		}
		catch(Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	public KeyTransferPolicyAttributes retrieve(String id) {
		try {
			File file = locate(id);
			if( !file.exists() ) {
				return null;
			}
			byte[] json = FileUtils.readFileToByteArray(file);
			Object item = jackson.decode(json);
			return (KeyTransferPolicyAttributes)item;
		}
		catch(Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	protected void delete(String id) {
		File file = locate(id);
		if( !file.exists() ) {
			throw new IllegalArgumentException("Key Transfer Policy Id does not exist");
		}
		file.delete();
	}

	public Collection<String> list() {
		Collection<File> files = FileUtils.listFiles(directory, null, false);
		ArrayList<String> list = new ArrayList<>();
		for(File file : files) {
			list.add(file.getName());
		}
		return list;
	}
}
