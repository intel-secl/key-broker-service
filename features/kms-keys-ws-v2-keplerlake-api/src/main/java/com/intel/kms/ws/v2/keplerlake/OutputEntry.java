/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.ws.v2.keplerlake;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author nallux
 */
public class OutputEntry {
    /*file_id removed in m8*/ 
   /* @JsonProperty("file_id")
    private String fileId;*/
    @JsonProperty("path")
    private String path;

   /* public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }*/

    /**
     * @return the path
     */
    public String getPath() {
        return path;
    }

    /**
     * @param path the path to set
     */
    public void setPath(String path) {
        this.path = path;
    }
    

}
