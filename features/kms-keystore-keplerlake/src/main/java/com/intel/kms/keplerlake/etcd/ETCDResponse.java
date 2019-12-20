/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake.etcd;

import java.util.List;

/**
 *
 * @author kchinnax
 */
public class ETCDResponse {

    private Header header;
    private List<Kv> kvs = null;
    private Integer count;

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public List<Kv> getKvs() {
        return kvs;
    }

    public void setKvs(List<Kv> kvs) {
        this.kvs = kvs;
    }

    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

}
