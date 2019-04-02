/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
