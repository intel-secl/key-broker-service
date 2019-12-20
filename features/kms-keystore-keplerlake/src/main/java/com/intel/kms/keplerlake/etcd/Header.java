/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake.etcd;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.math.BigInteger;

/**
 *
 * @author kchinnax
 */
public class Header {

@JsonProperty("cluster_id")
private BigInteger clusterId;

@JsonProperty("member_id")
private BigInteger memberId;

@JsonProperty("revision")
private Integer revision;

@JsonProperty("raft_term")
private Integer raftTerm;

public BigInteger getClusterId() {
return clusterId;
}

public void setClusterId(BigInteger clusterId) {
this.clusterId = clusterId;
}

public BigInteger getMemberId() {
return memberId;
}

public void setMemberId(BigInteger memberId) {
this.memberId = memberId;
}

public Integer getRevision() {
return revision;
}

public void setRevision(Integer revision) {
this.revision = revision;
}

public Integer getRaftTerm() {
return raftTerm;
}

public void setRaftTerm(Integer raftTerm) {
this.raftTerm = raftTerm;
}

}

