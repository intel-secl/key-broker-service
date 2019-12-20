/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake.etcd;

import com.intel.keplerlake.io.Etcdctl3;
import com.intel.keplerlake.registry.ext.KeplerLakeRegistryDAO;
import com.intel.kms.keplerlake.KeplerLakeUtil;
import java.io.IOException;
import java.util.HashMap;

/**
 *
 * @author kchinnax
 */
public class EtcdUtils {

    public static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(EtcdUtils.class);
    public static final String BYTE_ENCODING = "UTF-8";
    public static final String ETCDCTL_CMD = "etcdctl";
    public static final String POLICY_URN = "urn:etcd:";
    public static final String REALM = "realm";
    public static final String CONTENT = "content";
    public static final String POLICY = "policy";
    public static final String FLAVOR = "flavor";
    public static final String SERVICE = "service";
    public static final String KEY_ESCROW = "key-escrow";
    public static final String DATASET = "dataset";
    public static final String KEY_ESCROW_TLS_SHA256 = "tls.certificate.sha256";
    public static final String KEY_ESCROW_URL = "url";
    final private KeplerLakeUtil keplerLakeUtil;
    
    public EtcdUtils() throws IOException {
        keplerLakeUtil = new KeplerLakeUtil();
    }

    public enum MethodType {
        GET, PUT, DELETE
    }

    public final static HashMap<MethodType, String> METHODTYPE_MAP = new HashMap<MethodType, String>() {
        {
            put(MethodType.GET, "get");
            put(MethodType.PUT, "put");
            put(MethodType.DELETE, "del");
        }
    };

    public enum Options {
        WRITE_OUT, JSON, PREFIX, ETCD_CACERT, ETCD_CERT, ETCD_KEY, ENDPOINTS
    }

    public final static HashMap<Options, String> OPTION_MAP = new HashMap<Options, String>() {
        {
            put(Options.WRITE_OUT, "-w");
            put(Options.JSON, "json");
            put(Options.PREFIX, "--prefix");
            put(Options.ETCD_CACERT, "--cacert");
            put(Options.ETCD_CERT, "--cert");
            put(Options.ETCD_KEY, "--key");
            put(Options.ENDPOINTS, "--endpoints");
        }
    };
    
    public KeplerLakeRegistryDAO getKeplerLakeRegistryDAO() throws IOException {
        
        return new KeplerLakeRegistryDAO(new Etcdctl3(keplerLakeUtil.getEnvMap()), keplerLakeUtil.getEtcdConfiguration().getProperty("realm.name"));
    }


    /**
     * This method is used to prepare key to retrieve policy.
     *
     * @param realmName
     * @param policyId
     * @return
     */
    public String prepareKeyToGetPolicy(String realmName, String policyId) {
        StringBuilder keyBuilder = new StringBuilder();

        keyBuilder.append("/");
        keyBuilder.append(REALM);
        keyBuilder.append("/");
        keyBuilder.append(realmName.trim());
        keyBuilder.append("/");
        keyBuilder.append(POLICY);
        keyBuilder.append("/");
        keyBuilder.append(policyId.trim());
        keyBuilder.append("/");
        keyBuilder.append(CONTENT);
        LOG.debug("kms prepared key to get policy {}", keyBuilder.toString());
        return keyBuilder.toString();
    }

    public String prepareKeyToGetOriginalKeyEscrowInfo(String realmName, String context) {
        StringBuilder keyBuilder = new StringBuilder();

        keyBuilder.append("/");
        keyBuilder.append(REALM);
        keyBuilder.append("/");
        keyBuilder.append(realmName.trim());
        keyBuilder.append("/");
        keyBuilder.append(SERVICE);
        keyBuilder.append("/");
        keyBuilder.append(KEY_ESCROW);
        keyBuilder.append("/");
        keyBuilder.append(context);

        LOG.debug("kms prepared key to get {} : {}", context, keyBuilder.toString());
        return keyBuilder.toString();
    }

    /**
     *
     * @param realmName
     * @param flavorId
     * @return
     */
    public String prepareKeyToGetFlavor(String realmName, String flavorId) {
        StringBuilder keyBuilder = new StringBuilder();

        keyBuilder.append("/");
        keyBuilder.append(REALM);
        keyBuilder.append("/");
        keyBuilder.append(realmName.trim());
        keyBuilder.append("/");
        keyBuilder.append(FLAVOR);
        keyBuilder.append("/");
        keyBuilder.append(flavorId.trim());
        keyBuilder.append("/");
        keyBuilder.append(CONTENT);
        LOG.debug("kms prepared key to get flavor {}", keyBuilder.toString());

        return keyBuilder.toString();
    }

    public String prepareKeyToGetDatasetInfo(String realmName, String dataset) {
        StringBuilder keyBuilder = new StringBuilder();

        keyBuilder.append("/");
        keyBuilder.append(REALM);
        keyBuilder.append("/");
        keyBuilder.append(realmName);
        keyBuilder.append("/");
        keyBuilder.append(DATASET);
        keyBuilder.append("/");
        keyBuilder.append(dataset);
        keyBuilder.append("/");
        keyBuilder.append(CONTENT);
        LOG.debug("kms prepared key to get dataset {}", keyBuilder.toString());

        return keyBuilder.toString();
    }


}
