/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake.etcd;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.keplerlake.io.Etcdctl3;
import com.intel.keplerlake.registry.ext.KeplerLakeRegistryDAO;
import com.intel.kms.keplerlake.KeplerLakeUtil;
import com.intel.mtwilson.util.exec.ExecUtil;
import com.intel.mtwilson.util.exec.Result;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

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


   /* public boolean storePolicyToEtcd(String key, String value) {
        boolean status = false;
        try {
            LOG.debug("kms etcdctl insert key {} and value {}", key, value);
            byte[] keyByte = Base64.encodeBase64(key.getBytes(BYTE_ENCODING));
            byte[] valByte = Base64.encodeBase64(value.getBytes(BYTE_ENCODING));
            Result result = ExecUtil.execute(getETCDEnv(), ETCDCTL_CMD, OPTION_MAP.get(Options.ENDPOINTS), 
                    keplerLakeUtil.getEtcdConfiguration().getProperty("endpoint.url"), OPTION_MAP.get(Options.ETCD_CACERT), 
                    keplerLakeUtil.getEtcdConfiguration().getProperty("etcd.cacert.path"), METHODTYPE_MAP.get(MethodType.PUT), 
                    new String(keyByte, BYTE_ENCODING), new String(valByte, BYTE_ENCODING));
            LOG.debug("kms etcdctl status {} ", result.getExitCode());
            LOG.debug("kms etcdctl out {} ", result.getStdout());
            LOG.debug("kms etcdctl err {} ", result.getStderr());
            if (result.getExitCode() == 0) {
                status = true;
            }
        } catch (IOException ex) {
            LOG.debug("kms Error while inserting policy to Etcd {}", ex);
        }
        return status;
    }*/

   /* public String retrieveValueForKey(String key) {
        String value = "";
        try {
            LOG.debug("kms etcdctl get key {} ", key);
            Result result = ExecUtil.execute(getETCDEnv(), ETCDCTL_CMD, OPTION_MAP.get(Options.ENDPOINTS), 
                    keplerLakeUtil.getEtcdConfiguration().getProperty("endpoint.url"), OPTION_MAP.get(Options.ETCD_CACERT), 
                    keplerLakeUtil.getEtcdConfiguration().getProperty("etcd.cacert.path"), METHODTYPE_MAP.get(MethodType.GET), 
                    OPTION_MAP.get(Options.WRITE_OUT), OPTION_MAP.get(Options.JSON), key);
            LOG.debug("kms etcdctl status {} ", result.getExitCode());
            LOG.debug("kms etcdctl out {} ", result.getStdout());
            LOG.debug("kms etcdctl err {} ", result.getStderr());
            String jsonData = result.getStdout();
            ETCDResponse response = new ObjectMapper().readValue(jsonData, ETCDResponse.class);
            List<Kv> kvs = response.getKvs();
            if (kvs != null) {
                value = new String(Base64.decodeBase64(kvs.get(0).getValue()), BYTE_ENCODING);
            }

            if (value.startsWith("'") && value.endsWith("'")) {
                value = value.substring(1, value.length() - 1);
            }

        } catch (IOException ex) {
            LOG.error("Error retrieving value using etcdctl in kms for key {}", key, ex);
        }
        return value;
    }
    */

   /* public String getPolicyFromEtcd(String key) {
        String value = "";
        try {
            LOG.debug("tdc etcdctl get key {} ", key);
            Result result = ExecUtil.execute(getETCDEnv(), ETCDCTL_CMD, OPTION_MAP.get(Options.ENDPOINTS), keplerLakeUtil.getEtcdConfiguration().getProperty("endpoint.url"), OPTION_MAP.get(Options.ETCD_CACERT), keplerLakeUtil.getEtcdConfiguration().getProperty("etcd.cacert.path"), METHODTYPE_MAP.get(MethodType.GET), OPTION_MAP.get(Options.WRITE_OUT), OPTION_MAP.get(Options.JSON), key);
            LOG.debug("tdc etcdctl status {} ", result.getExitCode());
            LOG.debug("tdc etcdctl out {} ", result.getStdout());
            LOG.debug("tdc etcdctl err {} ", result.getStderr());
            String jsonData = result.getStdout();
            ETCDResponse response = new ObjectMapper().readValue(jsonData, ETCDResponse.class);
            List<Kv> kvs = response.getKvs();
            if (kvs != null) {
                value = new String(Base64.decodeBase64(kvs.get(0).getValue()), BYTE_ENCODING);
            }

            if (value.startsWith("'") && value.endsWith("'")) {
                value = value.substring(1, value.length() - 1);
            }

        } catch (IOException ex) {
            LOG.error("Error retrieving policy using etcdctl in tdc {}", ex);
        }
        return value;
    }
*/
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

    /*
    private Map<String, String> getETCDEnv() {
        Map<String, String> ETCD_ENV = new HashMap<String, String>() {
            {
                put("ETCDCTL_API", getETCDApiVersion());

            }
        };
        return ETCD_ENV;
    }

    private String getETCDApiVersion() {
        try {

            return keplerLakeUtil.getEtcdConfiguration().getProperty("etcd.api.version");

            //return "3";
        } catch (Exception ex) {
            LOG.error("Failed to read etcd api version swithcing to default value 3", ex);
            return "3";
        }
    }*/

   /* public boolean store(byte[] content, String path) {
        try {
            Etcdctl3 etcdctlClient = new Etcdctl3(keplerLakeUtil.getEnvMap());
            etcdctlClient.put(path, content);
            LOG.debug("Successfully stored in etcd {}", path);
            return true;
        } catch (IOException ex) {
            LOG.error("Storing in etcd failed ", ex);
            return false;
        }
    }*/

   /* public byte[] retrieve(String path) {
        try {
            Etcdctl3 etcdctlClient = new Etcdctl3(keplerLakeUtil.getEnvMap());
            return etcdctlClient.get(path);
        } catch (IOException ex) {
            LOG.error("Retrieve from etcd failed ", ex);
            return null;
        }
    }
*/

}
