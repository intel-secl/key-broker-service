/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.kms.keystore.kmip;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.keystore.kmip.exception.KMIPClientException;
import com.intel.kms.keystore.kmip.library.KmipLibrary;
import com.sun.jna.Native;

import java.io.IOException;

import static com.intel.mtwilson.configuration.ConfigurationFactory.getConfiguration;

public class KMIPClient {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KMIPClient.class);
    private static KMIPClient kmipClient;
    private static KmipLibrary kmipLibrary;
    private static Configuration config;
    public static final String KMIP_SERVER_ADDRESS = "kmip.server.address";
    public static final String KMIP_SERVER_PORT = "kmip.server.port";
    public static final String KMIP_CLIENT_CERTIFICATE_PATH = "kmip.client.certificate.path";
    public static final String KMIP_CLIENT_KEY_PATH = "kmip.client.key.path";
    public static final String KMS_KMIP_CA_CERTIFICATES = "kmip.ca.certificates.path";
    public static final int KMIP_CLIENT_RESULT_SUCCESS = 0;

    private static String address;
    private static String port;
    private static String clientCertPath;
    private static String clientKeyPath;
    private static String caCertificatesPath;

    enum CRYPTO_ALGORITHMS {
        KMIP_CRYPTOALG_AES(0x03),
        KMIP_CRYPTOALG_RSA(0x04),
        KMIP_CRYPTOALG_ECDSA(0x06);

        private int value;

        public int getValue()
        {
            return this.value;
        }

        private CRYPTO_ALGORITHMS(int value)
        {
            this.value = value;
        }
    }

    public KMIPClient() {
    }

    public static KMIPClient getKMIPClient(Configuration configuration)
            throws KMIPClientException {
        log.debug("getKMIPClient called");
        if (kmipClient == null) {
            kmipClient = new KMIPClient();
        }

        if (kmipLibrary == null){
            log.debug("Loading kmipclient library");
            kmipLibrary = (KmipLibrary) Native.loadLibrary("kmipclient", KmipLibrary.class);
            if (kmipLibrary == null){
                log.error("unable to load kmip client library");
                return null;
            }else {
                log.info("kmipclient library is successfully loaded");
            }
        }
        try {
            config = getConfiguration();
        } catch (IOException e) {
            e.printStackTrace();
        }

        address = config.get(KMIP_SERVER_ADDRESS, "");
        port = config.get(KMIP_SERVER_PORT, "");
        clientCertPath = config.get(KMIP_CLIENT_CERTIFICATE_PATH);
        clientKeyPath = config.get(KMIP_CLIENT_KEY_PATH);
        caCertificatesPath = config.get(KMS_KMIP_CA_CERTIFICATES);

        int result = kmipLibrary.kmipw_init(address, port, clientCertPath, clientKeyPath, caCertificatesPath);
        if (result == KMIP_CLIENT_RESULT_SUCCESS){
            log.info("KMIP client is initialized");
        } else {
            log.warn("KMIP client is not initialized. Check kmip client logs for more details.");
        }
        return kmipClient;
    }

    /**
     * Creates key from createkeyRequest
     *
     *
     * @param algorithm, key_length
     * @return Key UUID
     *
     */
     public String createKey(String algorithm, int key_length)
            throws KMIPClientException {
         int algId = 0;
         log.debug("createKey Called");
         switch (algorithm){
             case "AES":
                 algId = CRYPTO_ALGORITHMS.KMIP_CRYPTOALG_AES.getValue();
                 break;
             case "RSA":
                 algId = CRYPTO_ALGORITHMS.KMIP_CRYPTOALG_RSA.getValue();
                 break;
             case "EC":
                 algId = CRYPTO_ALGORITHMS.KMIP_CRYPTOALG_ECDSA.getValue();
                 break;
             default:
                 throw new KMIPClientException("Algorithm: " + algorithm +"Not supported");
         }

         if (key_length == 0){
             throw new KMIPClientException("Invalid key length");
         }
         String key_uuid = null;
         log.debug("Calling kmipclient for creating key");
         key_uuid = kmipLibrary.kmipw_create(algId, key_length);
         if (key_uuid == null){
             log.error("Error while creating key from kmip client. Check kmip client logs for more details.");
             throw new KMIPClientException("Error while creating key from kmipclient");
         }
         log.info("key is created successfully by kmip client, key id: {}", key_uuid);
         return key_uuid;
     }

    /**
     * Based on uid inside transferKeyRequest retrieves key
     *
     * @param uuid
     * @return key with the key populated
     * @throws KMIPClientException
     */

    public String retrieveKey(
            String uuid) throws KMIPClientException {
        log.debug("retrieveSecret called");
        log.debug("kmip-kms key uuid {}", uuid);
        String key = null;
        int result = kmipLibrary.kmipw_get(uuid, key);
        if (result != KMIP_CLIENT_RESULT_SUCCESS){
            log.error("Error while retrieving key from kmip client. Check kmip client logs for more details.");
            throw new KMIPClientException("Error while retrieving key from kmip client");
        }
        return key;
    }


    /**
     * Deletes key from kmip server
     *
     * @param uuid
     * @throws KMIPClientException
     */
    public void deleteKey(String uuid)
            throws KMIPClientException {
        log.debug("deleteSecret called");
        log.debug("kmip-kms key uuid {}", uuid);
        int result = kmipLibrary.kmipw_destroy(uuid);
        if (result != KMIP_CLIENT_RESULT_SUCCESS){
            log.error("Error while deleting key from kmip client. Check kmip client logs for more details.");
            throw new KMIPClientException("Could not delete keyId with id: " + uuid);
        }
    }

}
