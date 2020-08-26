/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.kms.dhsm2.common.CommonSession;

import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.tls.policy.TlsPolicyBuilder;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.jaxrs2.client.AASTokenFetcher;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.util.Properties;

import static com.intel.mtwilson.configuration.ConfigurationFactory.getConfiguration;

public class TokenFetcher {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TokenFetcher.class);

    public static Properties properties = new Properties();
    private static String bearerToken="";
    private static String trustStorePath = Folders.configuration()+ File.separator;

    public static String getTrustStorePath() {
        String extension = "p12";
        String truststoreType = KeyStore.getDefaultType();
        if (truststoreType.equalsIgnoreCase("JKS")) {
            extension = "jks";
        }
        return (trustStorePath + "truststore."+extension);
    }

    public static boolean setPropertyForFetchingAASAttributes() {
        try {
            if (getConfiguration().get("aas.api.url") == null
                    || getConfiguration().get("aas.api.url").isEmpty()) {
                return false;
            } else {
                properties.setProperty("aas.api.url", getConfiguration().get("aas.api.url"));
            }

            ///AAS BEARER TOKEN is to be used here
            if ((bearerToken == null) || (bearerToken.isEmpty())) {
                log.debug("bearerToken is empty");
                if (!updateToken()) {
                    return false;
                }
            }
            properties.setProperty("bearer.token", bearerToken);
        } catch(IOException ex) {
            log.error("Exception while reading aas properties: {}", ex.getMessage());
            return false;
        }
        return true;
    }

    public static boolean updateToken() {
        try {
            log.debug("in updateToken");
            String username  = getConfiguration().get("kms.admin.username");
            String password = getConfiguration().get("kms.admin.password");
            String url = properties.getProperty("aas.api.url");
            if ((username == null) || (username.isEmpty()) || (password == null) || (password.isEmpty()) || (url == null) || url.isEmpty()) {
                log.error("configurations are not set");
                return false;
            }
            TlsPolicy tlsPolicy = TlsPolicyBuilder.factory().strictWithKeystore(getTrustStorePath(), "changeit").build();
            try {
                AASTokenFetcher aasTokenFetcher = new AASTokenFetcher();
                bearerToken = aasTokenFetcher.getAASToken(username, password, new TlsConnection(new URL(url), tlsPolicy));
            } catch (Exception ex) {
                log.error("Exception while getting token: {}", ex.getMessage());
                return false;
            }
            if ((bearerToken == null) || (bearerToken.isEmpty())) {
                log.error("no bearerToken");
                return false;
            }
            properties.setProperty("bearer.token", bearerToken);
        } catch(IOException ex) {
            log.error("Exception while reading aas properties: {}", ex.getMessage());
            return false;
        }
        return true;
    }
}
