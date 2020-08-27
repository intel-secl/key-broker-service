/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.kms.dhsm2.sessionManagement;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.lang.Exception;
import java.io.StringReader;
import java.util.Properties;
import java.security.KeyStore;
import java.nio.charset.Charset;
import javax.ws.rs.core.Response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.mtwilson.jaxrs2.client.AASTokenFetcher;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import org.apache.commons.io.FileUtils;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.jaxrs2.client.SVSClient;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.TlsPolicyBuilder;
import com.intel.kms.dhsm2.common.CommonSession.TokenFetcher;
import com.intel.dcsg.cpg.configuration.Configuration;

import static com.intel.mtwilson.configuration.ConfigurationFactory.getConfiguration;

/*
 * This is to request the Session Management API for the creation of a
 * session and verify challenge response.
 * @srajen4x
*/
public class QuoteVerifyOperations {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(QuoteVerifyOperations.class);

    final private ObjectMapper mapper;
    private static SVSClient svsClient;
    private Configuration config;
    private String stmLabel;
    private static String aasBearerToken;
    private static String TRUSTSTORE_PASSWORD = "changeit";
    private static String trustStorePath = Folders.configuration() + File.separator;
    QuoteVerifyResponseAttributes verifyResponse = new QuoteVerifyResponseAttributes();

    protected String getTrustStorePath() {
        String extension = "p12";
        String truststoreType = KeyStore.getDefaultType();
        if (truststoreType.equalsIgnoreCase("JKS")) {
            extension = "jks";
        }
        return (trustStorePath + "truststore." + extension);
    }

    public QuoteVerifyOperations(String stm) {
        this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
        log.debug("QuoteVerifyOperations: Stm {}", stm);
        if (stm != null && !stm.isEmpty())
            stmLabel = stm;
    }

    public SVSClient getSvsClientObj() {
        String keyStorePath;
        String svsBaseUrl;
        File propertiesFile;
        Properties properties;
        TlsPolicy tlsPolicy;
        String pass;

        if (svsClient != null)
            return svsClient;

        try {
            config = getConfiguration();
            propertiesFile = new File(Folders.configuration() + File.separator + "https.properties");
            if (!propertiesFile.exists()) {
                log.error("getSvsClientObj: Invalid properties file path{}", propertiesFile);
                return null;
            }
            svsBaseUrl = config.get("svs.base.url");
            if (svsBaseUrl == null || svsBaseUrl.isEmpty()) {
                log.error("getSvsClientObj: SVS Base Url is not provided");
                return null;
            }

            properties = new Properties();
            properties.load(new StringReader(FileUtils.readFileToString(propertiesFile, Charset.forName("UTF-8"))));

            String username = config.get("kms.admin.username");
            String password = config.get("kms.admin.password");
            String url = config.get("aas.api.url");

            if ((username == null) || (username.isEmpty()) || (password == null) || (password.isEmpty()) || (url == null) || url.isEmpty()) {
                log.error("configurations are not set");
                return null;
            }
            tlsPolicy = TlsPolicyBuilder.factory().strictWithKeystore(getTrustStorePath(), TRUSTSTORE_PASSWORD).build();
            aasBearerToken = new AASTokenFetcher().getAASToken(username, password, new TlsConnection(new URL(url), tlsPolicy));
            if ((aasBearerToken == null) || (aasBearerToken.isEmpty())) {
                log.error("Error while retrieving bearer token from AAS");
                return null;
            }
            properties.setProperty("bearer.token", aasBearerToken);

            svsClient = new SVSClient(properties, new TlsConnection(new URL(svsBaseUrl), tlsPolicy));
        } catch (Exception e) {
            log.error("getSvsClientObj: exception while fetching SVS Client object {}", e.getMessage());
            return null;
        }
        return svsClient;
    }

    private void SetQuoteAttributes(Response response) {

        String jsonString = null;
        JsonNode rootNode;

        try {
            jsonString = response.readEntity(String.class);
            rootNode = mapper.readTree(jsonString);
            log.debug("Json Data:{}", jsonString);
            log.debug("Status:{}", rootNode.get("Status").asText());
            log.debug("Message:{}", rootNode.get("Message").asText());
            log.debug("ChallengeKeyType:{}", rootNode.get("ChallengeKeyType").asText());
            log.debug("ChallengeRsaPublicKey:{}", rootNode.get("ChallengeRsaPublicKey").asText());
            verifyResponse.setStatus(rootNode.get("Status").asText());
            verifyResponse.setMessage(rootNode.get("Message").asText());
            verifyResponse.setChallengeKeyType(rootNode.get("ChallengeKeyType").asText());
            verifyResponse.setChallengeRsaPublicKey(rootNode.get("ChallengeRsaPublicKey").asText());

            if (stmLabel.equals("SGX")) {
                verifyResponse.setEnclaveIssuer(rootNode.get("EnclaveIssuer").asText());
                verifyResponse.setEnclaveIssuerProdID(rootNode.get("EnclaveIssuerProdID").asText());
                verifyResponse.setEnclaveIssuerExtProdID(rootNode.get("EnclaveIssuerExtProdID").asText());
                verifyResponse.setEnclaveMeasurement(rootNode.get("EnclaveMeasurement").asText());
                verifyResponse.setConfigSvn(rootNode.get("ConfigSvn").asText());
                verifyResponse.setIsvSvn(rootNode.get("IsvSvn").asText());
                verifyResponse.setConfigId(rootNode.get("ConfigId").asText());
            }
        } catch (Exception ex) {
            log.error("Error while writing Quote verification response attributes");
        }
    }

    public QuoteVerifyResponseAttributes verifySKCQuote(String quote) {
        SVSClient svsObj = getSvsClientObj();
        if (svsObj == null) {
            log.error("svs client object is null");
            return null;
        }
        Response response = null;

        try {
            response = svsObj.quoteVerify(quote);
            if ((response.getStatus() == 200) && (response.hasEntity())) {
                SetQuoteAttributes(response);
            } else if (response.getStatus() == 401) {
                if (!TokenFetcher.updateToken()) {
                    verifyResponse.setStatus("Failed");
                    verifyResponse.setMessage("Error while updating the bearer token");
                } else {
                    TlsPolicy tlsPolicy = TlsPolicyBuilder.factory().strictWithKeystore(TokenFetcher.getTrustStorePath(), "changeit").build();
                    String url = getConfiguration().get("svs.base.url");
                    svsObj = new SVSClient(TokenFetcher.properties, new TlsConnection(new URL(url), tlsPolicy));
                    log.debug("Again calling SQVS verifyQuote API after authentication failure");
                    response = svsObj.quoteVerify(quote);
                    if ((response.getStatus() == 200) && (response.hasEntity())) {
                        SetQuoteAttributes(response);
                    } else {
                        verifyResponse.setStatus("Failed");
                        if (response.getStatus() == 401) {
                            verifyResponse.setMessage("Error from Sgx Verification Service: Unauthorized Access");
                        } else if (response.getStatus() == 400) {
                            verifyResponse.setMessage("Error from Sgx Verification Service: Invalid input received");
                        } else if (response.getStatus() == 500) {
                            verifyResponse.setMessage("Error from Sgx Verification Service: Quote verification Unsuccessful");
                        }
                    }
                }
            } else {
                verifyResponse.setStatus("Failed");
                if (response.getStatus() == 400) {
                    verifyResponse.setMessage("Error from Sgx Verification Service: Invalid input received");
                } else if (response.getStatus() == 500) {
                    verifyResponse.setMessage("Error from Sgx Verification Service: Quote verification Unsuccessful");
                }
            }
        } catch (Exception e) {
            log.error("verifySKCQuote: exception while verify quote data", e);
            return null;
        }
        return verifyResponse;
    }
}
