/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.PrefixConfiguration;
import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.ByteArrayResource;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.flavor.client.jaxrs.Reports;
import com.intel.mtwilson.flavor.rest.v2.model.ReportCreateCriteria;
import com.intel.mtwilson.supplemental.saml.TrustAssertion;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Properties;


/**
 *
 * @author jbuhacoff
 */
public class MtWilsonV2Client implements SecurityAssertionProvider {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MtWilsonV2Client.class);
    private final Configuration configuration;

    public MtWilsonV2Client() throws IOException {
        configuration = ConfigurationFactory.getConfiguration();
    }

    public MtWilsonV2Client(Configuration configuration) {
        this.configuration = configuration;
    }

    /**
     * Sends a GET request to Mt Wilson to check cache If no results, sends a
     * POST request to force attestation
     *
     * GET:
     * <pre>
     * GET https://10.1.71.88:8443/mtwilson/v2/host-attestations?limit=10&aik=9080c913c570f4a56c00b36bf1598ff184e15670&filter=true
     * Accept: application/samlassertion+xml
     * Authorization: Basic am9uYXRoYW46cGFzc3dvcmQ=
     * </pre>
     *
     * POST:
     * <pre>
     * POST https://10.1.71.88:8443/mtwilson/v2/host-attestations
     * Accept: application/samlassertion+xml
     * Content-Type: application/json
     * Authorization: Basic am9uYXRoYW46cGFzc3dvcmQ=
     * {"aik_public_key_sha1":"72de72db9f81dacc8b6aaa486c09e07e94b7f9d6"}
     * </pre>
     *
     * A successful response:
     * <pre>
     * 200
     * Date: Sat, 16 Jan 2016 06:32:27 GMT
     * Transfer-Encoding: chunked
     * Set-Cookie: rememberMe=deleteMe; Path=/mtwilson; Max-Age=0; Expires=Fri, 15-Jan-2016 06:32:27 GMT,JSESSIONID=70A96C28E1E76AE156060723B6720482; Path=/mtwilson/; Secure; HttpOnly,rememberMe=deleteMe; Path=/mtwilson; Max-Age=0; Expires=Fri, 15-Jan-2016 06:32:26 GMT
     * Content-Type: application/samlassertion+xml
     * Server: Apache-Coyote/1.1
     * (saml xml content goes here)
     * </pre>
     *
     * A failure response:
     * <pre>
     * 400
     * Incident-Tag: 421554eb
     * Date: Sat, 16 Jan 2016 06:07:47 GMT
     * Content-Length: 61
     * Set-Cookie: rememberMe=deleteMe; Path=/mtwilson; Max-Age=0; Expires=Fri, 15-Jan-2016 06:07:47 GMT,JSESSIONID=EDCA7C6BCA919D2C5149AE865985186D; Path=/mtwilson/; Secure; HttpOnly,rememberMe=deleteMe; Path=/mtwilson; Max-Age=0; Expires=Fri, 15-Jan-2016 06:07:47 GMT
     * Connection: close
     * Content-Type: text/plain
     * Server: Apache-Coyote/1.1
     * com.intel.mtwilson.repository.RepositoryInvalidInputException
     * </pre>
     *
     * @param subject
     * @return
     * @throws IOException
     */
    @Override
    public String getAssertionForSubject(String subject) throws IOException {
        Reports client = getMtWilsonClient();
	// Don't use the cached attestation report for host. Always use the attestation 
	// report by forcing a complete attestation cycle for the host.
	/*
        // try the mtwilson cache first with a GET request
        try {
            log.debug("Sending GET request to attestation service for aik: {}", subject);
            HostAttestationFilterCriteria criteria = new HostAttestationFilterCriteria();
            criteria.aikPublicKeySha256 = subject;
            String saml = client.searchHostAttestationsSaml(criteria);
            if( saml != null && !saml.isEmpty() ) {
                return saml;
            }
        } catch (Exception e) {
            log.debug("Search for cached SAML report failed: {}", e.getMessage());
        }
	*/
        // try asking for a new attestation report with a POST request
        try {
            log.debug("Sending POST request to attestation service for aik: {}", subject);
            ReportCreateCriteria query = new ReportCreateCriteria();
            query.setAikCertificate(subject);
            String saml = client.createSamlReport(query);
            if( saml != null && !saml.isEmpty() ) {
                return saml;
            }
        } catch (Exception e) {
            log.debug("Request for new SAML report failed; {}", e.getMessage());
        }
        return null;
    }

    public String getAssertionForHarwareUUID(UUID subject) throws IOException {
        Reports client = getMtWilsonClient();

        // try asking for a new attestation report with a POST request
        try {
            log.debug("Sending POST request to attestation service for aik: {}", subject);
            ReportCreateCriteria query = new ReportCreateCriteria();
            query.setHardwareUuid(subject);
            String saml = client.createSamlReport(query);
            if( saml != null && !saml.isEmpty() ) {
                return saml;
            }
        } catch (Exception e) {
            log.debug("Request for new SAML report failed; {}", e.getMessage());
        }
        return null;
    }
     
 
   //Removed com.intel.mtwilson.api.ApiException as mtwilson doesnt build mtwilson-api package 
    public boolean isReportValid(String saml) throws IOException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateEncodingException {
        Reports client = getMtWilsonClient();
        TrustAssertion report = client.verifyTrustAssertion(saml);
        if( report.isValid() ) {
            // signature is valid, check expiration date
            Date notAfter = report.getNotAfter();
            // if there is no expiration date, or the expiration date is AFTER today, then report is valid
            if( notAfter == null || notAfter.after(new Date())) {
                return true;
            }
        }
        return false;
    }

    private Reports getMtWilsonClient() throws IOException {
        //if (configuration.get("mtwilson.endpoint.url") != null && configuration.get("mtwilson.tls.policy.certificate.sha256") != null) {
            //Properties properties = PropertiesConfiguration.toProperties(new PrefixConfiguration(configuration, "mtwilson."));
            Properties properties = new Properties();
            MtWilsonClientConfiguration clientConfig = new MtWilsonClientConfiguration(configuration);

            URL endpointURL = clientConfig.getEndpointURL();

            properties.setProperty("mtwilson.api.username", clientConfig.getEndpointUsername());
            properties.setProperty("mtwilson.api.tls.policy.certificate.sha256",  clientConfig.getMtwilsonSHACert());
            properties.setProperty("mtwilson.api.url", String.format("%s", endpointURL.toExternalForm()));
            properties.setProperty("mtwilson.api.password", clientConfig.getEndpointPassword());
            
            try {
                Reports client = new Reports(properties);
                return client;
            } catch (Exception e) {
                log.error("Cannot instantiate Mt Wilson v2 client", e);
                throw new IOException(e);
            }
        /* Commenting Below as we have only one method to retrieve the MtWilson client through Report client */
        /*    
        } else {
            Properties properties = new Properties();
            
            MtWilsonClientConfiguration clientConfig = new MtWilsonClientConfiguration(configuration);
            try {
                Password password = clientConfig.getKeystorePassword();
                if (password == null) {
                    log.warn("MtWilson Password is not set");
                    password = new Password();
                }
                
                PasswordKeyStore passwordKeyStore = new PasswordKeyStore(new ByteArrayResource(), new Password(new char[0])); // empty password because it's only for in-memory use, we won't be writing out this keystore anywhere
                passwordKeyStore.set("mtwilson.api.key.password", password);
                passwordKeyStore.set("mtwilson.api.keystore.password", password);
                
                URL endpointURL = clientConfig.getEndpointURL();
                if (endpointURL == null) {
                    log.error("MtWilson URL is not set");
                    throw new IllegalArgumentException("Mt Wilson URL is required");
                }
                //properties.setProperty("mtwilson.api.url", String.format("%s/v2", endpointURL.toExternalForm()));
                properties.setProperty("mtwilson.api.keystore", clientConfig.getKeystorePath());
                properties.setProperty("mtwilson.api.key.alias", clientConfig.getEndpointUsername());
                properties.setProperty("mtwilson.api.tls.policy.certificate.sha256", configuration.get(MtWilsonClientConfiguration.MTWILSON_TLS_CERT_SHA256));

                try {
                    //Reports client = new Reports(properties, passwordKeyStore);
                    Reports client = new Reports(properties);
                    return client;
                } catch (Exception e) {
                    log.error("Cannot instantiate Mt Wilson v2 client", e);
                    throw new IOException(e);
                }

            } catch (KeyStoreException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                log.error("Cannot load password", e);
                throw new IOException(e);
            }
        }
        */
    }
}
