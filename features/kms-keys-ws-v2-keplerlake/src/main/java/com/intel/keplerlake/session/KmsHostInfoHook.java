/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.keplerlake.session;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.digest.Digest;
import com.intel.keplerlake.io.ByteArrayRepository;
import com.intel.kms.keplerlake.KeplerLakeUtil;
import com.intel.mtwilson.model.Hostname;
import com.intel.mtwilson.policy.TrustReport;
import com.intel.mtwilson.trust.verifier.Services.MtwilsonTrustVerifier;
import com.intel.mtwilson.trust.verifier.model.Host;
import com.intel.mtwilson.trust.verifier.processors.MtwilsonTrustVerifierAgent;
import com.intel.mtwilson.util.tpm12.TpmPublicKey;
import com.intel.keplerlake.io.Etcdctl3;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author jbuhacoff
 */
public class KmsHostInfoHook implements HostInfoHook {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KmsHostInfoHook.class);
    final private Configuration configuration;
    final private ObjectMapper mapper = new ObjectMapper();
    final private KeplerLakeUtil keplerLakeUtil;

    public KmsHostInfoHook(Configuration configuration) {
        this.configuration = configuration;
        this.keplerLakeUtil = new KeplerLakeUtil(configuration);
    }

    /**
     * Get the permissions to assign to this host based on information, for
     * example its address, TLS certificate, flavor id, or host group.
     *
     * @param hostInfo
     * @return
     */
    @Override
    public Set<String> getPermissions(HostInfo hostInfo) {
        HashSet<String> permissions = new HashSet<>();
        permissions.add("keys:transfer");
        permissions.add("keys:retrieve");
        permissions.add("keys:delete");
        return permissions;
    }

    @Override
    public String getRealm() {
        return configuration.get("TDC_REALM");
    }

    @Override
    public String getEndpoint() {
        return configuration.get("endpoint.url") + "/v1";     //example: https://10.1.69.84:443/v1
    }

    private Host convertToVerifierHostInput(HostInfo hostInfo, String challengerLabel) {
        Host mtHost = new Host();
        mtHost.setChallengerLabel(challengerLabel); // challenger name
        mtHost.setTlsPolicy(hostInfo.tlsPolicy);
        String hostAddress = hostInfo.addr; // getProxyHostAddressFromURL(connectionString);
        log.debug("hostaddress from host url:{}", hostAddress);
        mtHost.setHostname(new Hostname(hostAddress));
        mtHost.setPort(1443);
        String connectionString = String.format("https://%s:1443/v2", hostInfo.addr);
        log.debug("remoteAttestation url: {}", connectionString);
        mtHost.setConnectionString(connectionString);     // example: https://10.105.151.109:1443;kpladmin;kpl123"
        mtHost.setCallBackToken(hostInfo.callbackToken);

        if (hostInfo.aikPublicKey != null) {
            mtHost.setAikSha256(Digest.sha256().digest(hostInfo.aikPublicKey.getEncoded()).toHex());
        }

        return mtHost;
    }

    private TrustReport getTrustReport(Host mtHost, String flavor) {
        MtwilsonTrustVerifier citVerifier = new MtwilsonTrustVerifierAgent(mtHost.getCallBackToken());
        log.debug("remoteAttestation verifying host meassurements against flavor: {}", flavor);
        TrustReport trustReport = null;
        try {
            trustReport = citVerifier.getTrustReport(mtHost, flavor); // return value is never null
        } catch (Exception e) {
            log.error("Failed remoteAttestation verifying host meassurements against flavor", e);
        }
        return trustReport;
    }

    @Override
    public void remoteAttestation(HostInfo hostInfo, String flavor) {
        // previously the kms would connect to tdc to get host information.
        // now the host provides the necessary information in request headers.
        // it's the same information used to enroll the host with tdc:
        // addr, flavorId, tlsCertificateDigest
        log.debug("remoteAttestation for addr: {}", hostInfo.addr);

        try {

            Host mtHost = convertToVerifierHostInput(hostInfo, "TDC");
            log.debug("remoteAttestation host input to trust verifier: {} ", mapper.writeValueAsString(mtHost));
            TrustReport trustReport = getTrustReport(mtHost, flavor);
            log.debug("remoteAttestation trust report is {} ", mapper.writeValueAsString(trustReport));
            // prepare database updates dependent on host status
            if (trustReport!=null && trustReport.isTrusted()) {
                log.debug("remoteAttestation host measurements match flavor");
                hostInfo.bindingPublicKey = TpmPublicKey.valueOf(trustReport.getHostReport().bindingPubKey).toPublicKey();
                hostInfo.aikPublicKey = trustReport.getHostReport().aik.getPublicKey();
            }
                
        } catch (JsonProcessingException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Error in SessionTokenMonitoringService for host: {}", hostInfo.addr, e);
        }
    }

    @Override
    public ByteArrayRepository getByteArrayRepository() throws IOException {
        Etcdctl3 etcdctl3 = new Etcdctl3(keplerLakeUtil.getEnvMap());
        return etcdctl3;
    }
}
