/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.saml.jaxrs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.KeyManager;
import com.intel.kms.cipher.PublicKeyReport;
import com.intel.kms.cipher.TransferPublicKeyCipher;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.keystore.KeyManagerFactory;
import com.intel.kms.keystore.KeyTransferUtil;
import com.intel.kms.api.fault.NotTrusted;
import com.intel.kms.tpm.identity.jaxrs.TpmIdentityCertificateRepository;
import com.intel.mtwilson.supplemental.saml.TrustAssertion;
import com.intel.mtwilson.jaxrs2.Link;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.jaxrs2.mediatype.ZipMediaType;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.archive.TarGzipBuilder;
import com.intel.mtwilson.util.tpm20.CertifyKey20;
import com.intel.mtwilson.util.validation.faults.Thrown;
import gov.niarl.his.privacyca.TpmUtils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.DecoderException;
//import org.bouncycastle.asn1.ASN1InputStream;
//import org.bouncycastle.asn1.DERObject;
//import org.bouncycastle.asn1.DEROctetString;
/**
 * Does not extend AbstractEndpoint because kms-saml does not have a dependency
 * on kms-keystore; may need to refactor.
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class TransferKeyWithSAML {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransferKeyWithSAML.class);
    private KeyManager keyManager;
    private KeyTransferUtil keyTransferUtil;

    public KeyManager getKeyManager() throws IOException, ReflectiveOperationException {
        if (keyManager == null) {
            keyManager = KeyManagerFactory.getKeyManager();
        }
        return keyManager;
    }

    private void logFaults(String message, List<Fault> faults) {
        for (Fault f : faults) {
            log.error("{}: {}", message, f.toString());
        }
    }
    
    private KeyTransferUtil getKeyTransferUtil() throws IOException, ReflectiveOperationException {
        if( keyTransferUtil == null ) {
            keyTransferUtil = new KeyTransferUtil(getKeyManager());
        }
        return keyTransferUtil;
    }

    /**
     * Given a SAML trust report from Mt Wilson, checks the trust of the subject
     * and wraps the requested key using the subject's binding public key. The
     * wrapped key and its metadata are returned in a document container in .tgz
     * format.
     *
     * Note that the "keys:transfer" permission is NOT required to access this
     * API since we expect that anonymous clients will use this API to request
     * keys based on trust only.
     *
     * @param keyId
     * @param saml
     * @return
     */
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(CryptoMediaType.APPLICATION_SAML)
    @Produces(ZipMediaType.ARCHIVE_TAR_GZ)
//    @RequiresPermissions("keys:transfer")
    
    public byte[] getKeyWithSamlAsTgz(@PathParam("keyId") String keyId, String saml, @Context HttpServletResponse response) {
        log.debug("getKeyWithSamlAsTgz");
        log.debug("Received trust assertion to transfer key: {}", saml);

        try {
            TransferKeyResponse transferKeyResponse = transferKeyWithSAML(keyId, saml);
            if (!transferKeyResponse.getFaults().isEmpty()) {
                logFaults("Cannot process key transfer", transferKeyResponse.getFaults());
                Integer status = transferKeyResponse.getHttpResponse().getStatusCode();
                if (status == null) {
                    status = Response.Status.UNAUTHORIZED.getStatusCode();
                }
                throw new WebApplicationException(Response.status(status).entity("").build()); // results in full html not authorized response
            }
            byte[] container = createTgzFromTransferKeyResponse(transferKeyResponse);
            return container;
        } catch (IOException e) {
            log.error("Cannot process key request", e);
            throw new WebApplicationException("Internal error", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
  
    /**
     * Given a SAML trust report from Mt Wilson, checks the trust of the subject
     * and wraps the requested key using the subject's binding public key. The
     * wrapped key and its metadata are returned in a PEM-style format with the
     * banner "BEGIN ENCRYPTED SECRET KEY". The content is base-64 encoded
     * encrypted key, when decoded it's the same binary content as is found in
     * the "cipher.key" file in the document container returned by
     * getKeyWithSamlAsTgz
     *
     * Note that the "keys:transfer" permission is NOT required to access this
     * API since we expect that anonymous clients will use this API to request
     * keys based on trust only.
     *
     * @param keyId
     * @param saml
     * @return
     */
    
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(CryptoMediaType.APPLICATION_SAML)
    @Produces(CryptoMediaType.APPLICATION_X_PEM_FILE)
//    @RequiresPermissions("keys:transfer")
    public String getKeyWithSamlAsPem(@PathParam("keyId") String keyId, String saml, @Context HttpServletResponse response) {
        log.debug("getKeyWithSamlAsPem");
        log.debug("Received trust assertion to transfer key: {}", saml);
//        try {
        TransferKeyResponse transferKeyResponse = transferKeyWithSAML(keyId, saml);

        if (!transferKeyResponse.getFaults().isEmpty()) {
            logFaults("Cannot process key transfer", transferKeyResponse.getFaults());
            Integer status = transferKeyResponse.getHttpResponse().getStatusCode();
            if (status == null) {
                status = Response.Status.UNAUTHORIZED.getStatusCode();
            }
            throw new WebApplicationException(Response.status(status).entity("").build()); // results in full html not authorized response
        }

        try {
            Pem pem = getKeyTransferUtil().createPemFromTransferKeyResponse(transferKeyResponse);

            return pem.toString();
        }
        catch(IOException | ReflectiveOperationException e) {
            log.error("getKeyWithSamlAsPem: failed to generate PEM response", e);
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
//        }
//        catch(IOException e) {
//            throw new WebApplicationException("Internal error", Status.INTERNAL_SERVER_ERROR);
//        }

    }
    
    /**
     * Given a SAML trust report from Mt Wilson, checks the trust of the subject
     * and wraps the requested key using the subject's binding public key. The
     * wrapped key and its metadata are returned in a binary format, the same
     * binary content as is found in the "cipher.key" file in the document
     * container returned by getKeyWithSamlAsTgz
     *
     * HTTP headers are added to the response to identify the returned key and
     * possibly some additional attributes of the key, same as would be found in
     * the getKeyWithSamlAsPem.
     *
     * Note that the "keys:transfer" permission is NOT required to access this
     * API since we expect that anonymous clients will use this API to request
     * keys based on trust only.
     *
     * @param keyId
     * @param saml
     * @param response
     * @return
     */
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(CryptoMediaType.APPLICATION_SAML)
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    //@RequiresPermissions("keys:transfer")
    public byte[] getKeyWithSamlAsEncryptedBytes(@PathParam("keyId") String keyId, String saml, @Context HttpServletResponse response) {
        log.debug("getKeyWithSamlAsEncryptedBytes");
        log.debug("Received trust assertion to transfer key: {}", saml);
        TransferKeyResponse transferKeyResponse = transferKeyWithSAML(keyId, saml);
        // if there are no problems, return the key
        if (transferKeyResponse.getFaults().isEmpty()) {
            try {
                Pem pem = getKeyTransferUtil().createPemFromTransferKeyResponse(transferKeyResponse);
                for (String headerName : pem.getHeaders().keySet()) {
                    response.addHeader(headerName, pem.getHeaders().get(headerName));
                }
                return transferKeyResponse.getKey();
            }
            catch(IOException | ReflectiveOperationException e) {
                log.error("getKeyWithSamlAsEncryptedBytes: failed to generate PEM response", e);
                throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
            }
        }
        // otherwise, return an error message using hint provided by business object, if available
        logFaults("Cannot process key transfer", transferKeyResponse.getFaults());
        if (transferKeyResponse.getHttpResponse().getStatusCode() != null) {
            log.debug("Setting http status code {}", transferKeyResponse.getHttpResponse().getStatusCode());
            /*
             response.setStatus(transferKeyResponse.getHttpResponse().getStatusCode());
             for(String name : transferKeyResponse.getHttpResponse().getHeaders().keys() ) {
             for(String value : transferKeyResponse.getHttpResponse().getHeaders().get(name)) {
             log.debug("Adding error response header {}: {}", name, value);
             response.addHeader(name, value);
             }
             }
             return null;
             */
            throw new WebApplicationException(transferKeyResponse.getHttpResponse().getStatusCode());
        }
        throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }


    /**
     *
     * @param keyId
     * @param saml
     * @return a response object
     * @throws WebApplicationException if request is invalid or if client is
     * unauthorized to receive the key
     */
    private TransferKeyResponse transferKeyWithSAML(String keyId, String saml) {
        
        

        if (saml == null || saml.isEmpty()) {
            TransferKeyResponse transferKeyResponse = new TransferKeyResponse(null, null);
            transferKeyResponse.getHttpResponse().setStatusCode(Response.Status.UNAUTHORIZED.getStatusCode());
            transferKeyResponse.getFaults().add(new NotTrusted("No SAML in request"));
            return transferKeyResponse;
        }

        try {
			TrustReport client = isTrustedByMtWilson(saml);
            if (client != null && client.isTrusted()) {
                log.debug("Client is trusted, need to return key now");

                PublicKey recipientPublicKey = null;

                if (client.getPublicKey() != null) {
                    log.debug(" getPublicKey not null so need to return key now");
                    recipientPublicKey = client.getPublicKey();
                }
                /* no key contexts defined for CIT 3 */
                return getKeyTransferUtil().transferKeyWithRemoteAttestation(keyId, null, recipientPublicKey, null);
            } else {
                //throw new WebApplicationException("Unauthorized", Status.UNAUTHORIZED);
                TransferKeyResponse transferKeyResponse = new TransferKeyResponse(null, null);
                transferKeyResponse.getHttpResponse().setStatusCode(Response.Status.UNAUTHORIZED.getStatusCode());
                transferKeyResponse.getFaults().add(new NotTrusted("Not trusted by Mt Wilson"));
                return transferKeyResponse;
            }
        } catch (IOException | ReflectiveOperationException | GeneralSecurityException | TpmUtils.TpmBytestreamResouceException | TpmUtils.TpmUnsignedConversionException | CryptographyException e) {
//            throw new WebApplicationException("Invalid request", e);
            TransferKeyResponse transferKeyResponse = new TransferKeyResponse(null, null);
            transferKeyResponse.getHttpResponse().setStatusCode(Response.Status.BAD_REQUEST.getStatusCode());
            transferKeyResponse.getFaults().add(new Thrown(e));
            return transferKeyResponse;
        }
    }



    private byte[] createTgzFromTransferKeyResponse(TransferKeyResponse transferKeyResponse) throws JsonProcessingException, IOException {
        // create cipher.key
        byte[] cipherKey = transferKeyResponse.getKey(); // already encrypted  - the key manager already did the binding/wrapping
        // create cipher.json
//        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
//        String cipherJson = mapper.writeValueAsString(transferKeyResponse.getDescriptor()); // describes the cipher key and its encryption/integrity information but does not include the cipher key itself
        String cipherJson = (String) transferKeyResponse.getExtensions().get("cipher.json"); // see DirectoryKeyManager transferKey;  we could generate it using the line above BUT it's already been signed by the key manager so we need to make sure we use exactly what the key manager provided so the client can verify the signature
        // create server.crt
//        byte[] serverCertificate = null; // XXX TODO load the server certificat from configuration (need setup task to create it -- this is NOT ssl cert, it's key signing cert)
        // create integrity.sig
        byte[] integritySig = (byte[]) transferKeyResponse.getExtensions().get("integrity.sig"); // see DirectoryKeyManager transferKey
        // create index.html
        String indexHtml = createIndexHtml(transferKeyResponse); //  create index.html with entry point link to integrity.json (verify package) and cipher.json (how to decrypt cipher.key)
        // create key.tgz with these files
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        TarGzipBuilder builder = new TarGzipBuilder(buffer);
        builder.add("cipher.key", cipherKey);
        builder.add("cipher.json", cipherJson);
//        builder.add("server.crt", serverCertificate);
        builder.add("integrity.sig", integritySig);
        builder.add("index.html", indexHtml);
        builder.close();
        return buffer.toByteArray();
    }

    // create index.html with entry point link to integrity.json (verify package) and cipher.json (how to decrypt cipher.key)
    // TODO: use a template language, like StringTemplate
    private String createIndexHtml(TransferKeyResponse transferKeyResponse) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head>");
        if (transferKeyResponse.getDescriptor().get("links") != null) {
            for (Link link : (List<Link>) transferKeyResponse.getDescriptor().get("links")) {
                html.append(String.format("<link rel=\"%s\" href=\"%s\" type=\"%s\">", link.getRel(), link.getHref(), link.getType()));
            }
        }
        html.append("</head></html>");
        return html.toString();
    }


    private X509Certificate[] getTrustedSamlCertificateAuthorities() throws IOException, GeneralSecurityException, CryptographyException {
//        Configuration configuration = ConfigurationFactory.getConfiguration();
//        File mtwilsonKeystore = new File(Folders.configuration() + File.separator + "mtwilson.jks");
        SamlCertificateRepository repository = new SamlCertificateRepository();
        List<X509Certificate> list = repository.getCertificates();
        return list.toArray(new X509Certificate[0]);
    }

    private X509Certificate[] getTrustedTpmIdentityCertificateAuthorities() throws IOException, GeneralSecurityException, CryptographyException {
//        Configuration configuration = ConfigurationFactory.getConfiguration();
//        File mtwilsonKeystore = new File(Folders.configuration() + File.separator + "mtwilson.jks");
        TpmIdentityCertificateRepository repository = new TpmIdentityCertificateRepository();
        List<X509Certificate> list = repository.getCertificates();
        return list.toArray(new X509Certificate[0]);
    }

    public static class TrustReport {

        public static final TrustReport UNTRUSTED = new TrustReport(false, null /*, new byte[0]*/);
        private boolean trusted = false;
        private PublicKey publicKey = null;
//        private byte[] encScheme = {0};

        public TrustReport(boolean trusted, PublicKey publicKey /*, byte[] encScheme*/) {
            this.trusted = trusted;
            this.publicKey = publicKey;
//            this.encScheme = encScheme;
        }

        public boolean isTrusted() {
            return trusted;
        }

        /**
         * Public key to use when wrapping a key to transfer to the trusted
         * client.
         *
         * XXX TODO there should also be an indication of the client's supported
         * algorithms and formats... especially if the corresponding private key
         * is bound to a TPM 1.2 which supports only RSA and requires OAEP
         * padding with "TCPA" as the padding parameter.
         *
         * @return
         */
        public PublicKey getPublicKey() {
            return publicKey;
        }
       /* 
        public int getEncScheme() throws IOException {
            Short num = null;
            DERObject derObject = toDERObject(encScheme);
            if (derObject instanceof DEROctetString){
                DEROctetString derOctetString = (DEROctetString) derObject;
                num = ByteBuffer.wrap(derOctetString.getOctets()).asShortBuffer().get();
    }
            return num;
        }
		
		private DERObject toDERObject(byte[] data) throws IOException {
			ByteArrayInputStream inStream = new ByteArrayInputStream(data);
			ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
			return asnInputStream.readObject();
		}
		*/ 
    }

    private X509Certificate findCertificateIssuer(X509Certificate subject, X509Certificate[] authorities) {
        X509Certificate issuer = null;
        for (X509Certificate authority : authorities) {
            if (log.isDebugEnabled()) {
                try {
                    String authorityCertificateDigest = Sha384Digest.digestOf(authority.getEncoded()).toHexString();
                    log.debug("Checking certificate against authority: {} in certificate: {}", authority.getSubjectX500Principal().getName(), authorityCertificateDigest);
                } catch (CertificateEncodingException e) {
                    log.error("Cannot encode certificate for authority: {}", authority.getSubjectX500Principal().getName(), e);
                }
            }
            if (authority.getSubjectX500Principal().getName().equals(subject.getIssuerX500Principal().getName())) {
                try {
                    authority.checkValidity();
                    subject.verify(authority.getPublicKey());
                    issuer = authority;
                    log.debug("Certificate signed by authority: {}", authority.getSubjectX500Principal().getName());
                } catch (GeneralSecurityException e) {
                    log.debug("Verification failed: {}", e.getMessage());
                }
            }
        }
        return issuer;
    }

    private TrustReport isTrustedByMtWilson(String saml) throws IOException, GeneralSecurityException, CryptographyException, TpmUtils.TpmBytestreamResouceException, TpmUtils.TpmUnsignedConversionException {
        
        log.debug("TrustReport: Saml as String {}", saml); 
        X509Certificate[] trustedSamlAuthorities = getTrustedSamlCertificateAuthorities();
        TrustAssertion trustAssertion = new TrustAssertion(trustedSamlAuthorities, saml);
        log.debug("trust assertion valid? {}", trustAssertion.isValid());
     
        if (!trustAssertion.isValid()) {
            log.error("Invalid signature on trust report", trustAssertion.error());
            return TrustReport.UNTRUSTED;
        }
    
        log.debug("trust status for {}", trustAssertion.getHosts());
        // we only support getting an assertion for one host, so
        // find the first listed host and throw an exception if there's more
        // than one
        Set<String> hostnames = trustAssertion.getHosts();
        if (hostnames == null || hostnames.isEmpty() || hostnames.size() > 1) {
            log.error("Invalid SAML report, expecting exactly one hostname but found: {}", hostnames);
            return TrustReport.UNTRUSTED;
        }
        String hostname = hostnames.toArray(new String[1])[0];

        log.debug("hostname: {}", hostname);
        com.intel.mtwilson.supplemental.saml.TrustAssertion.HostTrustAssertion hostTrustAssertion = trustAssertion.getTrustAssertion(hostname);

        log.debug("trust assertion for host {}", hostTrustAssertion);
        log.debug("host is trusted? {}", hostTrustAssertion.isHostTrusted());

        if (!hostTrustAssertion.isHostTrusted()) {
            log.error("Host is not trusted");
            return TrustReport.UNTRUSTED;
        }

        log.debug("Host is trusted: {}", hostname);

        X509Certificate[] trustedTpmIdentityAuthorities = getTrustedTpmIdentityCertificateAuthorities();

        X509Certificate aikCertificate = hostTrustAssertion.getAikCertificate();
        if (aikCertificate == null) {
            log.error("Assertion does not include AIK Certificate");
            return TrustReport.UNTRUSTED;
        }
        log.debug("AIK Certificate SHA-384: {}", Sha384Digest.digestOf(aikCertificate.getEncoded()).toHexString());

        /*
         * Verify the AIK is signed by a trusted Privacy CA (Mt Wilson)
         */
        X509Certificate aikIssuer = findCertificateIssuer(aikCertificate, trustedTpmIdentityAuthorities);
        if (aikIssuer == null) {
            log.error("AIK certificate not verified any trusted authority");
            return TrustReport.UNTRUSTED;
        }

        /*
         * Check that AIK is currently valid
         */
        try {
            aikCertificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            log.error("AIK certificate not currently valid; dates from {} to {}", aikCertificate.getNotBefore().toString(), aikCertificate.getNotAfter().toString());
        }

        
         PublicKey aikPublicKey = hostTrustAssertion.getAikPublicKey();
         if( aikPublicKey == null ) {
         log.error("Assertion does not include AIK Public Key");
         return TrustReport.UNTRUSTED;
         }

        //PublicKey aikPublicKey = aikCertificate.getPublicKey();
        log.debug("AIK Public Key SHA-384: {}", Sha384Digest.digestOf(aikPublicKey.getEncoded()).toHexString());

        /*
         * We check that the AIK certified the binding key because
         * at this time Mt Wilson does not check this at the time the report
         * is generated, only when the binding key is registered with Mt Wilson.
         * This is done in two steps:
         * First a standard X.509 signature verification
         * on the binding key certificate by any trusted TPM identity authority
         * (may not be the same one that issued the AIK in the case of a cluster
         * of Mt Wilson servers).
         * Second, the binding key certificate attributes are used to verify
         * that the AIK signed the binding key. This links the binding key 
         * to the same TPM as the AIK.
         */
        X509Certificate bindingKeyCertificate = hostTrustAssertion.getBindingKeyCertificate();
        if (bindingKeyCertificate == null) {
            log.error("No binding key certificate in trust report");
            return TrustReport.UNTRUSTED;
        }
        log.debug("Binding Certificate SHA-384: {}", Sha384Digest.digestOf(bindingKeyCertificate.getEncoded()).toHexString());
        log.debug("Binding Public Key SHA-384: {}", Sha384Digest.digestOf(bindingKeyCertificate.getPublicKey().getEncoded()).toHexString());
        X509Certificate bindingKeyIssuer = findCertificateIssuer(bindingKeyCertificate, trustedTpmIdentityAuthorities);
        if (bindingKeyIssuer == null) {
            log.error("Binding key certificate not verified by any trusted authority");
            return TrustReport.UNTRUSTED;
        }

        /*
         * Check that binding key certificate is currently valid
         */
        try {
            bindingKeyCertificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            log.error("Binding key certificate not currently valid; dates from {} to {}", bindingKeyCertificate.getNotBefore().toString(), bindingKeyCertificate.getNotAfter().toString());
        }

        /* now verify binding key has the tpm-bind-data flag set and the migration flag NOT set */
        String os = hostTrustAssertion.getVMMOSName();
        String tpmVersion = hostTrustAssertion.getTPMVersion();
        log.debug("tpmVersion: {}", tpmVersion);

        if(tpmVersion.equals("2.0")){

            if (os.toLowerCase().contains("win")) {
                try {
                    if (!CertifyKey20.isCertifiedKeySignatureValid(com.intel.mtwilson.util.tpm20.x509.TpmCertifyKeyInfo.valueOf(bindingKeyCertificate.getExtensionValue(com.intel.mtwilson.util.tpm20.x509.TpmCertifyKeyInfo.OID)).getBytes(), com.intel.mtwilson.util.tpm20.x509.TpmCertifyKeySignature.valueOf(bindingKeyCertificate.getExtensionValue(com.intel.mtwilson.util.tpm20.x509.TpmCertifyKeySignature.OID)).getBytes(), aikPublicKey)) {
                        log.debug("TPM Binding Public Key cannot be verified by the given AIK public key");
                        return TrustReport.UNTRUSTED;
                    }
                } catch (GeneralSecurityException | DecoderException e) {
                    log.debug("Cannot verify TPM Binding Public Key signature", e);
                    return TrustReport.UNTRUSTED;
                }
            } else {
                if (!CertifyKey20.verifyTpmBindingKeyCertificate(bindingKeyCertificate, aikPublicKey)) {
                    log.error("Binding key certificate has invalid attributes or cannot be verified with the AIK");
                    return TrustReport.UNTRUSTED;
                }
            }
        }
        else
        {
            log.error("Unable to get tpm info, Binding key certificate cannot be verified with the AIK");
            return TrustReport.UNTRUSTED;
        }


        return new TrustReport(true, bindingKeyCertificate.getPublicKey());/*, bindingKeyCertificate.getExtensionValue("2.5.4.133.3.2.41.2")*/
    }
    
    /*
    private boolean tpm20Certified(X509Certificate bindingKeyCertificate, PublicKey aikPublicKey) {
        try {
            if (!CertifyKey20.verifyTpmBindingKeyCertificate(bindingKeyCertificate, aikPublicKey)) {
                log.error("Cannot certify TPM 2.0 binding key certificate");
                return false;
		}
        } catch (Exception ex) {
            log.error("Exception thrown while certifying TPM 2.0 binding key certificate", ex);
            return false;
        }
        return true;
    }
    */
}

