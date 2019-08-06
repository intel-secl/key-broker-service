package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import com.intel.mtwilson.tag.model.Certificate;
import com.intel.mtwilson.tag.model.CertificateCollection;
import com.intel.mtwilson.tag.model.CertificateFilterCriteria;

/**
 * The API resource is used to create, delete and update SAML certificates.
 * @author rksavino
 */
public class SamlCertificates extends JaxrsClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlCertificates.class);
    
    /**
     * To use password-based HTTP BASIC authorization with the user server, 
     * the client must be initialized with the following properties:
     * endpoint.url, login.basic.username, login.basic.password, and any valid TLS
     * policy. The example below uses the Properties format, a sample URL, and
     * a sample TLS certificate SHA-384 fingerprint:
     *<pre>
     * endpoint.url=https://kms.example.com
     * tls.policy.certificate.sha384=3e290080376a2a27f6488a2e10b40902b2194d701625a9b93d6fb25e5f5deb194b452544f8c5c3603894eb56eccb3057
     * login.basic.username=client-username
     * login.basic.password=client-password
     * </pre>
     */
    public SamlCertificates(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public SamlCertificates(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    /**
     * Creates a SAML certificate in the service database.
     * <pre>
     * This method registers a SAML public key certificate to this service. During the SAML transfer
     * key API call, a SAML report containing the same SAML certificate is provided and the
     * certificate is compared and verified against the SAML certificates registered with this service.
     * The certificate object model includes an ID, base64 encoded certificate and a revoked status.
     * </pre>
     * @param certificate The serialized certificate java model object represents the content of the<br/>
     * request body. Only the certificate portion is specified in the request.<br/>
     * <pre>
     * 
     *              id (optional)                    Certificate UUID that is randomly generated if
     *                                               not specified
     * 
     *              certificate (required)           Base64 encoded SAML certificate
     * 
     *              revoked (optional)               Boolean indicating whether the certificate is
     *                                               valid for the service
     * </pre>
     * @return The serialized certificate java model object that was created.
     * @since ISecL 2.0
     * @mtwRequiresPermissions saml_certificates:create
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre>
     * https://kms.server.com:kms_port/v1/saml-certificates
     * 
     * Headers:
     * Content-Type: application/x-pem-file
     * 
     * Input:
     *         -----BEGIN CERTIFICATE-----
     *         MIIDIjCCAgqgAwIBAgIIBrxF7PYTjakwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMxHDAa
     *         BgNVBAoTE1RydXN0ZWQgRGF0YSBDZW50ZXIxEjAQBgNVBAsTCU10IFdpbHNvbjEQMA4GA1UEAxMH
     *         Q049dGVzdDAeFw0xODEyMjcwMzI3MzZaFw0xODEyMjcwNDI3MzZaMFExCzAJBgNVBAYTAlVTMRww
     *         GgYDVQQKExNUcnVzdGVkIERhdGEgQ2VudGVyMRIwEAYDVQQLEwlNdCBXaWxzb24xEDAOBgNVBAMT
     *         B0NOPXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCohoz8Ptxnfqv+iZMApxGz
     *         ra5viot1dbYLL+OVY5/1+S1yEFXNUPmELO6gGhmRPO9LQgCgIRiSDSWTjiOXcoVppEQfgCQupSpr
     *         eHeXyc37Ee5dAk7rwansVjAFJtnrPzOeuVpRAxvI6FWd6qTKRhItaaGITx8n9MJXdL5Gd3qPeBXP
     *         Uj/U2aS9ViBajDPVxcAEeyWZsjxw+FdEtylCLR/nRYB70xafWuU7/iZWe5uPqbkldOD6xMK2hYhC
     *         wit5y6F79uDB+2OULOA5cnQPh+enWbqNiVCiW1sV+fZWcjo24q9duG6Kv7B0UawtF2TYoXKJkzwr
     *         pYRTVBpnZoH9jrzvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADEC64z3kyfOMMOkAO3OcQqjhwmH
     *         6UMslSjakNi2SmXMWeF/JUJmasawaKy0eQ9iZrgDIPw4ndvd0CaY3bf9e0eIijoYsrD2/oOw4f9U
     *         BZsbKE44s9QX7Byi5D1xtCxuKdRWFK+487GHuNAYpR/7Cgff2DVDro1q2WZLwgJs9X0TMqXzSJV3
     *         //HsWVIKRzXR14dJqrXO8JbQzWy5z+j5bHnSsTL2WmJY+a5xPdlPitbkKQDlPeHWKMA3IwsjHtNM
     *         v39A87oxcrc7rx6CycfSFDidz8a5OVH5Hkm4XquX6K2LDLcbesAkdId9Yge92zO0cHTZI2rD/ztF
     *         Yz78/Zo9py8=
     *         -----END CERTIFICATE-----
     * 
     * Output:
     * {
     *      "id": "9ea0c8b5-590f-481d-a5de-46edfbfbf8cc",
     *      "certificate": "MIIDIjCCAgqgAwIBAgIIBrxF7PYTjakwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMxHDAa
     *                      BgNVBAoTE1RydXN0ZWQgRGF0YSBDZW50ZXIxEjAQBgNVBAsTCU10IFdpbHNvbjEQMA4GA1UEAxMH
     *                      Q049dGVzdDAeFw0xODEyMjcwMzI3MzZaFw0xODEyMjcwNDI3MzZaMFExCzAJBgNVBAYTAlVTMRww
     *                      GgYDVQQKExNUcnVzdGVkIERhdGEgQ2VudGVyMRIwEAYDVQQLEwlNdCBXaWxzb24xEDAOBgNVBAMT
     *                      B0NOPXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCohoz8Ptxnfqv+iZMApxGz
     *                      ra5viot1dbYLL+OVY5/1+S1yEFXNUPmELO6gGhmRPO9LQgCgIRiSDSWTjiOXcoVppEQfgCQupSpr
     *                      eHeXyc37Ee5dAk7rwansVjAFJtnrPzOeuVpRAxvI6FWd6qTKRhItaaGITx8n9MJXdL5Gd3qPeBXP
     *                      Uj/U2aS9ViBajDPVxcAEeyWZsjxw+FdEtylCLR/nRYB70xafWuU7/iZWe5uPqbkldOD6xMK2hYhC
     *                      wit5y6F79uDB+2OULOA5cnQPh+enWbqNiVCiW1sV+fZWcjo24q9duG6Kv7B0UawtF2TYoXKJkzwr
     *                      pYRTVBpnZoH9jrzvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADEC64z3kyfOMMOkAO3OcQqjhwmH
     *                      6UMslSjakNi2SmXMWeF/JUJmasawaKy0eQ9iZrgDIPw4ndvd0CaY3bf9e0eIijoYsrD2/oOw4f9U
     *                      BZsbKE44s9QX7Byi5D1xtCxuKdRWFK+487GHuNAYpR/7Cgff2DVDro1q2WZLwgJs9X0TMqXzSJV3
     *                      //HsWVIKRzXR14dJqrXO8JbQzWy5z+j5bHnSsTL2WmJY+a5xPdlPitbkKQDlPeHWKMA3IwsjHtNM
     *                      v39A87oxcrc7rx6CycfSFDidz8a5OVH5Hkm4XquX6K2LDLcbesAkdId9Yge92zO0cHTZI2rD/ztF
     *                      Yz78/Zo9py8=",
     *      "revoked": false
     * }
     * </pre>
     */
    public Certificate createSamlCertificate(Certificate certificate) {
        Certificate created = getTarget().path("/v1/saml-certificates").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(certificate), Certificate.class);
        return created;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificate
     * 
     */
    public void deleteSamlCertificate(Certificate certificate) {
        deleteSamlCertificate(certificate.getId().toString());
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificateId
     * 
     */
    public void deleteSamlCertificate(String certificateId) {
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", certificateId);
        getTarget().path("/v1/saml-certificates/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).delete();
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificate
     * @return 
     * 
     */
    public Certificate editSamlCertificate(Certificate certificate) {
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", certificate.getId());
        Certificate edited = getTarget().path("/v1/saml-certificates/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).put(Entity.json(certificate), Certificate.class);
        return edited;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param filterCriteria
     * @return 
     * 
     **/
    public CertificateCollection searchSamlCertificates(CertificateFilterCriteria filterCriteria) {
        CertificateCollection searchCertificatesResponse = getTargetPathWithQueryParams("/v1/saml-certificates", filterCriteria).request().accept(MediaType.APPLICATION_JSON).get(CertificateCollection.class);
        return searchCertificatesResponse;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param certificateId
     * @return 
     * 
     **/
    public Certificate retrieveSamlCertificate(String certificateId) {
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", certificateId);
        Certificate retrieved = getTarget().path("/v1/saml-certificates/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).get(Certificate.class);
        return retrieved;
    }
    
    
}
