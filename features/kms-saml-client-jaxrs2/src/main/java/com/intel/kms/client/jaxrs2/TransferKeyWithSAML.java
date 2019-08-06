package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.client.Entity;

/**
 * The API resource is used to retrieve a key by providing a host SAML report.
 *
 * @author rksavino
 */
public class TransferKeyWithSAML extends JaxrsClient {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransferKeyWithSAML.class);
    
    /**
     * To use password-based HTTP BASIC authorization with the key server, the
     * client must be initialized with the following properties: endpoint.url,
     * login.basic.username, login.basic.password, and any valid TLS policy. The
     * example below uses the Properties format, a sample URL, and a sample TLS
     * certificate SHA-1 fingerprint:
     * <pre>
     * endpoint.url=https://kms.example.com
     * tls.policy.certificate.sha384=3e290080376a2a27f6488a2e10b40902b2194d701625a9b93d6fb25e5f5deb194b452544f8c5c3603894eb56eccb3057
     * login.basic.username=client-username
     * login.basic.password=client-password
     * </pre>
     *
     */
    public TransferKeyWithSAML(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    
    public TransferKeyWithSAML(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    /**
     * Retrieves a key wrapped with a binding key certificate provided by a given SAML report.
     * <pre>
     * This method retrieves a specified key by validating the contents of a provided host SAML report. The SAML certificate is
     * extracted from the provided report and verfied agaist the list of registered SAML certificates with this service. Then,
     * the AIK certificate and the binding key certificate are extracted from the same report, and it is verified that a TPM
     * identity certificate registered with this service has signed them. Finally, the host attributes are evaluated to confirm
     * that the host is trusted in the HVS. After verifying the contents of the SAML report, the binding key certificate is used
     * to encrypt the key retrieved from this service.
     * </pre>
     * @param keyId The key UUID provided as a path parameter.
     * @param saml The host SAML report.<br/>
     * @return The PEM formatted key wrapped with the SAML report provided binding key certificate.
     * @since ISecL 2.0
     * @mtwRequiresPermissions none
     * @mtwContentTypeReturned ARCHIVE_TAR_GZ/APPLICATION_X_PEM_FILE/APPLICATION_OCTET_STREAM
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * https://kms.server.com:kms_port/v1/keys/e6aa42d9-802e-4a1d-87f6-f525e1a928f6/transfer
     * 
     * Headers:
     * Content-Type: application/samlassertion+xml
     * Accept: application/x-pem-file
     * 
     * Input:
     * {@code
     *         <?xml version="1.0" encoding="UTF-8"?>
     *         <saml2:Assertion ID="MapAssertion" IssueInstant="2018-12-27T03:27:39.095Z" Version="2.0"
     *         xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
     *             <saml2:Issuer>https://10.105.167.79:8443</saml2:Issuer>
     *             <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
     *                 <SignedInfo>
     *                     <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
     *                     <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
     *                     <Reference URI="#MapAssertion">
     *                         <Transforms>
     *                             <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
     *                         </Transforms>
     *                         <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
     *                         <DigestValue>yQkJ1jRp2jB363n1JwcYJQph9PtxoMWeQYg9lkeaEG4=</DigestValue>
     *                     </Reference>
     *                 </SignedInfo>
     *                 <SignatureValue>nDLBfFUMiV1mUGL2muZ3JArjjGuifYD6vNfG/48TPUEqu3y64sBdsnBC0ObrrDoMzPFdHDQ6/oAS
     *                     91bjmkCdVSZAN0XexPOSg6TGXUCoCP9IiJOT0lZd7ktkzg9XgxBBTSfJFeUimvzr5O6Y/JhjVIfK
     *                     WJbh+aMWP5TdkJp0H4Yknfb/Q+JOJwItw3wAt/F0WNlGmXIylAUV6ReKpNxm0KtUKbbDTJ7b0cQq
     *                     KDHR3XM1qbtJ5JzvXFSCFT8VCV8VUrI2ghXznAPEGc2siHjh5Fo7ayC4LfS0EhQczgioGfpEiJ8q
     *                     +u135XjDlUvbfkXrtVcXl0ic6RgbhlQve4wJDA==</SignatureValue>
     *                 <KeyInfo>
     *                     <X509Data>
     *                         <X509Certificate>MIIDIjCCAgqgAwIBAgIIBrxF7PYTjakwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMxHDAa
     *                             BgNVBAoTE1RydXN0ZWQgRGF0YSBDZW50ZXIxEjAQBgNVBAsTCU10IFdpbHNvbjEQMA4GA1UEAxMH
     *                             Q049dGVzdDAeFw0xODEyMjcwMzI3MzZaFw0xODEyMjcwNDI3MzZaMFExCzAJBgNVBAYTAlVTMRww
     *                             GgYDVQQKExNUcnVzdGVkIERhdGEgQ2VudGVyMRIwEAYDVQQLEwlNdCBXaWxzb24xEDAOBgNVBAMT
     *                             B0NOPXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCohoz8Ptxnfqv+iZMApxGz
     *                             ra5viot1dbYLL+OVY5/1+S1yEFXNUPmELO6gGhmRPO9LQgCgIRiSDSWTjiOXcoVppEQfgCQupSpr
     *                             eHeXyc37Ee5dAk7rwansVjAFJtnrPzOeuVpRAxvI6FWd6qTKRhItaaGITx8n9MJXdL5Gd3qPeBXP
     *                             Uj/U2aS9ViBajDPVxcAEeyWZsjxw+FdEtylCLR/nRYB70xafWuU7/iZWe5uPqbkldOD6xMK2hYhC
     *                             wit5y6F79uDB+2OULOA5cnQPh+enWbqNiVCiW1sV+fZWcjo24q9duG6Kv7B0UawtF2TYoXKJkzwr
     *                             pYRTVBpnZoH9jrzvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADEC64z3kyfOMMOkAO3OcQqjhwmH
     *                             6UMslSjakNi2SmXMWeF/JUJmasawaKy0eQ9iZrgDIPw4ndvd0CaY3bf9e0eIijoYsrD2/oOw4f9U
     *                             BZsbKE44s9QX7Byi5D1xtCxuKdRWFK+487GHuNAYpR/7Cgff2DVDro1q2WZLwgJs9X0TMqXzSJV3
     *                             //HsWVIKRzXR14dJqrXO8JbQzWy5z+j5bHnSsTL2WmJY+a5xPdlPitbkKQDlPeHWKMA3IwsjHtNM
     *                             v39A87oxcrc7rx6CycfSFDidz8a5OVH5Hkm4XquX6K2LDLcbesAkdId9Yge92zO0cHTZI2rD/ztF
     *                             Yz78/Zo9py8=</X509Certificate>
     *                     </X509Data>
     *                 </KeyInfo>
     *             </Signature>
     *             <saml2:Subject>
     *                 <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">N16RU33</saml2:NameID>
     *                 <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches">
     *                     <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
     *                     Cloud Integrity Technology</saml2:NameID>
     *                     <saml2:SubjectConfirmationData NotBefore="2018-12-27T03:27:39.198Z"
     *                     NotOnOrAfter="2018-12-27T04:27:39.198Z"/>
     *                 </saml2:SubjectConfirmation>
     *             </saml2:Subject>
     *             <saml2:AttributeStatement>
     *                 <saml2:Attribute Name="hostName">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">N16RU33</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="biosVersion">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">SE5C610.86B.01.01.1008.031920151331</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="TRUST_OVERALL">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">true</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="tpmVersion">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">2.0</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="TRUST_ASSET_TAG">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">NA</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="processorInfo">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">F2 06 03 00 FF FB EB BF</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="vmmName">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">Docker</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="hardwareUuid">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">80294068-E62C-E411-906E-0012795D96DD</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="vmmVersion">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">17.06.0-dev</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="AIK_SHA256">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">cc705d363d96234f66b7e5e281076ad7e5e2345bdeb9390a49ec97af37999e31
     *                     </saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="osName">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">RedHatEnterpriseServer</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="TRUST_BIOS">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">true</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="TRUST_OS">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">true</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="noOfSockets">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">2</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="tpmEnabled">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">true</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="biosName">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">Intel Corporation</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="osVersion">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">7.5</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="processorFlags">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov
     *                     pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp
     *                     lm constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc aperfmperf
     *                     eagerfpu pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr
     *                     pdcm pcid dca sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c
     *                     rdrand lahf_lm abm epb intel_ppin tpr_shadow vnmi flexpriority ept vpid fsgsbase
     *                     tsc_adjust bmi1 avx2 smep bmi2 erms invpcid cqm xsaveopt cqm_llc cqm_occup_llc ibpb
     *                     ibrs stibp dtherm ida arat pln pts spec_ctrl intel_stibp</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="Binding_Key_Certificate">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">-----BEGIN CERTIFICATE-----
     *                         MIIEoDCCA4igAwIBAgIIaY9d8AmzzYkwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAxMQbXR3aWxz
     *                         b24tcGNhLWFpazAeFw0xODEyMjEwNDU3MjNaFw0yODEyMTgwNDU3MjNaMCUxIzAhBgNVBAMMGkNO
     *                         PUJpbmRpbmdfS2V5X0NlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
     *                         mZmiaeyIHLuLV+X7Y0l8Ea4sdaJ2I2MYOessKtAT6k7dGX0KGegpCC7chubzY0O3RGvzxScctVCF
     *                         L++CA9J94+mcvjjZa2kdP9VO0tpH3Dsp4wXTkOIIjCRNmN3iJY58N7NKoD1uSGYRXO0DLru0BymU
     *                         Ukmv25LLzuD1XBKiUrUDEHvR1hcIWETb5J67u1diFiRLl4QWEe9TooVZdIqwN11MGhIoHFCt6w3G
     *                         L1GteuxgblcGwJ1B9TT5o44kcgcm9EAt5Fal0B2OGCVtAkdM0QfIc30HNoXHrywEcx6VJ1PO4PYK
     *                         jbMqBYGrIq+BscXYdtWhKZ2RpafLPFyCG7C3mwIDAQABo4IB3DCCAdgwDgYDVR0PAQH/BAQDAgUg
     *                         MIGdBgdVBIEFAwIpBIGR/1RDR4AXACIAC5vdXYz9O1UXFL9zKp33sXGAfIULUsVDICC+TrrLwiYK
     *                         AAQA/1WqAAAAAAAF1V0AAAACAAAAAQAABQAyAAfmAAAiAAvL4wVO3yJMcxnFvGSJOBEHHw5xIciu
     *                         HMHzMVRZJWUrLwAiAAvLxm8eIM6iw4TH6ExeSARMI4vxkzesjDFBLqgzQ6t8mzCCARQGCFUEgQUD
     *                         AikBBIIBBhQACwAAAWgWHM+DWueV0nHXUiautbvRZpoF1vD/QdsVTIxDuMZwnK3XzD9jWScPzAO+
     *                         ZFgY45n3x8wpqZ/gqUWEk5Lcv50bucdq2hehSNVMxqlyw1vvD5El+D/u+N1w5VvykW3Iut81rKMF
     *                         XP/DY2CutCQIlFWdQbDL/1w9D6tnybcCUFzOM3jH8PJf0HH3TgKs6AnDLWWck3h74MavhagKna+B
     *                         omF3QkxM0hwB9YSnqGMA9R2CKU3QcNLzPWEd3TfCjPYwaHyvEK3utpqFp7XmD2mmQS6LyWVX4NtE
     *                         HwffHTSXmYcT2FvxJ6vBAlK22mXZaLAP0ehsfrrbV87FJegwkx8UTncwDgYIVQSBBQMCKQIEAgAV
     *                         MA0GCSqGSIb3DQEBCwUAA4IBAQAc60wpF8iQIRSavSiPMeiquxLgaQZHGS9TUDXJtqH0we0dY9mz
     *                         EDUa8C+Q/Ot2VcOLAmoe8xz4lnx1Td4ljgPW1JhQS7919BS+Uv/1PpTshVmjFUBVUNf8UCP0oaJv
     *                         duAmOZyumjTzHEHRiwMUv2qIv9rWKLSd7b8IYrWnRLq6QZFuxvxnkJlC0ujI77TEjVAXzmMpstuj
     *                         NK7cpfZcJZZ2si0DC67AyvKkCb6gNx5JDVBX4YdJvjZJxdwWJEQgxV/RFH/4lIx57FDb83WLkzns
     *                         ZRcwl+EJnR+cgqzuiPRydumMt9KhXNUZvssLFSTeU/Ybxp5iBkdf0dhZyluuhMyi
     *                         -----END CERTIFICATE-----</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="AIK_Certificate">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">-----BEGIN CERTIFICATE-----
     *                         MIICvTCCAaWgAwIBAgIGAWfPH+62MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u
     *                         LXBjYS1haWswHhcNMTgxMjIxMDQ1NzE1WhcNMjgxMjIwMDQ1NzE1WjAAMIIBIjANBgkqhkiG9w0B
     *                         AQEFAAOCAQ8AMIIBCgKCAQEAmfaFPApX3AEkcom59v4bzz0g1XCydtVBwJRO2bBjT2wtP2VlTQaw
     *                         RGt6G4YCpgp47JBqP0g0G8rIAJffExUp1vbN88ydr6p3NFKq5TFcXv/H5M1yaqNaQBlTMPipnvvm
     *                         J8+UAA8qKeZw5ygGwJRce7iLdz/ZOg81dDPn8KoUzXnc2Cm1GeuM0PzdRx3XD6P9O1F9AnSKtkw/
     *                         vF+wATXpCrXy86pn5qdgbn0PNQxS4rOBCMbtDX1yMMMmB9/SIH0YCIyEmLVxk2Uoew5fKh2jhIOH
     *                         yZWM0Id7+4vrMiWwQJt8OJobjnL+awnfRJCXGa1n6oPAI36I703a/WYHv5zYRQIDAQABoyIwIDAe
     *                         BgNVHREBAf8EFDASgRBIaXNfSWRlbnRpdHlfS2V5MA0GCSqGSIb3DQEBCwUAA4IBAQA3lNOom9QX
     *                         Ns5ZN7/rB0P62tt6fhWkR5ZBKrkxu7fjbQg40qjUXCHAqOHdkG2btMxCmHbRlJuw1Eki8muN4yl0
     *                         mCOAJpZ/sdVBxKtH6g/Q+LGxN3tmE/AskxtIKniHeJFZbCkrjUNbLNuHLhnPiIli5B0QI5DuSzfP
     *                         2kwrR1TQRqQRWUE1dDsydrtYhHWaXRoomWqhpRng49/twc+BTg+BVZwVq9yYYuGjlLnokf8QF3Qv
     *                         Dthvk1ZAwnAtBXm2yMd59rJKxMr2/cquqNFKnzFh1svi9nk/B9YiyqPEzTSrvTPFluoObLgMK+Sk
     *                         8D7S2hrfHzoRJVqhqQ+m/IdlOY1x
     *                         -----END CERTIFICATE-----</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="txtEnabled">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">true</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="TRUST_HOST_UNIQUE">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">true</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *                 <saml2:Attribute Name="pcrBanks">
     *                     <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
     *                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     *                     xsi:type="xs:string">[SHA1]</saml2:AttributeValue>
     *                 </saml2:Attribute>
     *             </saml2:AttributeStatement>
     *         </saml2:Assertion>
     * }
     * 
     * Output:
     *
     *         HTTP 200 OK
     *
     *         -----BEGIN ENCRYPTED SECRET KEY-----
     *         Key-ID: e6aa42d9-802e-4a1d-87f6-f525e1a928f6
     * 
     *         ibjvgE7lIdDqGrgf3CLY4xeOMdzU6K6c1dZO04U51Z7JomuaQCTgdtUbQUU5eJxnapV3lTO2ev3q
     *         pmnyCvR1fpwF7n/dQKRDVraLvuElABcJ33uQiVTxjBcCRIDmNRpBNjS0q6f7EuynUrbeqmEVFJWn
     *         v0U4smZd6s3x6krTP4BiOGttpDiR0TD5N9kbMJMBZvWvERkBMwRED/Nmt9JEdD0s3mHe5zV3G9WX
     *         ln40773Cczo9awtNfUVdVyDx6LejJcCgkt4XNdRZbK9cVdGK+w6Q1tASiVxRZmvJDVFA0Pa8F1I0
     *         I9Iri2+YRM6sGVg8ZkzcCmFd+CoTNy+cw/Y9AQ==
     *         -----END ENCRYPTED SECRET KEY-----
     * </pre></div>
     *
     */
    public String transferKey(String keyId, String saml) {
        HashMap<String, Object> map = new HashMap();
        map.put("id", keyId);
        // note we are sending an empty post body because this transfer request requires only key id (from url) and username (from login) which are already available to server without any message body
        String transferKeyResponse = getTarget().path("/v1/keys/{id}/transfer").resolveTemplates(map).request().accept(CryptoMediaType.APPLICATION_X_PEM_FILE).post(Entity.text(saml), String.class);
        return transferKeyResponse;
    }
}
