/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms;

import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeOpener;
import com.intel.dcsg.cpg.extensions.Extensions;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.client.jaxrs2.Keys;
import com.intel.kms.client.jaxrs2.Users;
import com.intel.kms.ws.v2.api.Key;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyCreator;
import java.security.KeyPair;
import java.util.Properties;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class KeysClientTest {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeysClientTest.class);
    private Key lastCreatedKey = null;
    private KeyPair envelope = null;

    @BeforeClass
    public static void init() {
        Extensions.register(TlsPolicyCreator.class, com.intel.mtwilson.tls.policy.creator.impl.CertificateDigestTlsPolicyCreator.class);
    }

    private Properties getEndpointProperties() {
        Properties properties = new Properties();
        properties.setProperty("endpoint.url", "https://10.1.68.32");
        properties.setProperty("tls.policy.certificate.sha256", "751c70c9f2789d3c17f29478eacc158e68436ec6d7808b1f76fb80fe43a45b90");
        properties.setProperty("login.basic.username", "jonathan");
        properties.setProperty("login.basic.password", "jonathan");
        return properties;
    }

    /**
     *
     * Example request:
     * <pre>
     * PUT https://10.1.68.32/v1/users/ff6da90f-ea52-4afc-b2d8-d755287ddc99/transfer-key
     * Content-Type: application/x-pem-file
     * Authorization: Basic am9uYXRoYW46am9uYXRoYW4=
     *
     * -----BEGIN PUBLIC KEY-----
     * MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgaB0rTTuELfHi67yhi55Lh60ODkyk2Tz
     * mMZO9t4lygcQWxw8O5Cvb4MUxt/0j7tfDBzRdfT2kLcRmEm6oNtJEWk4mEGiC5tEeEMlctmkSnQj
     * 98oS4G9A782KmgsB+2alzb1WVSBy43x2xAnG9XsocklYYkOdGUkS13YnK/TfMxrbFP1JRb7JGjIW
     * r6wb+qVpJ1ze52SGHZE7BiIIfoTQca+eZFkJJ6wcz8YEoe5EXVeIyjf0eR/9IkYJyT6a6WtDxiUM
     * g0rnOYNgVxvhhmfY5/cCYxYryFqWEPhUd4DMebEUrQfoO3fz65ECnkn2PNLRsfr86r3ubgxMyrH6
     * ucnKWwIDAQAB
     * -----END PUBLIC KEY-----
     * </pre>
     *
     * Example response:
     * <pre>
     * 204
     * Expires: Thu, 01 Jan 1970 00:00:00 GMT
     * Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Tue, 07-Apr-2015 20:14:36 GMT,rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Tue, 07-Apr-2015 20:14:35 GMT,JSESSIONID=v7lzgdv87e0tga7gzd9wpci9;Path=/;Secure
     * Server: Jetty(9.1.1.v20140108)
     * </pre>
     *
     * @throws Exception
     */
    @Test
    public void testRegisterEnvelopeKey() throws Exception {
        Users users = new Users(getEndpointProperties());
        envelope = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE);
        users.editTransferKey(getEndpointProperties().getProperty("login.basic.username"), envelope.getPublic());
//        Keys keys = new Keys(getEndpointProperties());
    }

    /**
     * Example request:
     * <pre>
     * POST https://10.1.68.32/v1/keys
     * Accept: application/json
     * Content-Type: application/json
     * Authorization: Basic am9uYXRoYW46am9uYXRoYW4=
     *
     * {"algorithm":"AES","key_length":128,"padding_mode":"OFB8"}
     * </pre>
     *
     * Example response:
     * <pre>
     * 200
     * Content-Length: 293
     * Expires: Thu, 01 Jan 1970 00:00:00 GMT
     * Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Tue, 07-Apr-2015 20:11:15 GMT,JSESSIONID=1tkwy46j65yi1s0tv5ei1hwrv;Path=/;Secure
     * Content-Type: application/json
     * Server: Jetty(9.1.1.v20140108)
     *
     * {"id":"70b6644c-f43b-436c-9c0b-40a4d5ea3cb6","algorithm":"AES","key_length":128,"padding_mode":"OFB8","transfer_policy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization","transfer_link":"http://ip6-localhost/v1/keys/70b6644c-f43b-436c-9c0b-40a4d5ea3cb6/transfer"}
     * </pre>
     *
     * @throws Exception
     */
    @Test
    public void testCreateAesKey() throws Exception {
        Keys keys = new Keys(getEndpointProperties());
        CreateKeyRequest request = new CreateKeyRequest();
        request.setAlgorithm("AES");
        request.setKeyLength(128);
        request.setPaddingMode("OFB8");
        Key created = keys.createKey(request);
        log.debug("Created key {}", created.getId().toString());
        lastCreatedKey = created;
    }

    /**
     * Example request:
     * <pre>
     * POST https://10.1.68.32/v1/keys/7ee8457f-d2c7-47ff-9a7e-c0b35cd347ae/transfer
     * Accept: application/x-pem-file
     * Content-Type: text/plain
     * Authorization: Basic am9uYXRoYW46am9uYXRoYW4=
     * </pre>
     *
     * Example response:
     * <pre>
     * 200
     * Content-Length: 828
     * Expires: Thu, 01 Jan 1970 00:00:00 GMT
     * Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Tue, 07-Apr-2015 21:19:28 GMT,JSESSIONID=6jclba94zg7skhyt9a67e31t;Path=/;Secure
     * Content-Type: application/x-pem-file
     * Server: Jetty(9.1.1.v20140108)
     *
     * -----BEGIN ENCRYPTED KEY-----
     * Content-Algorithm: AES
     * Content-Key-Id: fd3dc989-62fc-4f9f-be1e-4f400480871d
     * Content-Key-Length: 128
     * Content-Padding-Mode: OFB8
     * Encryption-Algorithm: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
     * Encryption-Key-Id: jonathan
     * Encryption-Key-Length: 2048
     * Integrity-Algorithm: HMAC-SHA256
     * Integrity-Key-Id: fd3dc989-62fc-4f9f-be1e-4f400480871d
     * Integrity-Key-Length: 128
     * Integrity-Manifest: cipher.key, cipher.json
     *
     * Kkz+PHPti/+Ac/OAChYfpG2mSrsi46IgXAYYwcTAA9Xfxz9FmG0RQfRhOyWkLBd36qRgm9pVXPYU
     * iQ5YJLt4+hiaiL0kfePuG0CrTVJ+cnUhfCAwLtRmwIfSyXQrlJKz/bkUuC3JCdAfqDgho3B8Uv3z
     * MgPu34W1cBnQ/0T2nctZ3VoQu98claJQebNE8h8VExwsFpD1LavGHw31eAq+q2Tqx1pPaImw/01N
     * /yN2L501pC66jy7JdqPzo2fYMIXcFRpiklQS0wNfIx6UKKbWJyWD0/urDC74m9ef72fGZyfWQBD4
     * BY3gj3RgBOI9d5sfjLqjGxvnVOk9l+gFIh68Vg==
     * -----END ENCRYPTED KEY-----
     *
     * </pre>
     *
     * @throws Exception
     */
    @Test
    public void testTransferKey() throws Exception {
        testRegisterEnvelopeKey();
        testCreateAesKey(); // will set lastCreatedKey
        Keys keys = new Keys(getEndpointProperties());
        String wrappedKeyPem = keys.transferKey(lastCreatedKey.getId().toString());
        log.debug("Transferred key {}", wrappedKeyPem);
        RsaPublicKeyProtectedPemKeyEnvelopeOpener opener = new RsaPublicKeyProtectedPemKeyEnvelopeOpener(envelope.getPrivate(), getEndpointProperties().getProperty("login.basic.username"));
        java.security.Key unwrapped = opener.unseal(Pem.valueOf(wrappedKeyPem));
        log.debug("Unwrapped key");
    }
}
