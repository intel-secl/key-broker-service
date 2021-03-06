/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeFactory;
import com.intel.dcsg.cpg.io.ByteArray;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.KeyLogMarkers;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.KeyNotFound;
import com.intel.kms.api.fault.KeyTransferProtectionNotAcceptable;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.kms.user.User;
import com.intel.kms.user.UserCollection;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.kms.user.jaxrs.UserRepository;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.jaxrs2.Link;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.IntegrityKeyAttributes;
import com.intel.mtwilson.util.tpm12.DataBind;
import com.intel.mtwilson.util.validation.faults.Thrown;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.ArrayUtils;

/**
 * Implements common functionality shared between implementations of remote key
 * managers like Barbican and KMIP. Currently written as a decorator to minimize
 * integration effort. Use it with
 * <pre>new RemoteKeyManager(barbicanKeyManager)</pre> or
 * <pre>new RemoteKeyManager(kmipKeyManager)</pre>
 *
 * @author jbuhacoff
 */
public class RemoteKeyManager implements KeyManager {

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(RemoteKeyManager.class);
    final private KeyManager delegate;
    final private ObjectMapper mapper;
    final private Configuration configuration;
    final private KeplerLakeUtil keplerLakeUtil;
    OAuth2Client auth2Client=null;
    final private String DESCRIPTOR_URI = "urn:intel:keplerlake:crypto-schema:data-encryption";

    public RemoteKeyManager(KeyManager delegate) throws IOException {
        this.delegate = delegate;
        mapper = JacksonObjectMapperProvider.createDefaultMapper();
        configuration = ConfigurationFactory.getConfiguration();
        keplerLakeUtil = new KeplerLakeUtil();
        auth2Client = new OAuth2Client(keplerLakeUtil.oAuthConfiguration());
    }
    private URL getTransferLinkForKeyId(String keyId) throws MalformedURLException {
        String template = configuration.get("endpoint.key.transfer.url", String.format("%s/v1/keys/{keyId}/transfer", configuration.get("endpoint.url", "http://localhost")));
        log.debug("getTransferLinkForKeyId template: {}", template);
        String url = template.replace("{keyId}", keyId);
        log.debug("getTransferLinkForKeyId url: {}", url);
        return new URL(url);
    }

    /**
     *
     * @param createKeyRequest
     * @return a list of faults with the request, or an empty list if the
     * request is valid
     */
    private List<Fault> validateCreateKey(CreateKeyRequest createKeyRequest) {
        ArrayList<Fault> faults = new ArrayList<>();
        if (createKeyRequest.getAlgorithm() == null) {
            faults.add(new MissingRequiredParameter("algorithm"));
            return faults;
        }
        if (!createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            faults.add(new InvalidParameter("algorithm", new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
            return faults;
        }
        // check AES specific parameters
        if (createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            if (createKeyRequest.getKeyLength() == null) {
                faults.add(new MissingRequiredParameter("keyLength")); // TODO: the "parameter" field of the MissingRequiredParameter class needs to be annotated so a filter can automatically convert it's VALUE from keyLength to key_length (javascript) or keep it as keyLength (xml) or KeyLength (SAML) etc.  ... that's something the jackson mapper doesn't do so we have to ipmlement a custom filter for VALUES taht represent key names.
                return faults;
            }
            if (!ArrayUtils.contains(new int[]{128, 192, 256}, createKeyRequest.getKeyLength())) {
                faults.add(new InvalidParameter("keyLength"));
                return faults;
            }
        }
        return faults;
    }

    private List<Fault> validateKplCreateKey(CreateKeyRequest createKeyRequest) {
        ArrayList<Fault> faults = new ArrayList<>();
        try {
            Map<String,Object> map = createKeyRequest.map();
            if (!map.containsKey("descriptor_uri") || ((String) map.get("descriptor_uri")).isEmpty()) {
                faults.add(new MissingRequiredParameter("descriptor_uri"));
            }
            if (map.containsKey("descriptor_uri") && !(map.get("descriptor_uri")).toString().equals(DESCRIPTOR_URI)) {
                faults.add(new InvalidParameter("descriptor_uri"));
            }
            if (!map.containsKey("realm") || ((String) map.get("realm")).isEmpty()) {
                faults.add(new MissingRequiredParameter("realm"));
            }

            if (!map.containsKey("path") || ((String) map.get("path")).isEmpty()) {
                faults.add(new MissingRequiredParameter("path"));
            }
            if (!map.containsKey("policy_uri") || ((String) map.get("policy_uri")).isEmpty()) {
                faults.add(new MissingRequiredParameter("policy_uri"));
            }
        } catch (Exception e) {
            log.error("Error while validating input parameters.", e);
            faults.add(new Fault("Error while validating input parameters."));
        }
        return faults;
    }

    @Override
    public CreateKeyResponse createKey(CreateKeyRequest createKeyRequest) {
        if (createKeyRequest.getKeyId() == null) {
            createKeyRequest.setKeyId(new UUID().toString());
        }

        ArrayList<Fault> faults = new ArrayList<>();
        if (!createKeyRequest.map().containsKey("descriptor_uri")) {
            faults.addAll(validateCreateKey(createKeyRequest));
        } else {
            faults.addAll(validateKplCreateKey(createKeyRequest));
        }

        if (!faults.isEmpty()) {
            CreateKeyResponse response = new CreateKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }

        createKeyRequest.setTransferPolicy("urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization");
        try {
            createKeyRequest.setTransferLink(getTransferLinkForKeyId(createKeyRequest.getKeyId()));
            if (createKeyRequest.getTransferPolicy() == null && createKeyRequest.map().containsKey("transferPolicy")) {
                createKeyRequest.setTransferPolicy((String) createKeyRequest.get("transferPolicy"));
            }
        } catch (MalformedURLException e) {
            log.debug("Cannot generate transfer url", e);
            faults.add(new InvalidParameter("endpoint.key.transfer.url")); // maybe should be a configuration fault... 
            CreateKeyResponse response = new CreateKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }

        log.debug("Transfer policy: {}", createKeyRequest.getTransferPolicy());
        log.debug("Transfer URL: {}", createKeyRequest.getTransferLink().toExternalForm());

        CreateKeyResponse response = delegate.createKey(createKeyRequest);

        // add missing transfer policy and link from response (barbican client doesn't save them) - must be refactored
        for (KeyAttributes attributes : response.getData()) {
            if (attributes.getTransferPolicy() == null) {
                attributes.setTransferPolicy("urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization");
                log.debug("Added transfer policy: {}", attributes.getTransferPolicy());
            }
            if (attributes.getTransferLink() == null) {
                try {
                    attributes.setTransferLink(getTransferLinkForKeyId(attributes.getKeyId()));
                    log.debug("Added transfer link: {}", attributes.getTransferLink());
                } catch (MalformedURLException e) {
                    log.debug("Cannot generate transfer url", e);
                    faults.add(new InvalidParameter("endpoint.key.transfer.url")); // maybe should be a configuration fault... 
                    response.getFaults().addAll(faults);
                    return response;
                }
            }
        }

        return response;
    }

    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest registerKeyRequest) {

        ArrayList<Fault> faults = new ArrayList<>();

        if (registerKeyRequest.getDescriptor() == null) {
            // should be an error
            registerKeyRequest.setDescriptor(new KeyDescriptor());
        }
        if (registerKeyRequest.getDescriptor().getContent() == null) {
            // should be an error
            registerKeyRequest.getDescriptor().setContent(new CipherKeyAttributes());
        }

        if (registerKeyRequest.getDescriptor().getContent().getKeyId() == null) {
            registerKeyRequest.getDescriptor().getContent().setKeyId(new UUID().toString());
        }

        if (registerKeyRequest.getDescriptor().getContent().get("transferPolicy") == null) {
            registerKeyRequest.getDescriptor().getContent().set("transferPolicy", "urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization");
        }
        if (registerKeyRequest.getDescriptor().getContent().get("transferLink") == null) {
            try {
                registerKeyRequest.getDescriptor().getContent().set("transferLink", getTransferLinkForKeyId(registerKeyRequest.getDescriptor().getContent().getKeyId()));
            } catch (MalformedURLException e) {
                log.debug("Cannot generate transfer url", e);
                faults.add(new InvalidParameter("endpoint.key.transfer.url")); // maybe should be a configuration fault... 
                RegisterKeyResponse response = new RegisterKeyResponse();
                response.getFaults().addAll(faults);
                return response;
            }
        }

        RegisterKeyResponse response = delegate.registerKey(registerKeyRequest);
        try {
            log.debug("delegate registerKey response: {}", mapper.writeValueAsString(response));
        } catch (Exception e) {
            log.error("Cannot serialize delegate registerKey response", e);
        }

        // add missing transfer policy and link from response (barbican client doesn't save them) - must be refactored
        for (KeyAttributes attributes : response.getData()) {
            if (attributes.getTransferPolicy() == null) {
                attributes.setTransferPolicy("urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization");
                log.debug("Added transfer policy: {}", attributes.getTransferPolicy());
            }
            if (attributes.getTransferLink() == null) {
                try {
                    attributes.setTransferLink(getTransferLinkForKeyId(attributes.getKeyId()));
                    log.debug("Added transfer link: {}", attributes.getTransferLink());
                } catch (MalformedURLException e) {
                    log.debug("Cannot generate transfer url", e);
                    faults.add(new InvalidParameter("endpoint.key.transfer.url")); // maybe should be a configuration fault... 
                    response.getFaults().addAll(faults);
                    return response;
                }
            }
        }

        return response;
    }

    @Override
    public DeleteKeyResponse deleteKey(DeleteKeyRequest deleteKeyRequest) {
        return delegate.deleteKey(deleteKeyRequest);
    }

    private String getUserFromBearerToken(String bearer) throws CustomException {
        try {
            if (bearer == null || bearer.isEmpty()) {
                log.error("Keplerlake Transfer Key request must have Authorization header.");
                throw new CustomException("Keplerlake Transfer Key request must have Authorization header.");
            }

            log.debug("Before bearer token {}", bearer);
            bearer = bearer.replace("Bearer", "");
            log.debug("After bearer token {}", bearer);
            log.debug("auth2Client call {}", bearer);
            Map<String, String> oAuthResponseMap = auth2Client.getVerifiedAttributes(bearer);
            if (oAuthResponseMap == null || oAuthResponseMap.isEmpty() || oAuthResponseMap.containsKey("error")) {
                log.error("Unauthorized User");
                throw new CustomException("Unauthorized User");
            }
            if (oAuthResponseMap.containsKey("email") && oAuthResponseMap.get("email") != null) {
                return oAuthResponseMap.get("email").trim();
            } else {
                log.error("Email information missing from oAuth response.");
                throw new CustomException("Email information missing from oAuth response.");
            }
        } catch (CustomException | IOException | InvalidTokenException e) {
            log.error("Exception in getUserFromBearerToken {}", e);
            throw new CustomException("Exception in getUserFromBearerToken.");

        }
    }

    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest keyRequest) {
        TransferKeyResponse response = new TransferKeyResponse();
        response.setDescriptor(new KeyDescriptor());

        String keyId = keyRequest.getKeyId();
        GetKeyAttributesRequest getRequest = new GetKeyAttributesRequest(keyId);
        GetKeyAttributesResponse getResponse = getKeyAttributes(getRequest);
        if (getResponse.getData().map().containsKey("descriptor_uri")) {
            keyRequest.set("descriptor_uri", getResponse.getData().get("descriptor_uri"));
        }

        // Only Keplerlake related code.
        if (keyRequest.map().containsKey("descriptor_uri")) {
            String userEmail;
            try {
                log.debug("OAuth2-Authorization in RKM '{}'", (String) keyRequest.get("OAuth2-Authorization"));
                // get value for user attribute from oauth bearer token present in request.
                userEmail = getUserFromBearerToken((String) keyRequest.get("OAuth2-Authorization"));
                log.debug("user ::: {}", userEmail);
            } catch (Exception e) {
                log.error("Error while fetching user from oAuth bearer token.", e);
                response.getFaults().add(new Thrown(e));
                response.getHttpResponse().setStatusCode(Response.Status.UNAUTHORIZED.getStatusCode());
                return response;
            }

            try {
                // Get policy key from key info using which the policy can be fetched from etcd.
            } catch (Exception ex) {
                log.error("Error while processing policy associated to the key", ex);
                response.getFaults().add(new Fault("Error while processing policy associated to the key"));
                return response;
            }
        }
        TransferKeyResponse delegateResponse = delegate.transferKey(keyRequest);
        byte[] key = delegateResponse.getKey();
        if (key == null) {
            log.error("Delegate returned null key");
            response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
            return response;
        }
        log.debug("Key length: {} bytes", key.length); // expect 16 for AES-128
        log.debug("Key digest: {}", Sha256Digest.digestOf(key));
        if (delegateResponse.getDescriptor() == null) {
            // this should be an error but for now we assume AES 128 ... TODO:  this is only for CIT
            KeyDescriptor tmpKeyDescriptor = new KeyDescriptor();
            tmpKeyDescriptor.setContent(new CipherKeyAttributes());
            tmpKeyDescriptor.getContent().setAlgorithm("AES");
            tmpKeyDescriptor.getContent().setKeyLength(128);
            delegateResponse.setDescriptor(tmpKeyDescriptor);
        }
        CipherKeyAttributes keyAttributes = delegateResponse.getDescriptor().getContent();
        if (keyRequest.map().containsKey("descriptor_uri")) {
            byte[] derivedKey;
            if (keyRequest.map().containsKey("context")) {
                // if request has context, we assume this is a master key, so it must have a salt for key derivation
                byte[] salt = (byte[]) keyAttributes.get("salt");
                String context = (String) keyRequest.get("context");

                // setting atrributes based on the context from request.
                CipherKeyAttributes derivedKeyAttributes = new CipherKeyAttributes();
                switch (context) {
                    case "dm-crypt":
                        derivedKeyAttributes.setAlgorithm("AES");
                        derivedKeyAttributes.setMode("XTS");
                        derivedKeyAttributes.setKeyLength(512);
                        break;
                    case "ecryptfs":
                        derivedKeyAttributes.setAlgorithm("AES");
                        derivedKeyAttributes.setMode("CBC");
                        derivedKeyAttributes.setKeyLength(256);
                        break;
                    case "openssl":
                        derivedKeyAttributes.setAlgorithm("AES");
                        derivedKeyAttributes.setMode("CBC");
                        derivedKeyAttributes.setKeyLength(256);
                        break;
                    case "hmac":
                        derivedKeyAttributes.setAlgorithm("HMAC");
                        derivedKeyAttributes.setKeyLength(256);
                        break;
                    default:
                        log.error("Unrecognized key context: {}", context);
                        response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                        return response;
                }
                try {
                    derivedKey = keplerLakeUtil.deriveKey(key, salt, context, keyAttributes, derivedKeyAttributes);
                    response.setKey(derivedKey);
                    keyAttributes.setAlgorithm(derivedKeyAttributes.getAlgorithm());
                    keyAttributes.setMode(derivedKeyAttributes.getMode());
                    keyAttributes.setKeyLength(derivedKeyAttributes.getKeyLength());
                } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                    log.error("Error while deriving new key from master key.", ex);
                }
            }
        }
        log.debug("Key algorithm: {}", keyAttributes.getAlgorithm()); // expect "AES" (CIT) or "HKDF" (Kepler Lake)
        log.debug("Key length: {} bits", keyAttributes.getKeyLength()); // expect 128

        /**
         * A response from DirectoryKeyManager contains the plain key and its
         * attributes, like this:
         * <pre>
         * CipherKey cipherKey = repository.retrieve(keyRequest.getKeyId());
         * CipherKeyAttributes keyAttributes = new CipherKeyAttributes();
         * keyAttributes.copyFrom(cipherKey);
         * TransferKeyResponse response = new TransferKeyResponse();
         * response.setKey(cipherKey.getEncoded());
         * response.setDescriptor(new KeyDescriptor());
         * response.getDescriptor().setContent(keyAttributes);
         * </pre>
         *
         * So the task here is to wrap the key appropriately for the current
         * context. We create a new TranferKeyResponse object and populate it.
         */
        CipherKeyAttributes recipientPublicKeyAttributes;
        RSAPublicKey recipientPublicKey;
        int encScheme;

        // is the request for an authorized user or a trust-based key transfer?
        if (keyRequest.getUsername() == null) {
            log.debug("transferKey request for trust-based key transfer");
            // no username, so attempt trust-based
            // XXX the saml policy enforcement should be coming from a plugin, either kms-saml or another one, which will look for the "saml" attribute (extension) in the request object
            // the trust-based request must  include a SAML document; the kms-saml plugin stores it in the "saml" extended attribute
//
            try {
//                // the kms-saml plugin puts these attributes here based on the SAML - but maybe this should be happening on "this side" but also via a plugin:
                recipientPublicKeyAttributes = (CipherKeyAttributes) keyRequest.get("recipientPublicKeyAttributes");
                try {
                    log.debug("transferKey recipient public key attributes: {}", mapper.writeValueAsString(recipientPublicKeyAttributes));
                } catch (Exception e) {
                    log.error("transferKey loaded recipient public key attributes but cannot serialize", e);
                }

                //get recipent public binding key
                recipientPublicKey = (RSAPublicKey) keyRequest.get("recipientPublicKey");

                log.debug("RKM recipientPublicKey:{}", recipientPublicKey.getEncoded());

//                Use crypto util to convert a pem to public key.
                // the encrpytion attributes describe how the key is encrypted so that only the client can decrypt it
                CipherKeyAttributes tpmBindKeyAttributes = new CipherKeyAttributes();
                tpmBindKeyAttributes.setKeyId(Sha256Digest.digestOf(recipientPublicKey.getEncoded()).toHexString());
                tpmBindKeyAttributes.setAlgorithm("RSA");
                tpmBindKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength());
                tpmBindKeyAttributes.setMode("ECB");
                tpmBindKeyAttributes.setPaddingMode("OAEP-TCPA"); // OAEP with the 4 byte literal 'TCPA' as the padding parameter.

                recipientPublicKeyAttributes = tpmBindKeyAttributes;

                // wrap the key; this is the content of cipher.key
                response.setKey(DataBind.bind(key, recipientPublicKey));
                response.getDescriptor().setEncryption(tpmBindKeyAttributes);
                log.debug("Transfer key response after public key encryption : " + mapper.writeValueAsString(response));
            } catch (Exception e) {
                log.error("Cannot bind requested key {}", e);
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }

        } else {
            log.debug("transferKey request for authorized user key transfer");
            // attempt by authorized user
            log.debug("Username: {}", keyRequest.getUsername());
            // do we have a registered public key for the user?
            UserRepository userRepository = new UserRepository();
            UserFilterCriteria criteria = new UserFilterCriteria();
            criteria.usernameEqualTo = keyRequest.getUsername();
            UserCollection userCollection = userRepository.search(criteria);
            if (userCollection.getUsers().isEmpty()) {
                // it is an error to request a transfer for a user that isn't registered; we log the specifics but we return simply "key not found" so that attackers cannot use this to discover registered usernames
                log.error("Username not found: {}", keyRequest.getUsername());
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }
            if (userCollection.getUsers().size() > 1) {
                // it is an error to have multiple users registered under the same username
                log.error("Multiple users found for username: {}", keyRequest.getUsername());
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }
            User user = userCollection.getUsers().get(0);
            try {
                if (user.getTransferKey() == null) {
                    // user does not have a transfer key registered, so policy must allow "plaintext" transfers to authorized user or else we deny the request
                    // XXX TODO
                    log.error("User does not have transfer key");
                    response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                    return response;
                } else {
                    recipientPublicKey = (RSAPublicKey) user.getTransferKey();
                    recipientPublicKeyAttributes = new CipherKeyAttributes();
                    recipientPublicKeyAttributes.setKeyId(keyRequest.getUsername());// XXX TODO  user's public key still needs an id...  we should be treating it like any other key.
                    recipientPublicKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength()); // we should just have this in metadata

                    RsaPublicKeyProtectedPemKeyEnvelopeFactory factory = new RsaPublicKeyProtectedPemKeyEnvelopeFactory(recipientPublicKey, recipientPublicKeyAttributes.getKeyId());
                    SecretKey secretKey = new SecretKeySpec(key, keyAttributes.getAlgorithm()); // algorithm like "AES"
                    PemKeyEncryption envelope = factory.seal(secretKey);

                    recipientPublicKeyAttributes.setAlgorithm(factory.getAlgorithm()); // "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"   or we could split it up and set algorithm, mode, and paddingmode separately on the encryption attributes

                    response.setKey(envelope.getDocument().getContent());
                    response.getDescriptor().setEncryption(recipientPublicKeyAttributes);
                }
            } catch (CryptographyException | CertificateException e) {
                log.error("Cannot load transfer key for user: {}", keyRequest.getUsername(), e);
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }
        }

        try {
            // enforce policy: cannot wrap key with weaker key
            log.debug("response :: " + mapper.writeValueAsString(response));
            log.debug("keyAttributes :: " + mapper.writeValueAsString(keyAttributes));
            log.debug("recipientPublicKeyAttributes :: " + mapper.writeValueAsString(recipientPublicKeyAttributes));
        } catch (JsonProcessingException ex) {
            log.error("error : " + ex);
        }
        if (!isProtectionAdequate(response, keyAttributes, recipientPublicKeyAttributes)) {
            return response;
        }

        try {
            response.getDescriptor().setContent(keyAttributes);

            // integrity protection on the encrypted key and its plaintext attributes.... use HMAC-SHA256 for 128-bit security  (see NIST 800-57 table 3) 
            // the two options are to use... 
            // 1) the cipher key itself as the HMAC key for HMAC-SHA-256, protecting its encrypted form and metadata, or 
            // 2) a key server private key to sign the encrypted form of the cipher key and the metadata.
            // For Mystery Hill specifically we know the clients will not have the key server's public key on hand,
            // so they wouldn't be able to verify the integrity using method #2. therefore we use the key itself with HMAC-SHA-256,
            // even though the key length recommendations for HMAC-SHA-256 is a 256-bit key (twice the size of the cipher key
            // which is likely to be 128 bits;  and if it was 256 bits then it would need HMAC-SHA-512 to protect and again it would
            // be half the appropriate length).
            // On the other hand, using the same key for integrity protection means an attacker could replace the entire package 
            // (encrypted secret key and its metadata and integrity signature) but unlikely that an attacker can tamper with just the metadata.
            IntegrityKeyAttributes integrityKeyAttributes = new IntegrityKeyAttributes();
            integrityKeyAttributes.setAlgorithm("HMAC-SHA256");
            integrityKeyAttributes.setKeyId(keyRequest.getKeyId()); // indicate we're using the same cipher key to generate the HMAC
            integrityKeyAttributes.setKeyLength(keyAttributes.getKeyLength());
            integrityKeyAttributes.setManifest(Arrays.asList("cipher.key", "cipher.json"));
            integrityKeyAttributes.set("signature", "integrity.sig"); // indicates in which file we are storing the HMAC signature;  we need to put it either here or in the links
            response.getDescriptor().setIntegrity(integrityKeyAttributes);

            // add links in the descriptor to the other content
            ArrayList<Link> links = new ArrayList<>();
            links.add(Link.build().rel("content").href("cipher.key").type("application/octet-stream"));
            links.add(Link.build().rel("content-descriptor").href("cipher.json").type("application/json"));
            links.add(Link.build().rel("signature").href("integrity.sig").type("application/octet-stream"));
            response.getDescriptor().set("links", links);

            // create cipher.json
            String cipherJson = mapper.writeValueAsString(response.getDescriptor()); // describes the cipher key and its encryption/integrity information but does not include the cipher key itself 

            // create integrity.sig
            byte[] document = ByteArray.concat(key, cipherJson.getBytes(Charset.forName("UTF-8"))); // this is what we're signing: the encrypted key + the metadata
            byte[] signature = hmacSha256(key, document);

            // add the serialized json because that's what was actually signed; this prevents any issue with slightly different serialization by the caller
            response.getExtensions().set("cipher.key", response.getKey());
            response.getExtensions().set("cipher.json", cipherJson);
            response.getExtensions().set("integrity.sig", signature);

            log.info(KeyLogMarkers.TRANSFER_KEY, "Transferred key id: {}", keyRequest.getKeyId());
            return response;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("Unable to bind key", e);
        }

    }

    private byte[] hmacSha256(byte[] key, byte[] document) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256"); // throws NoSuchAlgorithmException
        mac.init(keySpec); // throws InvalidKeyException
        return mac.doFinal(document);

    }

    // NOTE: this is a rough first draft;  should refer to NIST 800-57 part 1, table 2 "comparable strengths" for more detailed recommendation on key lengths
    private boolean isProtectionAdequate(TransferKeyResponse response, CipherKeyAttributes subject, CipherKeyAttributes encryption) {
        // first, we allow protection using a key of the same algorithm of equal or greater length ( AES-128,192,256 can wrap AES-128, or in RSA 2048 can wrap 1024, and RSA 3072 can wrap 2048, etc. because of their max message lengths)
        if (subject.getAlgorithm().equals(encryption.getAlgorithm()) && subject.getKeyLength() <= encryption.getKeyLength()) {
            log.debug("Requested key algorithm {} same as encryption algorithm {} and key lengths ok subject {} <= encryption {}", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
            return true;
        }
        // check equivalent protection for other algorithm combinations; for now assume RSA 2048 is adequate to protect AES 128, 192, and 256
        // XXX TODO  NIST 800-57 table 2 recommends RSA 3072 or greater to provide 128 bits of security (to protect AES-128 keys) ... this may be an issue with RSA key sizes in TPM
        if (subject.getAlgorithm().equals("AES") && encryption.getAlgorithm().startsWith("RSA") && encryption.getKeyLength() >= 2048) {
            log.debug("Requested key algorithm {} different from encryption algorithm {} and key lengths ok subject {} <= encryption {}", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
            return true;
        }
        // adding another condition for keplerlake
        if (subject.getAlgorithm().equals("HKDF") && encryption.getAlgorithm().startsWith("RSA") && encryption.getKeyLength() >= 2048) {
            log.debug("Requested key algorithm {} different from encryption algorithm {} and key lengths ok subject {} <= encryption {}", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
            return true;
        }
        if (subject.getAlgorithm().equals("HMAC") && encryption.getAlgorithm().startsWith("RSA") && encryption.getKeyLength() >= 2048) {
            log.debug("Requested key algorithm {} different from encryption algorithm {} and key lengths ok subject {} <= encryption {}", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
            return true;
        }
        log.debug("Requested key algorithm {} encryption algorithm {} and key lengths subject {} <= encryption {} does not meet policy", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
        response.getFaults().add(new KeyTransferProtectionNotAcceptable(encryption.getAlgorithm(), encryption.getKeyLength()));
        // for now reject anything else
        return false;
    }

    @Override
    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest keyAttributesRequest) {
        return delegate.getKeyAttributes(keyAttributesRequest);
    }

    @Override
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        return delegate.searchKeyAttributes(searchKeyAttributesRequest);
    }
}
