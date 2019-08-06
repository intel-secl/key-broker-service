/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.cipher.cmd;

import com.intel.dcsg.cpg.console.InteractiveCommand;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.digest.Digest;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeFactory;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.Charset;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FileUtils;
/**
 * Encrypts a given symmetric secret key using a given recipient public key.
 * 
 * Example output:
 * <pre>
* -----BEGIN ENCRYPTED KEY----- Content-Algorithm: AES
* Encryption-Algorithm: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
* Encryption-Key-Id:
* f41ab1c9d07bf5e0159ffe6091c325782a7e083de588c1934643b72102e63718
*
* ayR8NvkjS3GC1j8VpYs/WL3gRYWSLvlRDGeSFafjNyhUfjz3EcCFuXpaqsLX7zTw/zgF74e3oo/3
* nI0APHl/ENrxMRcUTkwDbcbHjwY9RjPu2f+udC+Y2aYEaFhrb92tQ64+Frrv5476pEZ1WVM+/yu0
* lw2u4mA+GVeDld/YOoVF2gHSrhbwlvH3iQ0FXpwXXjEt0B/Tc1dJbzzGb9sNHm0DH1qFtBfIb4l0
* VlNr364miGq9Bp1CHLBPxdvQ0hiEaCWdKJGajcHVQWqweSsFxpabZMVYRTjEfUzb/nJouOL6a1h3
* d3uMM76F3KBGAo5EVt1fnudTLnJiIZJ5Abbwng==
* -----END ENCRYPTED KEY-----
 * </pre>
 * 
 * @author jbuhacoff
 */
public class SecretKeyEnvelope extends InteractiveCommand {
    private final Charset utf8 = Charset.forName("UTF-8");

    @Override
    public void execute(String[] args) throws Exception {
        String secretFilePath = options.getString("secret-file");
        String recipientFilePath = options.getString("recipient-file");
        
        File secretFile = new File(secretFilePath);
        if( !secretFile.exists() ) {
            throw new FileNotFoundException(secretFilePath);
        }
        File recipientFile = new File(recipientFilePath);
        if( !recipientFile.exists() ) {
            throw new FileNotFoundException(recipientFilePath);
        }
        
        byte[] secretKeyBytes = FileUtils.readFileToByteArray(secretFile);
        String secretKeyAlgorithm = "AES";
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, secretKeyAlgorithm);
        
        String publicKeyText = FileUtils.readFileToString(recipientFile, utf8);
        
        Pem pem = Pem.valueOf(publicKeyText);
        RSAPublicKey publicKey;
        if( "PUBLIC KEY".equalsIgnoreCase(pem.getBanner()) ) {
            publicKey = (RSAPublicKey)RsaUtil.decodePemPublicKey(publicKeyText);
        }
        else if( "CERTIFICATE".equalsIgnoreCase(pem.getBanner())) {
            publicKey = (RSAPublicKey)X509Util.decodePemCertificate(publicKeyText).getPublicKey();
        }
        else {
            System.err.println("Unrecognized public key format");
            return;
        }
        
        String encrypted = encryptSecretKeyWithEnvelopePublicKey(secretKey, publicKey);
        
        System.out.println(encrypted);
    }
    
    
    public static String encryptSecretKeyWithEnvelopePublicKey(SecretKey secretKey, RSAPublicKey recipientPublicKey) throws CryptographyException {
        CipherKeyAttributes recipientPublicKeyAttributes = new CipherKeyAttributes();
//                    recipientPublicKeyAttributes.setAlgorithm(recipientPublicKey.getAlgorithm()); // this would be "RSA", but see below where we set it to the factory's algorithm "RSA/ECB/OAEP...."
        recipientPublicKeyAttributes.setKeyId(Digest.sha256().digest(recipientPublicKey.getEncoded()).toHex());
        recipientPublicKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength());
//                    recipientPublicKeyAttributes.setKeyLength(envelope.geten);
        /*
                     recipientPublicKeyAttributes.setAlgorithm(recipientPublicKey.getAlgorithm()); // "RSA"
                     recipientPublicKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength()); // for example, 2048
                     recipientPublicKeyAttributes.setMode("ECB"); // standard for wrapping a key with a public key since it's only one block
                     recipientPublicKeyAttributes.setPaddingMode("OAEPWithSHA-256AndMGF1Padding"); // see RsaPublicKeyProtectedPemKeyEnvelopeFactory
         */
        CipherKeyAttributes secretKeyAttributes = new CipherKeyAttributes();
        secretKeyAttributes.setKeyLength(secretKey.getEncoded().length * 8); // in bits
        secretKeyAttributes.setAlgorithm(secretKey.getAlgorithm());

        //descriptor.s
        RsaPublicKeyProtectedPemKeyEnvelopeFactory factory = new RsaPublicKeyProtectedPemKeyEnvelopeFactory(recipientPublicKey, recipientPublicKeyAttributes.getKeyId());
        PemKeyEncryption envelope = factory.seal(secretKey);

        recipientPublicKeyAttributes.setAlgorithm(factory.getAlgorithm()); // "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"   or we could split it up and set algorithm, mode, and paddingmode separately on the encryption attributes

//                    KeyDescriptor descriptor = new KeyDescriptor();
//                    descriptor.setContent(secretKeyAttributes);
//                    descriptor.setEncryption(recipientPublicKeyAttributes);
        return envelope.getDocument().toString();
    }
    
}
