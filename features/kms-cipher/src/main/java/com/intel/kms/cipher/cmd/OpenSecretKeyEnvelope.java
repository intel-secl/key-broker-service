/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.cipher.cmd;

import com.intel.dcsg.cpg.console.InteractiveCommand;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeOpener;
import com.intel.dcsg.cpg.io.pem.Pem;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
/**
 * Decrypts a given symmetric secret key using a given recipient private key.
 * 
 * Example output:
 * <pre>
 * (hex goes here)
 * </pre>
 * 
 * @author jbuhacoff
 */
public class OpenSecretKeyEnvelope extends InteractiveCommand {
    private final Charset utf8 = Charset.forName("UTF-8");

    @Override
    public void execute(String[] args) throws Exception {
        String envelopeFilePath = options.getString("envelope-file");
        String recipientFilePath = options.getString("private-key-file");
        
        File secretFile = new File(envelopeFilePath);
        if( !secretFile.exists() ) {
            throw new FileNotFoundException(envelopeFilePath);
        }
        File recipientFile = new File(recipientFilePath);
        if( !recipientFile.exists() ) {
            throw new FileNotFoundException(recipientFilePath);
        }
        
        String envelopePemText = FileUtils.readFileToString(secretFile, utf8);
        Pem envelopePem = Pem.valueOf(envelopePemText);

        String privateKeyText = FileUtils.readFileToString(recipientFile, utf8);
        
        PrivateKey privateKey = RsaUtil.decodePemPrivateKey(privateKeyText);
        
        RsaPublicKeyProtectedPemKeyEnvelopeOpener opener = new RsaPublicKeyProtectedPemKeyEnvelopeOpener(privateKey, envelopePem.getHeader("Encryption-Key-Id"));
        java.security.Key unwrapped = opener.unseal(envelopePem);
        
        String decrypted = Hex.encodeHexString(unwrapped.getEncoded());
        
        System.out.println(decrypted);
    }
    
    

}
