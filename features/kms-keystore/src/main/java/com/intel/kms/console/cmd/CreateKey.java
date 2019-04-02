/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.console.cmd;

import com.intel.dcsg.cpg.console.InteractiveCommand;
import com.intel.dcsg.cpg.io.pem.Pem;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import org.apache.commons.codec.binary.Base64;
/**
 * Generates a 128-bit AES "master key" to protect all other locally stored
 * secrets. Implemented as a command and not a setup task because it must
 * display the key directly to the user (not store in any configuration) 
 * and because it's not safely repeatable (if user creates a second key, 
 * there will be confusion about which one is being used).
 * 
 * How to run this command:
 * kms create-master-key
 * 
 * Example output:
 * <pre>
CGaTpWf3YcFeEzyQfxlOAQ==
 * </pre>
 * 
 * Output will be displayed in base64 by default. This command does not require
 * reading or writing to any configuration or file. The user must copy and 
 * paste the base64-encoded master key and provide it in an environment 
 * variable when starting the KMS:
 * export KMS_MASTER_KEY=(base64 encoded key here)
 * 
 * A complete PEM-style envelope can be printed with the base64-encoded key
 * by providing the --pem option:
 * kms create-master-key --pem
 * 
 * Example PEM output:
 * <pre>
-----BEGIN SECRET KEY-----
Key-Algorithm: AES
Key-Length: 256
Mode: OFB

DrwgJGzw5C9rwpeQVkAU0TFxIu4JTTyzmeHmxcyxFaE=
-----END SECRET KEY-----
 * </pre>
 * 
 * @author jbuhacoff
 */
public class CreateKey extends InteractiveCommand {

    @Override
    public void execute(String[] args) throws Exception {
        String algorithm = options.getString("alg","AES");
        int keyLengthBits = options.getInt("length", 256);
        
        byte[] key = generateKey(algorithm, keyLengthBits);
        
        if( this.options != null && options.getBoolean("pem", false) ) {
            // print base64-encoded key in PEM-style format
            Pem pem = new Pem("SECRET KEY", key);
            pem.getHeaders().put("Key-Algorithm", algorithm);
            pem.getHeaders().put("Key-Length", String.valueOf(keyLengthBits));
            pem.getHeaders().put("Mode", "OFB"); // OFB8
            System.out.println(pem.toString());
        }
        else {
            // print only base64-encoded key 
            System.out.println(Base64.encodeBase64String(key));
        }
    }
    
    private byte[] generateKey(String algorithm, int keyLengthBits) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm); // "AES"  // throws NoSuchAlgorithmException
        kgen.init(keyLengthBits);
        byte[] key = kgen.generateKey().getEncoded();
//        log.debug("key length is {} bits", (key.length*8));  // 128 for AES (no magic bytes prefixed)
        return key;
    }
    
    
}
