/*
 * Copyright 2016 Intel Corporation. All rights reserved.
 */
package com.intel.kms.ws.v2;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.dcsg.cpg.http.MutableQuery;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jbuhacoff
 */
public class OutputMasterKeyTest {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(OutputMasterKeyTest.class);

    /**
     * UNIT TEST ONLY
     *
     * Creates sample data for the unit test.
     *
     * The real input master keys would already be available to the key escrow,
     * identified by the associated dataset paths.
     *
     * @return
     */
    private List<CipherKey> createInputMasterKeys(int quantity) {
        ArrayList<CipherKey> list = new ArrayList<>();
        for (int i = 0; i < quantity; i++) {
            CipherKey keyHolder = new CipherKey();
            keyHolder.setEncoded(RandomUtil.randomByteArray(16));
            keyHolder.setAlgorithm("HKDF");
            keyHolder.setKeyId(String.valueOf(i + 1));
            keyHolder.setKeyLength(128);
            keyHolder.set("path", "/realm/example.com/dataset/1");
            list.add(keyHolder);
        }
        return list;
    }

    /**
     * UNIT TEST ONLY
     *
     * @param lengths
     * @return
     */
    private List<CipherKey> createInputMasterKeyWithLengths(int... lengths) {
        ArrayList<CipherKey> list = new ArrayList<>();
        for (int i = 0; i < lengths.length; i++) {
            CipherKey key = new CipherKey();
            key.setKeyLength(lengths[i]);
            list.add(key);
        }
        return list;
    }

    /**
     * UNIT TEST ONLY
     *
     * @param bytes
     * @return
     */
    private List<CipherKey> createInputMasterKeyWithBytes(byte[]... bytes) {
        ArrayList<CipherKey> list = new ArrayList<>();
        for (int i = 0; i < bytes.length; i++) {
            CipherKey key = new CipherKey();
            key.setEncoded(bytes[i]);
            list.add(key);
        }
        return list;
    }

    @Test
    public void testComputeOutputMasterKeyLengthBits() {
        assertEquals(128, computeOutputMasterKeyLengthBits(createInputMasterKeyWithLengths(128, 128), 128));
        assertEquals(192, computeOutputMasterKeyLengthBits(createInputMasterKeyWithLengths(128, 192), 128));
        assertEquals(256, computeOutputMasterKeyLengthBits(createInputMasterKeyWithLengths(128, 256), 128));
        assertEquals(192, computeOutputMasterKeyLengthBits(createInputMasterKeyWithLengths(128, 128), 128));
    }

    @Test
    public void testCombineMasterKeyParts() {
        assertArrayEquals(new byte[]{0x00}, combineMasterKeyParts(createInputMasterKeyWithBytes(new byte[]{0x00}, new byte[]{0x00}), 1));
        assertArrayEquals(new byte[]{0x01}, combineMasterKeyParts(createInputMasterKeyWithBytes(new byte[]{0x00}, new byte[]{0x01}), 1));
        assertArrayEquals(new byte[]{0x01}, combineMasterKeyParts(createInputMasterKeyWithBytes(new byte[]{0x01}, new byte[]{0x00}), 1));
        assertArrayEquals(new byte[]{0x00}, combineMasterKeyParts(createInputMasterKeyWithBytes(new byte[]{0x01}, new byte[]{0x01}), 1));

        assertArrayEquals(new byte[]{0x00, 0x00}, combineMasterKeyParts(createInputMasterKeyWithBytes(new byte[]{0x00, 0x00}, new byte[]{0x00, 0x00}), 2));
        assertArrayEquals(new byte[]{0x0A, 0x05}, combineMasterKeyParts(createInputMasterKeyWithBytes(new byte[]{0x05, 0x0A}, new byte[]{0x0F, 0x0F}), 2));
        assertArrayEquals(new byte[]{(byte) 0xA5, (byte) 0xA5}, combineMasterKeyParts(createInputMasterKeyWithBytes(new byte[]{0x5A, 0x5A}, new byte[]{(byte) 0xFF, (byte) 0xFF}), 2));
    }

    /**
     * UNIT TEST ONLY
     *
     * Example output:
     *
     * <pre>
     * master key algorithm: HKDF
     * master key length: 128 bits
     * master key path: /realm/central.org/dataset/task-output
     * master key digest_algorithm: SHA-256
     * master key salt: VxORnM2+rbriBT6QuVW3qm3yuwnSKXFALIzIxfW4Zvs=
     * </pre>
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    @Test
    public void testCreateOutputMasterKey() throws NoSuchAlgorithmException, InvalidKeyException {
        String outputDatasetPath = "/realm/central.org/dataset/task-output";
        List<CipherKey> inputMasterKeys = createInputMasterKeys(5); // MUST be a set of unique keys, with no repeated keys
        for(CipherKey inputMasterKey : inputMasterKeys) {
            log.debug("input master key: {}", inputMasterKey.getKeyId());
        }
        CipherKey masterKey = generateNewOutputMasterKey(outputDatasetPath, inputMasterKeys);
        log.debug("master key algorithm: {}", masterKey.getAlgorithm());
        log.debug("master key length: {} bits", masterKey.getKeyLength());
        for (String attributeName : masterKey.map().keySet()) {
            log.debug("master key {}: {}", attributeName, masterKey.get(attributeName));
        }
        // demonstrate that using same inputs we would get same master key again, using same dataset path and salt and input master keys, even when input master keys are in different order
        log.debug("shuffling inputs...");
        Collections.shuffle(inputMasterKeys);
        for(CipherKey inputMasterKey : inputMasterKeys) {
            log.debug("input master key: {}", inputMasterKey.getKeyId());
        }
        byte[] salt = Base64.decodeBase64((String)masterKey.get("salt"));
        CipherKey masterKey2 = generateOutputMasterKey(outputDatasetPath, salt, inputMasterKeys);
        assertArrayEquals(masterKey.getEncoded(), masterKey2.getEncoded());
    }

    
    /**
     * Given a dataset path and a collection of input master keys, creates the
     * master key for the dataset path.
     * 
     * This function can be used to create a NEW output dataset master key.
     * It generates a new random salt. 
     * 
     * @param outputDatasetPath
     * @param inputMasterKeys
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private CipherKey generateNewOutputMasterKey(String outputDatasetPath, Collection<CipherKey> inputMasterKeys) throws NoSuchAlgorithmException, InvalidKeyException {
        // generate random salt for the output master key, must be 32 bytes because we use SHA-256 with HKDF
        byte[] salt = RandomUtil.randomByteArray(32);
        // delegate to generateOutputMasterKey that takes dataset path and salt
        return generateOutputMasterKey(outputDatasetPath, salt, inputMasterKeys);
    }
    
    /**
     * Given a dataset path and a collection of input master keys, creates the
     * master key for the dataset path.
     * 
     * This function can be used to generate the output master key bytes using
     * EXISTING key info that includes dataset path and salt.
     *
     * @param outputDatasetPath
     * @param salt must be 32 bytes to match SHA-256 output size
     * @param inputMasterKeys
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private CipherKey generateOutputMasterKey(String outputDatasetPath, byte[] salt, Collection<CipherKey> inputMasterKeys) throws NoSuchAlgorithmException, InvalidKeyException {
        ArrayList<CipherKey> inputMasterKeyParts = new ArrayList<>();
        // step 1. compute the length of the output master key (equal to length of longest input master key) , with minimum 128
        int outputMasterKeyLengthBits = computeOutputMasterKeyLengthBits(inputMasterKeys, 128);
        // step 2. create output master key part from each input key
        for (CipherKey inputMasterKey : inputMasterKeys) {
            inputMasterKeyParts.add(deriveMasterKeyPart(inputMasterKey.getEncoded(), salt, outputMasterKeyLengthBits, outputDatasetPath));
        }
        // step 3. combine the parts 
        byte[] outputMasterKeyBytes = combineMasterKeyParts(inputMasterKeyParts, outputMasterKeyLengthBits / 8);
        // step 4. package the output master key
        CipherKey outputMasterKey = new CipherKey();
        outputMasterKey.setEncoded(outputMasterKeyBytes);
        outputMasterKey.setAlgorithm("HKDF");
        outputMasterKey.setKeyLength(outputMasterKeyLengthBits);
        outputMasterKey.set("salt", Base64.encodeBase64String(salt));
        outputMasterKey.set("path", outputDatasetPath);
        outputMasterKey.set("digest_algorithm", "SHA-256");
        return outputMasterKey;
    }    

    private int computeOutputMasterKeyLengthBits(Collection<CipherKey> inputMasterKeyAttributes, int minimum) {
        int outputMasterKeyLengthBits = minimum;
        for (CipherKey inputMasterKey : inputMasterKeyAttributes) {
            Integer inputMasterKeyLength = inputMasterKey.getKeyLength();
            if (inputMasterKeyLength != null && inputMasterKeyLength > outputMasterKeyLengthBits) {
                outputMasterKeyLengthBits = inputMasterKeyLength;
            }
        }
        return outputMasterKeyLengthBits;
    }

    private byte[] combineMasterKeyParts(Collection<CipherKey> masterKeyParts, int length) {
        byte[] masterKey = new byte[length];
        Arrays.fill(masterKey, (byte) 0x00);
        for (CipherKey inputMasterKeyPart : masterKeyParts) {
            byte[] part = inputMasterKeyPart.getEncoded();
            for (int i = 0; i < length; i++) {
                masterKey[i] ^= part[i];
            }
        }
        return masterKey;
    }

    /**
     * Given an input master key, creates an output master key PART to be
     * combined with other output master key PARTS in order to form the final
     * output master key.
     *
     * The output master key PART may only be used with designated algorithm for
     * combining the parts which is included in the HKDF info block. The
     * "algorithm" is xor of union of all related output master key parts.
     *
     *
     * The salt is not secret and may be stored with output master key info.
     * This may change in a later milestone.
     *
     * @param masterKey MUST be designated to use with HKDF algorithm
     * @param salt length MUST be equal to digest length in bytes
     * @param keyLengthBits for output key part, MUST be equal to desired key
     * length bits of final output key
     * @param datasetPath of the output dataset
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private CipherKey deriveMasterKeyPart(byte[] masterKey, byte[] salt, int keyLengthBits, String datasetPath) throws NoSuchAlgorithmException, InvalidKeyException {
        HKDF hkdf = new HKDF("SHA256");
        MutableQuery query = new MutableQuery();
        query.add("keyuse", "masterkeypart");
        query.add("path", datasetPath);
        query.add("algorithm", "xor"); // this is the algorithm that may be used with the derived key
        query.add("length", String.valueOf(keyLengthBits));
        byte[] info = query.toString().getBytes(Charset.forName("UTF-8"));
        log.debug("derived key info: {}", query.toString());
        byte[] derivedKey = hkdf.deriveKey(salt, masterKey, hkdf.getMacLength(), info);  // #6304 salt should be hashlen bytes
        log.debug("derived key length: {}", derivedKey.length);

        // package the master key part with metadata
        CipherKey masterKeyPart = new CipherKey();
        masterKeyPart.setEncoded(derivedKey);
        masterKeyPart.setAlgorithm("xor");
        masterKeyPart.setKeyLength(keyLengthBits);
        masterKeyPart.set("path", datasetPath);
        masterKeyPart.set("keyuse", "masterkeypart");

        return masterKeyPart;
    }

}
