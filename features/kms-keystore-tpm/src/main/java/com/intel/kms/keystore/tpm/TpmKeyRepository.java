/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.tpm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.dcsg.cpg.http.MutableQuery;
import com.intel.dcsg.cpg.io.ByteArray;
import com.intel.keplerlake.io.ByteArrayRepository;
import com.intel.kms.repository.Repository;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.exec.ExecUtil;
import com.intel.mtwilson.util.exec.Result;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.StringUtils;

/**
 * Provides convenient access to TPM sealed master keys. The keys are
 * content-addressable by the set of PCR values to which they are sealed. Due to
 * the nature of TPM sealing, this repository can only unseal and retrieve the
 * master key that is sealed to PCRs matching the current PCR values. You may
 * attempt to retrieve any sealed master key by its locator but expect an
 * exception for all sealed master keys not matching the current PCR values. The
 * master key attributes are always available.
 *
 * @author jbuhacoff
 */
public class TpmKeyRepository implements Repository {

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmKeyRepository.class);
    final private static Charset UTF8 = Charset.forName("UTF-8");
    final private ByteArrayRepository tpmSealedMasterKeyRepository;
    final private Repository userKeyRepository;
    final private ObjectMapper mapper;
    final private Integer[] defaultPcrs; // new Integer[]{0, 17, 18, 19}

    public TpmKeyRepository(Repository userKeyRepository, ByteArrayRepository tpmSealedMasterKeyRepository, Integer[] defaultPcrs) {
        this.userKeyRepository = userKeyRepository;
        this.tpmSealedMasterKeyRepository = tpmSealedMasterKeyRepository;
        this.mapper = new ObjectMapper();
        this.defaultPcrs = defaultPcrs;
    }

    public Map<Integer, String> getCurrentPcrMap() throws IOException {
        // run "tagent tpm tpm_readpcr" command to read all 24 pcr values from TPM
        Result result = ExecUtil.execute("tagent", "tpm", "tpm_readpcr");
        // parse results and extract values for 0,17,18,19
        if (result.getExitCode() == 0) {
            String text = result.getStdout();
            Map<Integer, String> pcrMap = parsePcrMap(text);
            return filterPcrMap(pcrMap, defaultPcrs);
        }
        log.debug("getCurrentPcrMap got exit code {} from tpm_readpcr", result.getExitCode());
        log.debug("getCurrentPcrMap tpm_readpcr stderr: {}", result.getStderr());
        throw new IOException("Cannot read pcrs");
    }

    /**
     *
     * @param pcrMap containing all available pcrs
     * @param selected array of the pcrs to keep
     * @return a new map containing only the selected pcrs
     */
    public Map<Integer, String> filterPcrMap(Map<Integer, String> pcrMap, Integer[] selected) {
        HashMap<Integer, String> filteredPcrMap = new HashMap<>();
        for (Integer pcr : selected) {
            filteredPcrMap.put(pcr, pcrMap.get(pcr));
        }
        return filteredPcrMap;
    }

    /**
     * Result String format is like this:
     *
     * <pre>
     * 00 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     * 01 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     * ...
     * 23 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     * </pre>
     *
     * @param pcrMap
     * @return the string representation of the pcr map
     */
    public String formatPcrMap(Map<Integer, String> pcrMap) {
        ArrayList<Integer> pcrList = new ArrayList<>();
        pcrList.addAll(pcrMap.keySet());
        Collections.sort(pcrList);
        ArrayList<String> lines = new ArrayList<>();
        for (Integer pcr : pcrList) {
            lines.add(String.format("%2d %s", pcr, pcrMap.get(pcr)));
        }
        return StringUtils.join(lines, "\n");
    }

    /**
     * Parse a pcr map in string format
     *
     * Input String format is like this:
     *
     * <pre>
     * 00 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     * 01 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     * ...
     * 23 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     * </pre>
     *
     *
     * @param text input pcr map
     * @return the same info in a java Map
     */
    public Map<Integer, String> parsePcrMap(String text) {
        HashMap<Integer, String> pcrMap = new HashMap<>();
        String[] lines = StringUtils.split(text, "\n");
        for (String line : lines) {
            String[] parts = StringUtils.split(line, " ");
            Integer pcr = Integer.valueOf(parts[0]);
            String value = parts[1];
            pcrMap.put(pcr, value);
        }
        return pcrMap;
    }

    /**
     * Creates a content-address for the pcr map using its string format
     *
     * @param pcrMap
     * @return
     */
    public String toLocator(Map<Integer, String> pcrMap) {
        String pcrMapText = formatPcrMap(pcrMap);
        byte[] pcrMapEncoded = pcrMapText.getBytes(UTF8);
        return Sha256Digest.digestOf(pcrMapEncoded).toHexString();
    }

    private CipherKey getCurrentKEK() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        Map<Integer, String> pcrMap = getCurrentPcrMap();
        String locator = toLocator(pcrMap);
        if (tpmSealedMasterKeyRepository.contains(locator + "/encrypted-key")) {
            return loadKEK(locator);
        } else {
            return createKEK(pcrMap);
        }
    }
    
    private CipherKeyAttributes getKeyInfoKEK() {
        CipherKeyAttributes keyInfo = new CipherKeyAttributes();
        keyInfo.setAlgorithm("AES");
        keyInfo.setKeyLength(128); // in bits
        keyInfo.setMode("CBC");
        keyInfo.setPaddingMode("PKCS5Padding");
        return keyInfo;
    }
    
    private CipherKeyAttributes getKeyInfoHMAC() {
        CipherKeyAttributes keyInfo = new CipherKeyAttributes();
        keyInfo.setAlgorithm("HMAC");
        keyInfo.setKeyLength(256); // in bits
        keyInfo.set("digest_algorithm", "SHA-256");
        return keyInfo;
    }

    private String[] concat(String[] array1, String[] array2) {
        String[] result = new String[array1.length+array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }
    
    private String[] getSealDataCommandPcrArguments(Set<Integer> pcrs) {
        ArrayList<Integer> pcrlist = new ArrayList<>();
        pcrlist.addAll(pcrs);
        Collections.sort(pcrlist);
        int pcrcount = pcrlist.size();
        String[] result = new String[pcrcount*2];
        for(int i=0; i<pcrcount; i++) {
            result[i*2] = "-p";
            result[i*2+1] = String.valueOf(pcrlist.get(i));
        }
        return result;
    }

    /**
     * Create a new master key encryption key sealed to current pcr map
     *
     * @param pcrMap
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private CipherKey createKEK(Map<Integer, String> pcrMap) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        String locator = toLocator(pcrMap);
        // generate random master key
        byte[] masterKeyBytes = RandomUtil.randomByteArray(32); // 256-bit master key
        // generate arguments for tpm_sealdata command
        String[] args = concat(new String[] { "tpm", "tpm_sealdata", "-z" }, getSealDataCommandPcrArguments(pcrMap.keySet()));
        // call tagent tpm tpm_sealkey
        Result result = ExecUtil.execute(new ByteArrayInputStream(masterKeyBytes), "tagent", args);
        if (result.getExitCode() == 0) {
            // store the sealed master key
            byte[] sealedMasterKeyBytes = result.getStdoutByteArray();
            tpmSealedMasterKeyRepository.put(locator + "/encrypted-key", sealedMasterKeyBytes);
            // store the key info
            CipherKeyAttributes keyInfo = new CipherKeyAttributes();
            keyInfo.setAlgorithm("HKDF");
            keyInfo.setKeyId(locator);
            keyInfo.setKeyLength(256); // in bits
            keyInfo.set("digest_algorithm", "SHA-256");
            keyInfo.set("pcrs", formatPcrMap(pcrMap));
            // skip writing the "hmac" and "keyenc" derivation info since it's hard-coded in this class
            String keyInfoJson = mapper.writeValueAsString(keyInfo);
            byte[] keyInfoJsonUTF8 = keyInfoJson.getBytes(UTF8);
            tpmSealedMasterKeyRepository.put(locator + "/info", keyInfoJsonUTF8);
            // store the hmac for the key info
            CipherKey masterKey = new CipherKey();
            masterKey.copyFrom(keyInfo);
            masterKey.setEncoded(masterKeyBytes);
            CipherKey hmacKey = deriveHmacKey(masterKey);
            byte[] hmac = hmacSha256(hmacKey.getEncoded(), keyInfoJsonUTF8);
            tpmSealedMasterKeyRepository.put(locator + "/hmac", hmac);
            // derive and return the KEK
            CipherKey kek = deriveKeyEncryptionKey(masterKey);
            kek.setKeyId(locator);
            return kek;
         }
        log.debug("createKEK got exit code {} from tpm_sealdata", result.getExitCode());
        log.debug("createKEK tpm_sealdata stderr: {}", result.getStderr());
        throw new IOException("Cannot create KEK");
    }

    private CipherKey loadKEK(String locator) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        // load the sealed key from disk and unseal it
        byte[] sealedMasterKeyBytes = tpmSealedMasterKeyRepository.get(locator + "/encrypted-key");
        Result result = ExecUtil.execute(new ByteArrayInputStream(sealedMasterKeyBytes), "tagent", "tpm", "tpm_unsealdata", "-z");
        if (result.getExitCode() == 0) {
            byte[] masterKeyBytes = result.getStdoutByteArray();
            // load key info
            byte[] keyInfoJsonUTF8 = tpmSealedMasterKeyRepository.get(locator + "/info");
            CipherKeyAttributes masterKeyInfo = mapper.readValue(new String(keyInfoJsonUTF8, UTF8), CipherKeyAttributes.class);
            CipherKey masterKey = new CipherKey();
            masterKey.copyFrom(masterKeyInfo);
            masterKey.setEncoded(masterKeyBytes);            
            // derive the hmac key to verify integrity of key info
            CipherKey hmacKey = deriveHmacKey(masterKey);
            // verify hmac
            byte[] hmac = tpmSealedMasterKeyRepository.get(locator + "/hmac");
            byte[] expectedHmac = hmacSha256(hmacKey.getEncoded(), keyInfoJsonUTF8);
            if (Arrays.equals(hmac, expectedHmac)) {
                // derive and return the KEK
                CipherKey kek = deriveKeyEncryptionKey(masterKey);
                kek.setKeyId(locator);
                return kek;
            }
            throw new InvalidKeyException("Integrity verification failed");
        }
        log.debug("loadKEK got exit code {} from tpm_unsealdata", result.getExitCode());
        log.debug("loadKEK tpm_unsealdata stderr: {}", result.getStderr());
        throw new IOException("Cannot load KEK");
    }

    private String toJavaCipher(CipherKeyAttributes keyInfo) {
        return toJavaCipher(keyInfo.getAlgorithm(), keyInfo.getMode(), keyInfo.getPaddingMode());
    }
    
    private String toJavaCipher(String algorithm, String cipherMode, String paddingMode) {
        if( paddingMode == null || paddingMode.isEmpty() ) {
            paddingMode = "NoPadding";
        }
        return String.format("%s/%s/%s", algorithm, cipherMode, paddingMode);
    }
    
    /**
     * 
     * @param plaintext
     * @param masterKey
     * @return the wrapped key comprised of the iv and the cipher text
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    private byte[] wrap(byte[] plaintext, CipherKey masterKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKey secretKey = new SecretKeySpec(masterKey.getEncoded(), masterKey.getAlgorithm());
        log.debug("wrap cipher: {}", toJavaCipher(masterKey));
        Cipher cipher = Cipher.getInstance(toJavaCipher(masterKey)); // throws NoSuchAlgorithmException, NoSuchPaddingException
        log.debug("wrap block size: {}", cipher.getBlockSize());
        // encrypt
        int blockSizeBytes = cipher.getBlockSize();
        IvParameterSpec iv = new IvParameterSpec(RandomUtil.randomByteArray(blockSizeBytes));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv); // throws InvalidKeyException, InvalidAlgorithmParameterException
        byte[] ciphertext = cipher.doFinal(plaintext); // throws IllegalBlockSizeException, BadPaddingException
        return ByteArray.concat(iv.getIV(), ciphertext);
    }

    private byte[] unwrap(byte[] ciphertext, CipherKey masterKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKey secretKey = new SecretKeySpec(masterKey.getEncoded(), masterKey.getAlgorithm());
        log.debug("unwrap cipher: {}", toJavaCipher(masterKey));
        Cipher cipher = Cipher.getInstance(toJavaCipher(masterKey)); // throws NoSuchAlgorithmException, NoSuchPaddingException
        log.debug("unwrap block size: {}", cipher.getBlockSize());
        // decrypt
        int blockSizeBytes = cipher.getBlockSize();
        IvParameterSpec iv = new IvParameterSpec(ciphertext, 0, blockSizeBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv); // throws InvalidKeyException, InvalidAlgorithmParameterException
        return cipher.doFinal(ciphertext, blockSizeBytes, ciphertext.length - blockSizeBytes); // skip the first 16 bytes (IV), throws IllegalBlockSizeException, BadPaddingException
    }

    private CipherKey deriveHmacKey(CipherKey masterKey) throws NoSuchAlgorithmException, InvalidKeyException {
        CipherKeyAttributes keyInfo = getKeyInfoHMAC();
        byte[] hmacKeyBytes = deriveKey(masterKey, "hmac", keyInfo);
        CipherKey key = new CipherKey();
        key.copyFrom(keyInfo);
        key.setEncoded(hmacKeyBytes);
        return key;
    }

    private CipherKey deriveKeyEncryptionKey(CipherKey masterKey) throws NoSuchAlgorithmException, InvalidKeyException {
        CipherKeyAttributes keyInfo = getKeyInfoKEK();
        byte[] kekBytes = deriveKey(masterKey, "keyenc", keyInfo);
        CipherKey key = new CipherKey();
        key.copyFrom(keyInfo);
        key.setEncoded(kekBytes);
        return key;
    }

    // NOTE: copied from kms-keystore RemoteKeyManager; modified; needs to be refactored to common module
    private byte[] deriveKey(CipherKey masterKey, String context, CipherKeyAttributes derivedKeyAttributes) throws NoSuchAlgorithmException, InvalidKeyException {
        String derivationAlgorithm = masterKey.getAlgorithm();
        if (derivationAlgorithm != null && derivationAlgorithm.equals("HKDF")) {
            HKDF hkdf = new HKDF((String) masterKey.get("digest_algorithm"));
            MutableQuery query = new MutableQuery();
            query.add("context", context); // hmac, kek, etc.
            String[] attributeNames = new String[]{"algorithm", "mode", "key_length", "padding_mode", "digest_algorithm"};
            for (String attributeName : attributeNames) {
                String attributeValue = (String) derivedKeyAttributes.get(attributeName);
                if (attributeValue != null) {
                    query.add(attributeName, attributeValue);
                }
            }
            byte[] salt = (byte[]) masterKey.get("salt");
            byte[] info = query.toString().getBytes(Charset.forName("UTF-8"));
            log.debug("derived key info: {}", query.toString());
            byte[] derivedKey = hkdf.deriveKey(salt, masterKey.getEncoded(), hkdf.getDigestLengthBytes(), info);  // #6304 salt should be hashlen bytes
            log.debug("derived key length: {}", derivedKey.length);
            return derivedKey;
        } else {
            throw new UnsupportedOperationException("Unsupported key derivation algorithm: " + derivationAlgorithm);
        }
    }

    // NOTE: copied from kms-keystore RemoteKeyManager; needs to be refactored to common module
    private byte[] hmacSha256(byte[] key, byte[] document) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256"); // throws NoSuchAlgorithmException
        mac.init(keySpec); // throws InvalidKeyException
        return mac.doFinal(document);

    }

    @Override
    public void create(CipherKeyAttributes item) {
        try {
            // create the new key 
            byte[] keyBytes = RandomUtil.randomByteArray(item.getKeyLength() / 8);
            // use the current kek for wrapping new keys
            CipherKey kek = getCurrentKEK();
            byte[] wrappedKeyBytes = wrap(keyBytes, kek);
            // store the current kek's locator in the input item so caller will have this
            item.set("kek_locator", kek.getKeyId());
            // prepare the wrapped cipher key object for storage
            CipherKey wrapped = new CipherKey();
            wrapped.copyFrom(item);
            wrapped.setEncoded(wrappedKeyBytes);
            // store wrapped key on disk
            userKeyRepository.store(wrapped);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void store(CipherKey item) {
        try {
            byte[] keyBytes = item.getEncoded();
            // use the current kek for wrapping new keys
            CipherKey kek = getCurrentKEK();
            byte[] wrappedKeyBytes = wrap(keyBytes, kek);
            // store the current kek's locator in the input item so caller will have this
            item.set("kek_locator", kek.getKeyId());
            // prepare the wrapped cipher key object for storage
            CipherKey wrapped = new CipherKey();
            wrapped.copyFrom(item);
            wrapped.setEncoded(wrappedKeyBytes);
            // store wrapped key on disk
            userKeyRepository.store(wrapped);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CipherKeyAttributes getAttributes(String id) {
        CipherKeyAttributes keyInfo = userKeyRepository.getAttributes(id);
        return keyInfo;
    }

    @Override
    public CipherKey retrieve(String id) {
        try {
            CipherKey cipherKey = userKeyRepository.retrieve(id);
            if (cipherKey == null) {
                return null;
            }
            // look for kek locator
            String locator = (String) cipherKey.get("kek_locator");
            if (locator == null) {
                throw new IllegalArgumentException("Missing KEK locator");
            }
            // use the current kek for unwrapping new keys, if it matches the kek locator on the stored key
            CipherKey kek = getCurrentKEK();
            if (!locator.equals(kek.getKeyId())) {
                log.debug("cannot retrieve key {} wrapped with kek {} because current kek is {}", id, locator, kek.getKeyId());
                throw new InvalidKeyException("Requested key is not accessible");
            }
            // replace the wrapped key with the unwrapped key in memory 
            byte[] keyBytes = unwrap(cipherKey.getEncoded(), kek);
            cipherKey.setEncoded(keyBytes);
            return cipherKey;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void delete(String id) {
        userKeyRepository.delete(id);
    }

    @Override
    public Collection<String> list() {
        return userKeyRepository.list();
    }

}
