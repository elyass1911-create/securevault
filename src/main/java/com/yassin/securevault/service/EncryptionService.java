package com.yassin.securevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;      // Standard für GCM
    private static final int TAG_LENGTH_BITS = 128;     // 16 bytes tag

    private final SecretKey key;
    private final SecureRandom secureRandom = new SecureRandom();

    public record EncryptedPayload(byte[] iv, byte[] ciphertext) {}

    public EncryptionService(@Value("${security.aes.key-base64}") String keyBase64) {
        byte[] raw = Base64.getDecoder().decode(keyBase64);
        if (raw.length != 32) {
            throw new IllegalStateException("security.aes.key-base64 must decode to 32 bytes (AES-256)");
        }
        this.key = new SecretKeySpec(raw, "AES");
    }

    public EncryptedPayload encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

            byte[] ciphertext = cipher.doFinal(plaintext);
            return new EncryptedPayload(iv, ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] iv, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            // Auth tag fail / tampering / wrong key -> Decryption fails
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}
