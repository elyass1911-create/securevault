package com.yassin.securevault;

import com.yassin.securevault.service.EncryptionService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {

    // 32 bytes -> Base64
    private static String base64KeyOf32Bytes(char fill) {
        byte[] raw = new byte[32];
        for (int i = 0; i < raw.length; i++) raw[i] = (byte) fill;
        return Base64.getEncoder().encodeToString(raw);
    }

    @Test
    void encrypt_then_decrypt_roundtrip_returns_original() {
        EncryptionService svc = new EncryptionService(base64KeyOf32Bytes('A'));

        byte[] plaintext = "super_secret_value".getBytes(StandardCharsets.UTF_8);

        EncryptionService.EncryptedPayload payload = svc.encrypt(plaintext);
        byte[] decrypted = svc.decrypt(payload.iv(), payload.ciphertext());

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void decrypt_with_wrong_key_fails() {
        EncryptionService svc1 = new EncryptionService(base64KeyOf32Bytes('A'));
        EncryptionService svc2 = new EncryptionService(base64KeyOf32Bytes('B'));

        byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);

        EncryptionService.EncryptedPayload payload = svc1.encrypt(plaintext);

        assertThrows(IllegalStateException.class, () ->
                svc2.decrypt(payload.iv(), payload.ciphertext())
        );
    }

    @Test
    void decrypt_with_tampered_ciphertext_fails() {
        EncryptionService svc = new EncryptionService(base64KeyOf32Bytes('A'));

        byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);

        EncryptionService.EncryptedPayload payload = svc.encrypt(plaintext);

        byte[] tampered = payload.ciphertext().clone();
        tampered[tampered.length - 1] ^= 0x01; // flip 1 bit => GCM tag should fail

        assertThrows(IllegalStateException.class, () ->
                svc.decrypt(payload.iv(), tampered)
        );
    }
}