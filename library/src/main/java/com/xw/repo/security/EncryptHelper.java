package com.xw.repo.security;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * EncryptHelper
 * <p>
 * AES（非对称加密）的Key想要存在KeyStore里，需要Api 23才被支持，但是RSA（非对称加密）不受限制（Api >= 18）。
 * 因此用RSA加密AES的密钥保存到本地（如SharedPreferences），需要时解密得到AES的密钥，在用AES密钥来加解密。
 * <p>
 * 1.使用KeyStore生成随机的RSA Key（非对称加密密钥）；<br>
 * 2.生成AES Key（对称加密密钥），并用RSA PublicKey（公钥）加密后存入SharedPreferences；<br>
 * 3.从SharedPreferences取出AES Key，并用RSA PrivateKey（私钥）解密，用AES Key来加密和解密。<br>
 * <p>
 * Created by woxingxiao on 2017-09-01.
 */

public class EncryptHelper {

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";

    private static final String KEY_IV = "security_key_iv";
    private static final String KEY_AES_KEY = "security_key_aes_key";

    private KeyStore mKeyStore;
    private String mAlias;
    private SharedPreferences mSharedPreferences;

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    public EncryptHelper(@NonNull Context context) {
        try {
            mKeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            mKeyStore.load(null);

            mAlias = context.getPackageName();
            mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);

            if (!mKeyStore.containsAlias(mAlias)) {
                mSharedPreferences.edit().putString(KEY_IV, "").apply();
                genKeyStoreKey(context);
                genAESKey();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void genKeyStoreKey(Context context) throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            generateRSAKeyApi23();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            generateRSAKeApi18(context);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateRSAKeyApi23() throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);

        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(mAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build();

        keyPairGenerator.initialize(keyGenParameterSpec);
        keyPairGenerator.generateKeyPair();
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void generateRSAKeApi18(Context context) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 30);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(mAlias)
                .setSubject(new X500Principal("CN=" + mAlias))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);

        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }

    private void genAESKey() throws Exception {
        // Generate AES-Key
        byte[] aesKey = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(aesKey);

        // Generate 12 bytes iv then save to SharedPrefs
        byte[] generated = secureRandom.generateSeed(12);
        String iv = Base64.encodeToString(generated, Base64.DEFAULT);
        mSharedPreferences.edit().putString(KEY_IV, iv).apply();

        // Encrypt AES-Key with RSA Public Key then save to SharedPrefs
        String encryptAESKey = encryptRSA(aesKey);
        mSharedPreferences.edit().putString(KEY_AES_KEY, encryptAESKey).apply();
    }

    private String encryptRSA(byte[] plainText) throws Exception {
        PublicKey publicKey = mKeyStore.getCertificate(mAlias).getPublicKey();

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedByte = cipher.doFinal(plainText);
        return Base64.encodeToString(encryptedByte, Base64.DEFAULT);
    }

    private byte[] decryptRSA(String encryptedText) throws Exception {
        PrivateKey privateKey = (PrivateKey) mKeyStore.getKey(mAlias, null);

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes = Base64.decode(encryptedText, Base64.DEFAULT);
        return cipher.doFinal(encryptedBytes);
    }

    /**
     * Encryption.
     *
     * @param plainText The plain text you want to encrypted.
     * @return The encrypted text.
     * @throws Exception NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException.
     */
    public String encrypt(String plainText) throws Exception {
        return encryptAES(plainText);
    }

    /**
     * Decryption.
     *
     * @param encryptedText The encrypted text you want to decrypted.
     * @return The decrypted text.
     * @throws Exception NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException.
     */
    public String decrypt(String encryptedText) throws Exception {
        return decryptAES(encryptedText);
    }

    private String encryptAES(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, getAESKey(), new IvParameterSpec(getIV()));

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    private String decryptAES(String encryptedText) throws Exception {
        byte[] decodedBytes = Base64.decode(encryptedText.getBytes(), Base64.DEFAULT);
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.DECRYPT_MODE, getAESKey(), new IvParameterSpec(getIV()));

        return new String(cipher.doFinal(decodedBytes));
    }

    private SecretKeySpec getAESKey() throws Exception {
        String encryptedKey = mSharedPreferences.getString(KEY_AES_KEY, "");
        byte[] aesKey = decryptRSA(encryptedKey);

        return new SecretKeySpec(aesKey, AES_MODE);
    }

    private byte[] getIV() {
        String prefIV = mSharedPreferences.getString(KEY_IV, "");
        return Base64.decode(prefIV, Base64.DEFAULT);
    }

}
