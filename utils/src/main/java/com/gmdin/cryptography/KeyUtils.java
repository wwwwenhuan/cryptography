package com.gmdin.cryptography;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author WEN HUAN
 * @date 2020/3/1 17:54
 */
@Slf4j
public class KeyUtils {

    private static final String RSA_ALGORITHM = "RSA";

    private static final String ERROR_MSG_TEMPLATE = "KeyUtils.{} error";

    /**
     * 构建RSA私钥
     * @param key
     * @return
     */
    public static RSAPrivateKey buildRSAPrivateKey(byte[] key){
        try {
            KeySpec keySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
             return (RSAPrivateKey)keyFactory.generatePrivate(keySpec);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "buildRSAPrivateKey", e);
        }
        return null;
    }

    /**
     * 从Base64字符串构建RSA私钥
     * @param key
     * @return
     */
    public static RSAPrivateKey buildRSAPrivateKeyFromBase64(String key){
        return buildRSAPrivateKey(Base64.getUrlDecoder().decode(key));
    }

    /**
     * 构建RSA私钥
     * @param key
     * @return
     */
    public static RSAPublicKey buildRSAPublicKey(byte[] key){
        try {
            KeySpec keySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "buildRSAPublicKey", e);
        }
        return null;
    }

    /**
     * 从Base64字符串构建RSA公钥
     * @param key
     * @return
     */
    public static RSAPublicKey buildRSAPublicKeyFromBase64(String key){
        return buildRSAPublicKey(Base64.getUrlDecoder().decode(key));
    }

    /**
     * 构建SecretKey
     * @param key
     * @param algorithm
     * @return
     */
    public static SecretKeySpec buildSecretKey(byte[] key, String algorithm){
        try {
            return new SecretKeySpec(key, algorithm);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "buildSecretKey",  e);
        }
        return null;
    }

    /**
     * 从base64格式的字符串key构建SecretKey
     * @param key
     * @param algorithm
     * @return
     */
    public static SecretKeySpec buildSecretKeyFromBase64(String key, String algorithm){
        return buildSecretKey(Base64.getUrlDecoder().decode(key), algorithm);
    }

    /**
     * 从seed构建SecretKey
     * @param seed
     * @param algorithm
     * @return
     */
    public static SecretKeySpec buildSecretKeyFromSeed(final byte[] seed, String algorithm){
        try {
            KeyGenerator kg = KeyGenerator.getInstance(algorithm);
            //一定要指定SHA1PRNG算法，否则windows和Linux会存在不兼容
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed);
            kg.init(secureRandom);
            return new SecretKeySpec(kg.generateKey().getEncoded(), algorithm);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "buildSecretKeyFromSeed",  e);
        }
        return null;
    }

    /**
     * 从seed构建SecretKey
     * @param seed
     * @param keyLength
     * @param algorithm
     * @return
     */
    public static SecretKeySpec buildSecretKeyFromSeed(final byte[] seed, final int keyLength, final String algorithm){
        try {
            KeyGenerator kg = KeyGenerator.getInstance(algorithm);
            //一定要指定SHA1PRNG算法，否则windows和Linux会存在不兼容
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed);
            kg.init(keyLength, secureRandom);
            return new SecretKeySpec(kg.generateKey().getEncoded(), algorithm);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "buildSecretKeyFromSeed",  e);
        }
        return null;
    }

}
