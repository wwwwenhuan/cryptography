package com.gmdin.cryptography.cipher;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * AES cipher utils
 *  seed：任意byte数组(也可以使用String.getBytes)，KeyGenerator秘钥生成器可以基于seed生成固定的秘钥(真正加解密使用的秘钥)，
 *  key：128位的秘钥
 *  如果配置文件中存的是seed，则每次加解密时都需要实时生成key，然后使用生成的key加解密
 *  如果配置文件中存的是key，则每次加解密时可以直接使用该key
 * @author WEN HUAN
 * @date 2020/2/29 16:31
 */
@Slf4j
public class AESUtils {

    /**
     * AES秘钥算法
     */
    private static final String KEY_ALGORITHM = "AES";
    /**
     *  AES加解密规格算法（算法/工作模式/填充方式）
     */
    private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    /**
     * 异常日志模板
     */
    private static final String ERROR_MSG_TEMPLATE = "AESUtils.{} error";

    /**
     *  基于seed加密二进制数据
     * @param seed
     * @param data
     * @return
     */
    public static byte[] encryptBySeed(byte[] seed, byte[] data){
        return BaseCipher.encrypt(buildSecretKeyFromSeed(seed), data, CIPHER_ALGORITHM);
    }

    /**
     *  基于seed解密二进制数据
     * @param seed
     * @param data
     * @return
     */
    public static byte[] decryptBySeed(byte[] seed, byte[] data){
        return BaseCipher.decrypt(buildSecretKeyFromSeed(seed), data, CIPHER_ALGORITHM);
    }


    /**
     *  基于seed加密字符串
     * @param seed
     * @param data
     * @return
     */
    public static String encryptStringBySeed(String seed, String data){
        return Base64.getUrlEncoder().encodeToString(encryptBySeed(seed.getBytes(), data.getBytes()));
    }

    /**
     *  基于seed解密字符串
     * @param seed
     * @param data
     * @return
     */
    public static String decryptStringBySeed(String seed, String data){
        byte[] content = decryptBySeed(seed.getBytes(), Base64.getUrlDecoder().decode(data));
        if(Objects.nonNull(content)){
            return new String(content);
        }
        return null;
    }

    /**
     * 使用AES秘钥加密数据
     * @param key AES秘钥
     * @param data 明文
     * @return
     */
    public static byte[] encrypt(byte[] key, byte[] data){
        return BaseCipher.encrypt(buildSecretKey(key), data, CIPHER_ALGORITHM);
    }

    /**
     * 使用AES秘钥解密数据
     * @param key AES秘钥
     * @param data 明文
     * @return
     */
    public static byte[] decrypt(byte[] key, byte[] data){
        return BaseCipher.decrypt(buildSecretKey(key), data, CIPHER_ALGORITHM);
    }

    /**
     * 使用AES字符串秘钥加密字符串
     * @param key
     * @param data
     * @return
     */
    public static String encryptString(String key, String data){
        return Base64.getUrlEncoder().encodeToString(encrypt(Base64.getUrlDecoder().decode(key), data.getBytes()));
    }

    /**
     * 使用AES字符串秘钥解密字符串
     * @param key
     * @param data
     * @return
     */
    public static String decryptString(String key, String data){
        byte[] content = decrypt(Base64.getUrlDecoder().decode(key), Base64.getUrlDecoder().decode(data));
        if(Objects.nonNull(content)){
            return new String(content);
        }
        return null;
    }

    /**
     * 生成base64编码的AES秘钥(128位)字符串
     * @return
     */
    public static String generateStringKey(){
        try{
            KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
            kg.init(128);
            return Base64.getUrlEncoder().encodeToString(kg.generateKey().getEncoded());
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "generateKeyToString", e);
        }
        return null;
    }


    /**
     *  构建AES秘钥对象（128位长度）
     * @param key
     * @return
     */
    private static SecretKeySpec buildSecretKey(final byte[] key ){
        try {
            return new SecretKeySpec(key, KEY_ALGORITHM);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "buildSecretKey",  e);
        }
        return null;
    }

    /**
     * 基于seed构建AES秘钥对象（128位长度）
     * @param seed
     * @return
     */
    private static SecretKeySpec buildSecretKeyFromSeed(final byte[] seed ){
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
            //一定要指定SHA1PRNG算法，否则windows和Linux会存在不兼容
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed);
            kg.init(128, secureRandom);
            return new SecretKeySpec(kg.generateKey().getEncoded(), KEY_ALGORITHM);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "buildSecretKeyFromSeed",  e);
        }
        return null;
    }

}
