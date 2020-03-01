package com.gmdin.cryptography.cipher;

import com.gmdin.cryptography.KeyUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

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
        return BaseCipher.encryptString(buildSecretKeyFromSeed(seed.getBytes()), data, CIPHER_ALGORITHM);
    }

    /**
     *  基于seed解密字符串
     * @param seed
     * @param data
     * @return
     */
    public static String decryptStringBySeed(String seed, String data){
        return BaseCipher.decryptString(buildSecretKeyFromSeed(seed.getBytes()), data, CIPHER_ALGORITHM);
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
        return BaseCipher.encryptString(buildSecretKeyFromBase64(key), data, CIPHER_ALGORITHM);
    }

    /**
     * 使用AES字符串秘钥解密字符串
     * @param key
     * @param data
     * @return
     */
    public static String decryptString(String key, String data){
        return BaseCipher.decryptString(buildSecretKeyFromBase64(key), data, CIPHER_ALGORITHM);
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
            log.error(ERROR_MSG_TEMPLATE, "generateStringKey", e);
        }
        return null;
    }


    /**
     *  构建AES秘钥对象（128位长度）
     * @param key
     * @return
     */
    private static SecretKeySpec buildSecretKey(final byte[] key ){
        return KeyUtils.buildSecretKey(key, KEY_ALGORITHM);
    }

    /**
     * 从Base64字符串构建SecretKey
     * @param key
     * @return
     */
    private static SecretKeySpec buildSecretKeyFromBase64(final String key){
        return KeyUtils.buildSecretKeyFromBase64(key, KEY_ALGORITHM);
    }

    /**
     * 基于seed构建AES秘钥对象（128位长度）
     * @param seed
     * @return
     */
    private static SecretKeySpec buildSecretKeyFromSeed(final byte[] seed ){
        return KeyUtils.buildSecretKeyFromSeed(seed, 128, KEY_ALGORITHM);
    }

}
