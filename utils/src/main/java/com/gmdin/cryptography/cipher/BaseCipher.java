package com.gmdin.cryptography.cipher;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.Key;
import java.util.Base64;
import java.util.Objects;

/**
 * Base Cipher class
 * @author WEN HUAN
 * @date 2020/2/29 23:36
 */
@Slf4j
public class BaseCipher {

    private static byte[] doFinal(Key key, byte[] data, int mode, String algorithm){
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(mode, key);
            return cipher.doFinal(data);
        }catch (Exception e){
            log.error("BaseCipher.doFinal error", e);
        }
        return null;
    }

    /**
     * 加密
     * @param key 秘钥
     * @param data 明文
     * @param algorithm 算法
     * @return
     */
    public static byte[] encrypt(Key key, byte[] data, String algorithm){
        return doFinal(key,data, Cipher.ENCRYPT_MODE, algorithm);
    }

    /**
     * 解密
     * @param key 秘钥
     * @param data 密文
     * @param algorithm 算法
     * @return
     */
    public static byte[] decrypt(Key key, byte[] data, String algorithm){
        return doFinal(key,data, Cipher.DECRYPT_MODE, algorithm);
    }

    /**
     * 加密字符串
     * @param key
     * @param data
     * @param algorithm
     * @return
     */
    public static String encryptString(Key key, String data, String algorithm){
        return Base64.getUrlEncoder().encodeToString(encrypt(key, data.getBytes(), algorithm));
    }

    /**
     * 解密字符串
     * @param key
     * @param data
     * @param algorithm
     * @return
     */
    public static String decryptString(Key key, String data,  String algorithm){
        byte[] content = decrypt(key, Base64.getUrlDecoder().decode(data), algorithm);
        if(Objects.nonNull(content)){
            return new String(content);
        }
        return null;
    }

}
