package com.gmdin.cryptography.cipher;

import com.sun.javafx.scene.traversal.Algorithm;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.Key;

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

}
