package com.gmdin.cryptography.cipher;

import com.gmdin.cryptography.KeyUtils;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;

/**
 * Cipher based on RSA
 * @author WEN HUAN
 * @date 2020/2/29 20:19
 */
@Slf4j
public class RSACipherUtils {

    /**
     * 算法名称
     */
    private static final String KEY_ALGORITHM = "RSA";

    /**
     *  RSA加解密规格算法（算法/工作模式/填充方式）
     */
    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static final String PRIVATE_KEY = "privateKey";
    public static final String PUBLIC_KEY = "publicKey";

    /**
     * 异常日志模板
     */
    private static final String ERROR_MSG_TEMPLATE = "RSACipherUtils.{} error";

    /**
     *  生成RSA的秘钥对
     * @return
     */
    public static Map<String, String> generateStringKeyPair(){
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            kpg.initialize(512);
            KeyPair keyPair = kpg.generateKeyPair();
            Map<String, String> keyMap = Maps.newHashMap();
            keyMap.put(PRIVATE_KEY, Base64.getUrlEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            keyMap.put(PUBLIC_KEY, Base64.getUrlEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            return keyMap;
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "generateStringKeyPair", e);
        }
        return null;
    }

    /**
     * 公钥加密
     * @param publicKey 公钥
     * @param data 明文
     * @return
     */
    public static byte[] encryptByPublicKey(byte[] publicKey, byte[] data){
        return BaseCipher.encrypt(KeyUtils.buildRSAPublicKey(publicKey), data, CIPHER_ALGORITHM);
    }

    /**
     * 私钥解密
     * @param privateKey 私钥
     * @param data 密文
     * @return
     */
    public static byte[] decryptByPrivateKey(byte[] privateKey, byte[] data){
        return BaseCipher.decrypt(KeyUtils.buildRSAPrivateKey(privateKey), data, CIPHER_ALGORITHM);
    }

    /**
     * 公钥加密字符串
     * @param publicKey
     * @param data
     * @return
     */
    public static String encryptStringByPublicKey(String publicKey, String data){
        return BaseCipher.encryptString(KeyUtils.buildRSAPublicKeyFromBase64(publicKey), data, CIPHER_ALGORITHM);
    }

    /**
     * 私钥解密字符串
     * @param privateKey
     * @param data
     * @return
     */
    public static String decryptStringByPrivateKey(String privateKey, String data){
        return BaseCipher.decryptString(KeyUtils.buildRSAPrivateKeyFromBase64(privateKey), data, CIPHER_ALGORITHM);
    }

}
