package com.gmdin.cryptography.cipher;

import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * Cipher based on RSA
 * @author WEN HUAN
 * @date 2020/2/29 20:19
 */
@Slf4j
public class RSACipherUtils {

    private static final String KEY_ALGORITHM = "RSA";

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
        try{
            KeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey rsaPublicKey = keyFactory.generatePublic(keySpec);
            return BaseCipher.encrypt(rsaPublicKey, data, KEY_ALGORITHM);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "encryptByPublicKey", e);
        }
        return null;
    }

    /**
     * 私钥解密
     * @param privateKey 私钥
     * @param data 密文
     * @return
     */
    public static byte[] decryptByPrivateKey(byte[] privateKey, byte[] data){
        try{
            KeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey rsaPrivateKey = keyFactory.generatePrivate(keySpec);
            return BaseCipher.decrypt(rsaPrivateKey, data, KEY_ALGORITHM);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "decryptByPrivateKey", e);
        }
        return null;
    }

    /**
     * 公钥加密字符串
     * @param publicKey
     * @param data
     * @return
     */
    public static String encryptStringByPublicKey(String publicKey, String data){
        return Base64.getUrlEncoder().encodeToString(encryptByPublicKey(Base64.getUrlDecoder().decode(publicKey), data.getBytes()));
    }

    /**
     * 私钥解密字符串
     * @param privateKey
     * @param data
     * @return
     */
    public static String decryptStringByPrivateKey(String privateKey, String data){
        byte[] content = decryptByPrivateKey(Base64.getUrlDecoder().decode(privateKey), Base64.getUrlDecoder().decode(data));
        if(Objects.nonNull(content)){
            return new String(content);
        }
        return null;
    }

}
