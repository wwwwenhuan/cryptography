package com.gmdin.cryptography.signature;

import com.gmdin.cryptography.KeyUtils;

/**
 * RSASignUitls
 * @author WEN HUAN
 * @date 2020/3/1 21:33
 */
public class RSASignUitls {

    /**
     * sign
     * @param privateKey
     * @param data
     * @param algorithm
     * @return
     */
    public static byte[] sign(byte[] privateKey, byte[] data, String algorithm){
        return BaseSign.sign(KeyUtils.buildRSAPrivateKey(privateKey), data, algorithm);
    }

    /**
     * verify
     * @param publicKey
     * @param data
     * @param sign
     * @param algorithm
     * @return
     */
    public static boolean verify(byte[] publicKey, byte[] data, byte[] sign,  String algorithm){
        return BaseSign.verify(KeyUtils.buildRSAPublicKey(publicKey), data, sign, algorithm);
    }

    /**
     * signString
     * @param privateKey
     * @param data
     * @param algorithm
     * @return
     */
    public static String signString(String privateKey, String data, String algorithm){
        return BaseSign.signString(KeyUtils.buildRSAPrivateKeyFromBase64(privateKey), data, algorithm);
    }

    /**
     * verifyString
     * @param publicKey
     * @param data
     * @param sign
     * @param algorithm
     * @return
     */
    public static boolean verifyString(String publicKey, String data, String sign, String algorithm){
        return BaseSign.verifyString(KeyUtils.buildRSAPublicKeyFromBase64(publicKey), data, sign, algorithm);
    }

}
