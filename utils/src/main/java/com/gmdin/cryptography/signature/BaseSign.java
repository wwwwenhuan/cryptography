package com.gmdin.cryptography.signature;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

/**
 * BaseSign
 * @author WEN HUAN
 * @date 2020/3/1 17:33
 */
@Slf4j
public class BaseSign {

    private static final String ERROR_MSG_TEMPLATE = "BaseSign.{} error";

    /**
     * 私钥签名
     * @param privateKey
     * @param data
     * @param algorithm
     * @return
     */
    public static byte[] sign(PrivateKey privateKey, byte[] data, String algorithm){
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "sign", e);
        }
        return null;
    }

    /**
     * 公钥验签
     * @param publicKey
     * @param data
     * @param sign
     * @param algorithm
     * @return
     */
    public static boolean verify(PublicKey publicKey, byte[] data, byte[] sign, String algorithm){
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sign);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "verify", e);
        }
        return false;
    }

    /**
     *  签名字符串
     * @param privateKey
     * @param data
     * @param algorithm
     * @return
     */
    public static String signString(PrivateKey privateKey, String data, String algorithm){
        byte[] signBytes = sign(privateKey, data.getBytes(), algorithm);
        return Objects.nonNull(signBytes) ? Hex.encodeHexString(signBytes, true) : null;
    }

    /**
     *  验签字符串
     * @param publicKey
     * @param data
     * @param sign
     * @param algorithm
     * @return
     */
    public static boolean verifyString(PublicKey publicKey, String data, String sign, String algorithm){
        try {
            return verify(publicKey, data.getBytes(), Hex.decodeHex(sign), algorithm);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "verifyString", e);
        }
        return false;
    }

}
