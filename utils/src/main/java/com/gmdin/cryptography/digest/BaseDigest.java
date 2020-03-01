package com.gmdin.cryptography.digest;

import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;

/**
 * @author WEN HUAN
 * @date 2020/3/1 0:46
 */
@Slf4j
public class BaseDigest {

    private static final String ERROR_MSG_TEMPLATE = "BaseDigest.{} error";

    public static byte[] digest(byte[] data, String algorithm){
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return digest.digest(data);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "digest", e);
        }
        return null;
    }


    /**
     *  bytes 转16进制的字符串
     * @param data
     * @return
     */
    public static String bytesToHexString(byte[] data){
        StringBuilder stringBuilder = new StringBuilder();
        if (data == null || data.length <= 0) {
            return null;
        }
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

}
