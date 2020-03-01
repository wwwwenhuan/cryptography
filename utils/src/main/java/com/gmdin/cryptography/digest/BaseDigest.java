package com.gmdin.cryptography.digest;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.util.Objects;

/**
 * @author WEN HUAN
 * @date 2020/3/1 0:46
 */
@Slf4j
public class BaseDigest {

    private static final String ERROR_MSG_TEMPLATE = "BaseDigest.{} error";

    public static byte[] digest(final byte[] data, final String algorithm){
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return digest.digest(data);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "digest", e);
        }
        return null;
    }

    public static String digestString(final String data, final String algorithm){
        byte[] bytes = digest(data.getBytes(), algorithm);
        if(Objects.nonNull(bytes)){
            return Hex.encodeHexString(bytes);
        }
        return null;
    }

    /**
     *  生成加盐的字符串摘要：(hash(hash($data)+salt))
     * @param data
     * @param salt
     * @return
     */
    public static String digestStringWithSalt(final String data, final String salt, final String algorithm){
        String hashOfData = digestString(data, algorithm);
        if(Objects.nonNull(hashOfData)){
            if(Objects.nonNull(salt)){
                return digestString(hashOfData + salt, algorithm);
            }else{
                return hashOfData;
            }
        }
        return null;
    }
}
