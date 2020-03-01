package com.gmdin.cryptography.digest;

import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

/**
 * MD5Utils
 * @author WEN HUAN
 * @date 2020/3/1 0:28
 */
public class MD5Utils {

    private static final String DIGEST_ALGORITHM = "MD5";

    /**
     *  生成摘要
     * @param data
     * @return
     */
    public static byte[] encode(byte[] data){
        return BaseDigest.digest(data, DIGEST_ALGORITHM);
    }

    /**
     *  生成字符串摘要
     * @param data
     * @return
     */
    public static String encodeString(String data){
        byte[] bytes = encode(data.getBytes());
        if(Objects.nonNull(bytes)){
            return BaseDigest.bytesToHexString(bytes);
        }
        return null;
    }

    /**
     *  生成加盐的字符串摘要：(md5(md5($data)+salt))
     * @param data
     * @param salt
     * @return
     */
    public static String encodeStringWithSalt(String data, String salt){
        String dataMd5 = encodeString(data);
        if(Objects.nonNull(dataMd5)){
            if(Objects.nonNull(salt)){
                return encodeString(dataMd5 + salt);
            }else{
                return dataMd5;
            }
        }
        return null;
    }

}
