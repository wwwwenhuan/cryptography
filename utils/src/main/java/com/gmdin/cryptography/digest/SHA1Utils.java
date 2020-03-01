package com.gmdin.cryptography.digest;

import java.util.Objects;

/**
 * @author WEN HUAN
 * @date 2020/3/1 1:27
 */
public class SHA1Utils {

    private static final String DIGEST_ALGORITHM = "SHA";

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

}
