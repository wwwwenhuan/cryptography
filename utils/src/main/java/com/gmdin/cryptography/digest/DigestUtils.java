package com.gmdin.cryptography.digest;

/**
 * DigestUtils
 * @author WEN HUAN
 * @date 2020/3/1 21:15
 */
public class DigestUtils {

    public static final String MD5_ALGORITHM = "MD5";
    public static final String SHA1_ALGORITHM = "SHA";
    public static final String SHA256_ALGORITHM = "SHA-256";

    /**
     * md5
     * @param data
     * @return
     */
    public static byte[] md5(final byte[] data){
        return BaseDigest.digest(data, MD5_ALGORITHM);
    }

    /**
     * md5String
     * @param data
     * @return
     */
    public static String md5String(final String data){
        return BaseDigest.digestString(data, MD5_ALGORITHM);
    }

    /**
     * sha1
     * @param data
     * @return
     */
    public static byte[] sha1(final byte[] data){
        return BaseDigest.digest(data, SHA1_ALGORITHM);
    }

    /**
     * sha1String
     * @param data
     * @return
     */
    public static String sha1String(final  String data){
        return BaseDigest.digestString(data, SHA1_ALGORITHM);
    }

    /**
     * sha256
     * @param data
     * @return
     */
    public static byte[] sha256(final byte[] data){
        return BaseDigest.digest(data, SHA256_ALGORITHM);
    }

    /**
     * sha256String
     * @param data
     * @return
     */
    public static String sha256String(final String data){
        return BaseDigest.digestString(data, SHA256_ALGORITHM);
    }

    /**
     * md5WithSalt
     * @param data
     * @param salt
     * @return
     */
    public static String md5WithSalt(final String data, final String salt){
        return BaseDigest.digestStringWithSalt(data, salt, MD5_ALGORITHM);
    }

    /**
     * sha1WithSalt
     * @param data
     * @param salt
     * @return
     */
    public static String sha1WithSalt(final String data, final String salt){
        return BaseDigest.digestStringWithSalt(data, salt, SHA1_ALGORITHM);
    }

    /**
     * sha256WithSalt
     * @param data
     * @param salt
     * @return
     */
    public static String sha256WithSalt(final String data, final String salt){
        return BaseDigest.digestStringWithSalt(data, salt, SHA256_ALGORITHM);
    }

}
