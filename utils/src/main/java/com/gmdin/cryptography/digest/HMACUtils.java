package com.gmdin.cryptography.digest;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Objects;

/**
 * HMACUtils
 * HMAC （Hash-based Message Authentication Code）：一种带秘钥的摘要算法(结合已有的摘要算法 + 秘钥，功效类似于加盐)
 * HMAC的秘钥长度可以任意，但是最好不要小于摘要的长度；真正运算时，会将key处理成和消息分组一样的长度(B)，不够B位的尾部用0补全，超过B位的先将key取HASH，然后再补0
 *  输出长度和原有HASH算法一致
 * 主要作用：1.消息认证码(防篡改)，可用作简单的验签；2. 用户密码的存储(HMAC哈希值 + key)
 * 用来替代HASH 算法+ SALT，更加安全，推荐使用
 * @author WEN HUAN
 * @date 2020/3/1 1:28
 */
@Slf4j
public class HMACUtils {

    /**
     * 常用HMAC算法名称
     */
    public static final String HMAC_MD5_ALGORITHM = "HmacMD5";
    public static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    public static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private static final String ERROR_MSG_TEMPLATE = "HMACUtils.{} error";

    /**
     * 通用编码方法
     * @param key
     * @param data
     * @param algorithm
     * @return
     */
    public static byte[] encode(byte[] key, byte[] data, String algorithm){
        try {
            SecretKey secretKey = new SecretKeySpec(key, algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKey);
            return mac.doFinal(data);
        }catch (Exception e){
            log.error(ERROR_MSG_TEMPLATE, "encode" , e);
        }
        return null;
    }

    /**
     * 编码字符串
     * @param key
     * @param data
     * @param algorithm
     * @return
     */
    public static String encodeString(String key, String data, String algorithm){
        byte[] result = encode(key.getBytes(), data.getBytes(), algorithm);
        if(Objects.nonNull(result)){
            return Hex.encodeHexString(result);
        }
        return null;
    }

    /**
     * hmacMD5
     * @param key
     * @param data
     * @return
     */
    public static String hmacMD5(String key, String data){
        return encodeString(key, data, HMAC_MD5_ALGORITHM);
    }

    /**
     * hmacSHA1
     * @param key
     * @param data
     * @return
     */
    public static String hmacSHA1(String key, String data){
        return encodeString(key, data, HMAC_SHA1_ALGORITHM);
    }

    /**
     * hmacSHA256
     * @param key
     * @param data
     * @return
     */
    public static String hmacSHA256(String key, String data){
        return encodeString(key, data, HMAC_SHA256_ALGORITHM);
    }

}
