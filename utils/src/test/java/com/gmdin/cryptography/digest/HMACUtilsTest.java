package com.gmdin.cryptography.digest;

import org.junit.Test;

/**
 * Test HMACUtils
 * @author WEN HUAN
 * @date 2020/3/1 15:52
 */
public class HMACUtilsTest {

    @Test
    public void testHmacMD5(){
        String sourceData = "hello";
        String key = "haha";
        String encodeData = HMACUtils.hmacMD5(key, sourceData);
        System.out.println(encodeData);
        System.out.println(encodeData.length());
    }

}
