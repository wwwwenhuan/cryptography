package com.gmdin.cryptography.digest;

import org.junit.Assert;
import org.junit.Test;

/**
 * Test MD5Utils
 * @author WEN HUAN
 * @date 2020/3/1 1:18
 */
public class MD5UtilsTest {

    @Test
    public void testMD5(){
        String sourceData = "hello";
        String md5 = "5d41402abc4b2a76b9719d911017c592";
        String encodeData = MD5Utils.encodeString(sourceData);
        System.out.println(encodeData);
        Assert.assertEquals(md5, encodeData);
    }

    @Test
    public void testMD5withSalt(){
        String sourceData = "hello";
        String salt = "abc";
        String md5WithSalt = "128cd7841b5084e7829b62703912aada";
        String encodeData = MD5Utils.encodeStringWithSalt(sourceData, salt);
        System.out.println(encodeData);
        Assert.assertEquals(md5WithSalt, encodeData);
    }



}
