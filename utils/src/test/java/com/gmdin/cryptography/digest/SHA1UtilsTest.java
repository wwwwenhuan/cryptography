package com.gmdin.cryptography.digest;

import org.junit.Assert;
import org.junit.Test;

/**
 *  Test SHA1Utils
 * @author WEN HUAN
 * @date 2020/3/1 12:35
 */
public class SHA1UtilsTest {

    @Test
    public void testSHA1(){
        String sourceData = "hello";
        String sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
        String encodeData = SHA1Utils.encodeString(sourceData);
        System.out.println(encodeData);
        Assert.assertEquals(sha1, encodeData);
    }

}
