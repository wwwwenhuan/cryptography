package com.gmdin.cryptography.digest;

import org.junit.Assert;
import org.junit.Test;

/**
 *  Test SHA256Utils
 * @author WEN HUAN
 * @date 2020/3/1 12:35
 */
public class SHA256UtilsTest {

    @Test
    public void testSHA256(){
        String sourceData = "hello";
        String sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        String encodeData = SHA256Utils.encodeString(sourceData);
        System.out.println(encodeData);
        Assert.assertEquals(sha256, encodeData);
    }

}
