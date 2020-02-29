package com.gmdin.cryptography.cipher;

import org.junit.Assert;
import org.junit.Test;

import java.util.Base64;
import java.util.Map;

/**
 * Test RSACipherUtils
 * @author WEN HUAN
 * @date 2020/2/29 20:47
 */
public class RSACipherUtilsTest {

    @Test
    public void testGenKey(){
        Map<String,String> keyPair = RSACipherUtils.generateStringKeyPair();
        String privatekey = keyPair.get(RSACipherUtils.PRIVATE_KEY);
        String publickey = keyPair.get(RSACipherUtils.PUBLIC_KEY);
        System.out.println(privatekey);
        System.out.println(Base64.getUrlDecoder().decode(privatekey.getBytes()).length);
        System.out.println(publickey);
        System.out.println(Base64.getUrlDecoder().decode(publickey.getBytes()).length);
    }

    @Test
    public void testWithKeyPair(){
        String sourceData = "hello world 世界你好";
        Map<String,String> keyPair = RSACipherUtils.generateStringKeyPair();
        String privatekey = keyPair.get(RSACipherUtils.PRIVATE_KEY);
        String publickey = keyPair.get(RSACipherUtils.PUBLIC_KEY);
        String encodeData = RSACipherUtils.encryptStringByPublicKey(publickey, sourceData);
        System.out.println(encodeData);
        System.out.println(RSACipherUtils.decryptStringByPrivateKey(privatekey, encodeData));
        Assert.assertEquals(sourceData, RSACipherUtils.decryptStringByPrivateKey(privatekey, encodeData));
    }

}
