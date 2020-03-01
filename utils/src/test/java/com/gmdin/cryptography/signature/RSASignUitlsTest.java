package com.gmdin.cryptography.signature;

import com.gmdin.cryptography.cipher.RSACipherUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

/**
 * Test RSASignUitls
 * @author WEN HUAN
 * @date 2020/3/1 22:39
 */
public class RSASignUitlsTest {

    @Test
    public void test(){
        String algorithm = "SHA1withRSA";
        String sourceData = "hello world 世界你好";
        String sourceDataModified = "hello world 世界你好 fuck";
        Map<String,String> keyPair = RSACipherUtils.generateStringKeyPair();
        String privatekey = keyPair.get(RSACipherUtils.PRIVATE_KEY);
        String publickey = keyPair.get(RSACipherUtils.PUBLIC_KEY);
        String signData = RSASignUitls.signString(privatekey, sourceData, algorithm);
        System.out.println(signData);
        Assert.assertTrue(RSASignUitls.verifyString(publickey, sourceData, signData, algorithm));
        Assert.assertFalse(RSASignUitls.verifyString(publickey, sourceDataModified, signData, algorithm));
    }

}
