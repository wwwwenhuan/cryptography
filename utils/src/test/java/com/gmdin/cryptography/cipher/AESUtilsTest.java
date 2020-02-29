package com.gmdin.cryptography.cipher;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.util.Base64;

/**
 *  Test  AESUtils
 * @author WEN HUAN
 * @date 2020/2/29 17:58
 */
public class AESUtilsTest {

    @Test
    public void testWithKey(){
        String sourceData = "hello world 世界你好";
        String key = AESUtils.generateStringKey();
        System.out.println(key);
        System.out.println(Base64.getUrlDecoder().decode(key).length);
        String encodeData = AESUtils.encryptString(key, sourceData);
        System.out.println(encodeData);
        System.out.println(AESUtils.decryptString(key, encodeData));
        Assert.assertEquals(sourceData, AESUtils.decryptString(key,encodeData));
    }

    @Test
    public void testWithSeed(){
        String sourceData = "hello world 世界你好";
        String seed = "haha";
        String encodeData = AESUtils.encryptStringBySeed(seed, sourceData);
        System.out.println(encodeData);
        System.out.println(AESUtils.decryptStringBySeed(seed, encodeData));
        Assert.assertEquals(sourceData, AESUtils.decryptStringBySeed(seed,encodeData));
    }

    @Test
    public void testGenKeyWithSeed(){
        String seed = "haha";
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed.getBytes());
            kg.init(128,secureRandom);
            System.out.println(Base64.getUrlEncoder().encodeToString(kg.generateKey().getEncoded()));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
