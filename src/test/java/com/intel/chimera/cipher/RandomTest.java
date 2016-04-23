package com.intel.chimera.cipher;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.Test;

import com.intel.chimera.random.OpensslSecureRandom;
import com.intel.chimera.random.OpensslSecureRandomNative;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import junit.framework.Assert;

public class RandomTest {
    @Test
    public void testRand() {
        byte[] rand = new byte[10];
        OpensslSecureRandomNative.nextRandBytes(rand);
        
        boolean ok = false;
        for (int i = 0; i < rand.length; i++) {
            byte b = rand[i];
            if(b != 0) {
                ok = true;
                break;
            }
        }
        
        System.out.println(Arrays.toString(rand));
        Assert.assertTrue(ok);
    }
    
}
