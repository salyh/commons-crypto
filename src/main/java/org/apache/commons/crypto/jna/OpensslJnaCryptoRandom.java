/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.jna;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.utils.Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.jna.ptr.PointerByReference;

/**
 * <p>
 * OpenSSL secure random using JNI. This implementation is thread-safe.
 * </p>
 *
 * <p>
 * If using an Intel chipset with RDRAND, the high-performance hardware random
 * number generator will be used and it's much faster than SecureRandom. If
 * RDRAND is unavailable, default OpenSSL secure random generator will be used.
 * It's still faster and can generate strong random bytes.
 * </p>
 *
 * @see <a href="https://wiki.openssl.org/index.php/Random_Numbers">
 *      https://wiki.openssl.org/index.php/Random_Numbers</a>
 * @see <a href="http://en.wikipedia.org/wiki/RdRand">
 *      http://en.wikipedia.org/wiki/RdRand</a>
 */
public class OpensslJnaCryptoRandom extends Random implements CryptoRandom {
    private static final long serialVersionUID = -7128193502768749585L;
    private static final Log LOG = LogFactory.getLog(OpensslJnaCryptoRandom.class
            .getName());
    private final static OpensslNativeJna opensslNativeJna = OpensslNativeJna.INSTANCE;
    private final boolean rdrandEnabled;
    private PointerByReference rdrandEngine;
    private static Lock LOCK = new ReentrantLock();

    /**
     * Constructs a {@link OpensslJnaCryptoRandom}.
     *
     * @param props the configuration properties.
     * @throws NoSuchAlgorithmException if no Provider supports a
     *         SecureRandomSpi implementation for the specified algorithm.
     */
    public OpensslJnaCryptoRandom(Properties props)
            throws NoSuchAlgorithmException {

        boolean rdrandLoaded = false;
        try {
            
            opensslNativeJna.CRYPTO_set_id_callback(OpensslNativeJna.default_id_function);
            opensslNativeJna.CRYPTO_set_locking_callback(new OpensslNativeJna.Locking_function_cb() {
                
                @Override
                public void invoke(int mode, int n, String file, int line) {
                    boolean lock = ((1&mode) != 0);
                    
                    if(lock) {
                        LOCK.lock();
                        //System.out.println("LOCK: "+n);
                    } else {
                        LOCK.unlock();
                        //System.out.println("UNLOCK: "+n);
                    }
                }
            });
            
            opensslNativeJna.ENGINE_load_rdrand();
            rdrandEngine = opensslNativeJna.ENGINE_by_id("rdrand");
            int ENGINE_METHOD_RAND = 0x0008;
            if(rdrandEngine != null) {
                int rc = opensslNativeJna.ENGINE_init(rdrandEngine);
                
                if(rc != 0) {
                    int rc2 = opensslNativeJna.ENGINE_set_default(rdrandEngine, ENGINE_METHOD_RAND);
                    if(rc2 != 0) {
                        rdrandLoaded = true;
                    }
                    
                }
            } else {
                LOG.debug("Unable to find rdrand engine");
            }
            
        } catch (Throwable e) {
            LOG.debug("Unable load or initialize rdrand engine due to "+e,e);
        }
        
        LOG.debug("Will use rdrand engine: "+rdrandLoaded);
        rdrandEnabled = rdrandLoaded;
        
        if(!rdrandLoaded && rdrandEngine != null) {
            close();
        }
    }

    /**
     * Generates a user-specified number of random bytes. It's thread-safe.
     *
     * @param bytes the array to be filled in with random bytes.
     */
    @Override
    public void nextBytes(byte[] bytes) {
        
        if(rdrandEnabled && opensslNativeJna.RAND_get_rand_method().equals(opensslNativeJna.RAND_SSLeay())) {
            throw new RuntimeException("rdrand should be used but default is detected");
        }
        
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        if(opensslNativeJna.RAND_bytes(buf, bytes.length) == 1) {
            buf.rewind();
            buf.get(bytes,0, bytes.length);
        } else {
            throw new RuntimeException("Unable to get random data");
        }
    }

    /**
     * Overrides {@link OpensslJnaCryptoRandom}. For {@link OpensslJnaCryptoRandom},
     * we don't need to set seed.
     *
     * @param seed the initial seed.
     */
    @Override
    public void setSeed(long seed) {
        // Self-seeding.
    }

    /**
     * Overrides Random#next(). Generates an integer containing the
     * user-specified number of random bits(right justified, with leading
     * zeros).
     *
     * @param numBits number of random bits to be generated, where 0
     *        {@literal <=} <code>numBits</code> {@literal <=} 32.
     * @return int an <code>int</code> containing the user-specified number of
     *         random bits (right justified, with leading zeros).
     */
    @Override
    final protected int next(int numBits) {
        Utils.checkArgument(numBits >= 0 && numBits <= 32);
        int numBytes = (numBits + 7) / 8;
        byte b[] = new byte[numBytes];
        int next = 0;

        nextBytes(b);
        for (int i = 0; i < numBytes; i++) {
            next = (next << 8) + (b[i] & 0xFF);
        }

        return next >>> (numBytes * 8 - numBits);
    }

    /**
     * Overrides {@link java.lang.AutoCloseable#close()}. Closes openssl context
     * if native enabled.
     */
    @Override
    public void close() {
        
        if(rdrandEngine != null) {
            opensslNativeJna.ENGINE_finish(rdrandEngine);
            opensslNativeJna.ENGINE_free(rdrandEngine);
        }
        
        opensslNativeJna.ENGINE_cleanup();
        
        //cleanup locks
        //opensslNativeJna.CRYPTO_set_locking_callback(null);
        //LOCK.unlock();
    }

    /**
     * Checks if rdrand engine is used to retrieve random bytes
     * 
     * @return true if rdrand is used, false if default engine is used
     */
    public boolean isRdrandEnabled() {
        return rdrandEnabled;
    }
}
