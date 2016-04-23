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
package com.intel.chimera.random;

import java.nio.ByteBuffer;

import com.intel.chimera.cipher.OpensslNativeJna;
import com.sun.jna.ptr.PointerByReference;

/**
 * JNI interface of {@link SecureRandom} implementation.
 * The native method in this class is defined in
 * OpensslSecureRandomNative.h(genereted by javah).
 */
public class OpensslSecureRandomNative {
    
    final static int ENGINE_METHOD_RAND = 0x0008;
    final static OpensslNativeJna jnaLib = OpensslNativeJna.INSTANCE;  
    
  /**
   * Declares a native method to initialize SR.
   */
  public static void initSR() {
      //noop
  }

  /**
   * Judges whether use {@link OpensslSecureRandomNative} to
   * generate the user-specified number of random bits.
   *
   * @param bytes the array to be filled in with random bytes.
   * @return true if use {@link OpensslSecureRandomNative} to
   * generate the user-specified number of random bits.
   */
  public static boolean nextRandBytes(byte[] bytes) {
      /*PointerByReference rdrand;
      try {
          jnaLib.OPENSSL_cpuid_setup();
          jnaLib.OPENSSL_init_crypto(OpensslNativeJna.OPENSSL_INIT_ENGINE_RDRAND, Pointer.NULL);
          rdrand = jnaLib.ENGINE_by_id("rdrand");
          
          if(rdrand != null) {
              System.out.println("rdrand active");
              
              int rc = jnaLib.ENGINE_init(rdrand);
              System.out.println("rc rdrand "+rc);
              
              int rc2 = jnaLib.ENGINE_set_default(rdrand, ENGINE_METHOD_RAND);
              System.out.println("rc rdrand default "+rc2);
              
              openssl_rand_clean(rdrand, false);
              
              
          } 
          
      } catch (Throwable e) {
          System.out.println("rdrand not found "+e);
      }
      
      
      System.out.println("rdrand not active");*/
      
      ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
      if(jnaLib.RAND_bytes(buf, 10) == 1)
      {
          buf.rewind();
          buf.get(bytes,0, bytes.length);
      } else {
          //maybe fill bytes with 0 or -1
      }
     
      return true;
  }
  
  static void openssl_rand_clean(PointerByReference eng, boolean clean_locks)
  {
    if (null != eng) {
      jnaLib.ENGINE_finish(eng);
      jnaLib.ENGINE_free(eng);
    }
      
    jnaLib.ENGINE_cleanup();
    
    if (clean_locks) {
      //locks_cleanup();
    }
  }
}
