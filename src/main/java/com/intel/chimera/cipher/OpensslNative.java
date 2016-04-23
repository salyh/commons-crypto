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
package com.intel.chimera.cipher;

import java.nio.ByteBuffer;

import com.sun.jna.ptr.PointerByReference;

public class OpensslNative {
    
   private static final OpensslNativeJna jnaLib = OpensslNativeJna.INSTANCE;
    

  /**
   * Declares a native method to initialize JNI field and method IDs.
   */
  public static void initIDs() {
      //noop
  }

  /**
   * Declares a native method to initialize the cipher context.
   *
   * @param algorithm The algorithm name of cipher
   * @param padding The padding name of cipher
   * @return the context address of cipher
   */
  public static PointerByReference initContext(int algorithm, int padding) {
      PointerByReference ptr = jnaLib.EVP_CIPHER_CTX_new();
      jnaLib.EVP_CIPHER_CTX_set_padding(ptr, padding);
      return ptr;
  }

  /**
   * Declares a native method to initialize the cipher context.
   *
   * @return the context address of cipher
   */
  public static PointerByReference init(PointerByReference context, int mode, int alg, int padding,
      byte[] key, byte[] iv) {
      jnaLib.EVP_CipherInit_ex(context, jnaLib.EVP_aes_128_cbc(), null, key, iv, mode);
      return context;
  }

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param input The input byte buffer
   * @param inputOffset The offset in input where the input starts
   * @param inputLength The input length
   * @param output The byte buffer for the result
   * @param outputOffset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public static int update(PointerByReference context, ByteBuffer input,
      int inputOffset, int inputLength, ByteBuffer output, int outputOffset,
      int maxOutputLength) {
      int[] len = new int[1];
      
      int oldPos = input.position();
      byte[] in = new byte[inputLength];
      input.position(inputOffset);
      input.get(in, 0, inputLength);
      input.position(oldPos);
      
      jnaLib.EVP_CipherUpdate(context, output, len, in, in.length);
      return len[0];
  }

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param input The input byte array
   * @param inputOffset  The offset in input where the input starts
   * @param inputLength The input length
   * @param output The byte array for the result
   * @param outputOffset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public static int updateByteArray(PointerByReference context, byte[] input,
      int inputOffset, int inputLength, byte[] output, int outputOffset,
      int maxOutputLength) {
      return update(context, ByteBuffer.wrap(input), inputOffset, inputLength, ByteBuffer.wrap(output), outputOffset, maxOutputLength);
  }

  /**
   * Finishes a multiple-part operation. The data is encrypted or decrypted,
   * depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param output The byte buffer for the result
   * @param offset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public static int doFinal(PointerByReference context, ByteBuffer output, int offset,
      int maxOutputLength) {
      int[] len = new int[1];
      output.position(offset);
      
      if(output.remaining() < maxOutputLength) {
          
      }
      
      jnaLib.EVP_CipherFinal_ex(context, output, len);
      return len[0];
  }

  /**
   * Finishes a multiple-part operation. The data is encrypted or decrypted,
   * depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param output The byte array for the result
   * @param offset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public static int doFinalByteArray(PointerByReference context, byte[] output, int offset,
      int maxOutputLength) {
      return doFinal(context,ByteBuffer.wrap(output), offset, maxOutputLength);
  }

  /**
   * Cleans the context at native.
   *
   * @param context The cipher context address
   */
  public static void clean(PointerByReference context) {
      jnaLib.EVP_CIPHER_CTX_free(context);
  }
}
