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

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public interface OpensslNativeJna extends Library {

    public static int OPENSSL_INIT_ENGINE_RDRAND = 0x00000200;

    OpensslNativeJna INSTANCE = (OpensslNativeJna)
            Native.loadLibrary(("crypto"), OpensslNativeJna.class);
    
    PointerByReference EVP_CIPHER_CTX_new();
    int EVP_CIPHER_CTX_set_padding(PointerByReference c, int pad);
    
    PointerByReference EVP_aes_128_cbc();
    
    int EVP_CipherInit_ex(PointerByReference ctx, PointerByReference cipher, PointerByReference impl, byte key[], byte iv[], int enc);
    
    
    //int EVP_EncryptInit_ex(PointerByReference ctx, PointerByReference cipher, PointerByReference impl, byte key[], byte iv[]);
    int EVP_CipherUpdate(PointerByReference ctx, ByteBuffer bout, int[] outl, byte in[], int inl);
    int EVP_CipherFinal_ex(PointerByReference ctx, ByteBuffer bout, int[] outl);

    //int EVP_DecryptInit_ex(PointerByReference ctx, PointerByReference cipher, PointerByReference impl, byte key[], byte iv[]);
    //int EVP_DecryptUpdate(PointerByReference ctx, ByteBuffer out, int[] outl, byte in[], int inl);
    //int EVP_DecryptFinal_ex(PointerByReference ctx, ByteBuffer outm, int[] outl);
    
    void EVP_CIPHER_CTX_free(PointerByReference c);
    
    int RAND_bytes(ByteBuffer buf, int num);
    int ENGINE_finish(PointerByReference e);
    int ENGINE_free(PointerByReference e);
    int ENGINE_cleanup(/*PointerByReference e*/);
    int ENGINE_init(PointerByReference e);
    int ENGINE_set_default(PointerByReference e, int flags);
    PointerByReference ENGINE_by_id(String id);
    //void ENGINE_load_rdrand();
    NativeLong ERR_get_error();
    void OPENSSL_cpuid_setup();
    
    int OPENSSL_init_crypto(int opts, Pointer settings);
}
