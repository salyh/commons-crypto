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

import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.PointerByReference;

public interface OpensslNativeJna extends Library {

    static final int OPENSSL_INIT_ENGINE_RDRAND = 0x00000200;
    
    static final int OOSL_JNA_ENCRYPT_MODE = 1;
    static final int OOSL_JNA_DECRYPT_MODE = 0;
    
    OpensslNativeJna INSTANCE = (OpensslNativeJna)
            Native.loadLibrary(("crypto"), OpensslNativeJna.class);
    
    Initializer INITIALIZER = new Initializer();
    
    class Initializer {
        static {
            Native.setProtected(true);
            INSTANCE.ERR_load_crypto_strings();
            System.out.println(INSTANCE.SSLeay_version(0)+", protected mode supported: "+Native.isProtected());
        }
    }
    
    //misc
    long SSLeay();
    String SSLeay_version(int type);
    void ERR_load_crypto_strings();
    long ERR_peek_error();
    String ERR_error_string(long err, char[] null_);
    String ERR_lib_error_string(long err);
    String ERR_func_error_string(long err);
    String ERR_reason_error_string(long err);
    
    //en-/decryption
    PointerByReference EVP_CIPHER_CTX_new();
    void EVP_CIPHER_CTX_init(PointerByReference p);
    int EVP_CIPHER_CTX_set_padding(PointerByReference c, int pad);
    PointerByReference EVP_aes_128_cbc();
    PointerByReference EVP_aes_128_ctr();
    PointerByReference EVP_aes_192_cbc();
    PointerByReference EVP_aes_192_ctr();
    PointerByReference EVP_aes_256_cbc();
    PointerByReference EVP_aes_256_ctr();
    int EVP_CipherInit_ex(PointerByReference ctx, PointerByReference cipher, PointerByReference impl, byte key[], byte iv[], int enc);
    int EVP_CipherUpdate(PointerByReference ctx, ByteBuffer bout, int[] outl, ByteBuffer in, int inl);
    int EVP_CipherFinal_ex(PointerByReference ctx, ByteBuffer bout, int[] outl);   
    void EVP_CIPHER_CTX_free(PointerByReference c);
    void EVP_CIPHER_CTX_cleanup(PointerByReference c);
    
    //Random generator
    PointerByReference RAND_get_rand_method();
    PointerByReference RAND_SSLeay();
    int RAND_bytes(ByteBuffer buf, int num);
    int ENGINE_finish(PointerByReference e);
    int ENGINE_free(PointerByReference e);
    int ENGINE_cleanup();
    int ENGINE_init(PointerByReference e);
    int ENGINE_set_default(PointerByReference e, int flags);
    PointerByReference ENGINE_by_id(String id);
    void ENGINE_load_rdrand();
    
    //callback multithreading
    public interface Id_function_cb extends Callback {
        long invoke ();
    }
   
    public interface Locking_function_cb extends Callback {
        void invoke(int mode, int n, String file, int line);
    }
    
    public static final Id_function_cb default_id_function = new Id_function_cb() {
        
        @Override
        public long invoke() {
            //id always positive
            long id = Thread.currentThread().getId();
            return id;
        }
    };
    
    void CRYPTO_set_id_callback(Id_function_cb id_function);
    void CRYPTO_set_locking_callback(Locking_function_cb locking_function);
}