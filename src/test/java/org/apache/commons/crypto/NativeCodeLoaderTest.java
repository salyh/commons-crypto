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

package org.apache.commons.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

public class NativeCodeLoaderTest {

    @Test
    public void test() {    	
    	
    	final boolean forceNativeCodeLoaded = 
    			Boolean.getBoolean(Crypto.CONF_PREFIX+"test.force_native_code_loaded");
    	
    	System.out.println("** INFO: Native code is enforced: "+forceNativeCodeLoaded);
    	
        if (NativeCodeLoader.isNativeCodeLoaded()) {
            System.out.println("** INFO: Native (JNI) code loaded successfully. ("
                + OpenSslInfoNative.NativeName()
                + " "
                + OpenSslInfoNative.NativeVersion()
                + " "
                + OpenSslInfoNative.NativeTimeStamp()
                + ")"
            );
            System.out.println("** INFO: "+OpenSslInfoNative.SSLeayVersion(0)
                + " (0x"+Long.toHexString(OpenSslInfoNative.SSLeay())+")");
        } else {
            System.out.println("** WARN: Native (JNI) code was not loaded: " 
                + NativeCodeLoader.getLoadingError());
            
            if(forceNativeCodeLoaded) {
            	Assert.fail("Native code could be loaded although native code is enforced. Reason "
                + NativeCodeLoader.getLoadingError());
            }
        }
    }
    
    @Test
    public void testOpenSslVersion() {
    	Assume.assumeTrue(NativeCodeLoader.isNativeCodeLoaded());
    	final long openSsl101cVersion = 0x1000103f;
    	Assert.assertTrue(OpenSslInfoNative.SSLeayVersion(0) 
    			+ " is too old. Version 1.0.1c or newer is necessary.", OpenSslInfoNative.SSLeay() >= openSsl101cVersion);
    }

    @Test
    public void testNativePresent() {
        Assume.assumeTrue(NativeCodeLoader.isNativeCodeLoaded());
        assertNull(NativeCodeLoader.getLoadingError());
    }

    @Test
    public void testNativeNotPresent() {
        Assume.assumeTrue(!NativeCodeLoader.isNativeCodeLoaded());
        assertNotNull(NativeCodeLoader.getLoadingError());
    }

    @Test
    public void testCanLoadIfPresent() {
        Assume.assumeTrue(NativeCodeLoader.isNativeCodeLoaded());
        // This will try to reload the library, so should work
        assertNull(NativeCodeLoader.loadLibrary());
    }

    @Test
    @Ignore("Seems to cause issues with other tests on Linux; disable for now")
    public void testUnSuccessfulLoad() throws Exception {
        final String nameKey = System.getProperty(Crypto.LIB_NAME_KEY);
        final String pathKey = System.getProperty(Crypto.LIB_PATH_KEY);
        // An empty file should cause UnsatisfiedLinkError
        File empty = File.createTempFile("NativeCodeLoaderTest", "tmp");
        try {
            System.setProperty(Crypto.LIB_PATH_KEY, empty.getParent());
            System.setProperty(Crypto.LIB_NAME_KEY, empty.getName());
            final Throwable result = NativeCodeLoader.loadLibrary();
            assertNotNull(result);
            assertTrue(result instanceof UnsatisfiedLinkError);
        } finally {
            empty.delete();
            if (nameKey != null) {
                System.setProperty(Crypto.LIB_NAME_KEY, nameKey);
            }
            if (pathKey != null) {
                System.setProperty(Crypto.LIB_PATH_KEY, pathKey);
            }
        }
    }
}
