/*-----------------------------------------------------------------------

  This file is part of the jSSLutils library.
  
Copyright (c) 2008-2009, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author........: Bruno Harbulot

-----------------------------------------------------------------------*/
package org.jsslutils.sslcontext.test;

import static org.junit.Assert.fail;

import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;

import org.jsslutils.sslcontext.DefaultSSLContextFactory;
import org.jsslutils.sslcontext.PKIXSSLContextFactory;
import org.jsslutils.sslcontext.SSLContextFactory;
import org.jsslutils.sslcontext.X509SSLContextFactory;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Bruno Harbulot
 * 
 */
public class DefaultStoreTest {
    public final static String KNOWN_CA_URL = System
            .getProperty("jsslutils.test.known_ca_url");
    public final static String UNKNOWN_CA_URL = System
            .getProperty("jsslutils.test.unknown_ca_url");

    public void connect(SSLContext sslContext, String address) throws Exception {
        URL url = new URL(address);
        HttpsURLConnection connection = (HttpsURLConnection) url
                .openConnection();
        if (sslContext != null) {
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
        }
        connection.connect();
        connection.disconnect();
    }
    
    @Before
    public void setUp() {
        Assume.assumeTrue(KNOWN_CA_URL != null && UNKNOWN_CA_URL != null);
    }

    @Test
    public void testKnownCA() throws Exception {
        connect(null, KNOWN_CA_URL);
    }

    @Test
    public void testUnknownCA() throws Exception {
        try {
            connect(null, UNKNOWN_CA_URL);
            fail();
        } catch (SSLHandshakeException e) {
        }
    }

    @Test
    public void testDefaultFactoryKnownCA() throws Exception {
        SSLContextFactory sslContextFactory = new DefaultSSLContextFactory();
        SSLContext sslContext = sslContextFactory.buildSSLContext();

        connect(sslContext, KNOWN_CA_URL);
    }

    @Test
    public void testDefaultFactoryUnKnownCA() throws Exception {
        SSLContextFactory sslContextFactory = new DefaultSSLContextFactory();
        SSLContext sslContext = sslContextFactory.buildSSLContext();

        try {
            connect(sslContext, UNKNOWN_CA_URL);
            fail();
        } catch (SSLHandshakeException e) {
        }
    }

    @Test
    public void testX509FactoryKnownCA() throws Exception {
        SSLContextFactory sslContextFactory = new X509SSLContextFactory();
        SSLContext sslContext = sslContextFactory.buildSSLContext();

        connect(sslContext, KNOWN_CA_URL);
    }

    @Test
    public void testX509FactoryUnKnownCA() throws Exception {
        SSLContextFactory sslContextFactory = new X509SSLContextFactory();
        SSLContext sslContext = sslContextFactory.buildSSLContext();

        try {
            connect(sslContext, UNKNOWN_CA_URL);
            fail();
        } catch (SSLHandshakeException e) {
        }
    }

    @Test
    public void testPKIXFactoryKnownCA() throws Exception {
        SSLContextFactory sslContextFactory = new PKIXSSLContextFactory();
        SSLContext sslContext = sslContextFactory.buildSSLContext();

        connect(sslContext, KNOWN_CA_URL);
    }

    @Test
    public void testPKIXFactoryUnKnownCA() throws Exception {
        SSLContextFactory sslContextFactory = new PKIXSSLContextFactory();
        SSLContext sslContext = sslContextFactory.buildSSLContext();

        try {
            connect(sslContext, UNKNOWN_CA_URL);
            fail();
        } catch (SSLHandshakeException e) {
        }
    }
}
