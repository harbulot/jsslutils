/*-----------------------------------------------------------------------

  This file is part of the jSSLutils library.
  
Copyright (c) 2011, Bruno Harbulot.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the copyright holder nor the names of 
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

package org.jsslutils.sslcontext.trustmanagers;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.UUID;

import javax.net.ssl.X509TrustManager;

import org.jsslutils.sslcontext.X509TrustManagerWrapper;

/**
 * @author Bruno Harbulot.
 */
public class ServerCallbackWrappingTrustManager implements X509TrustManager {
    private final X509TrustManager trustManager;
    private final KeyStore localTrustStore;
    private final CheckServerTrustedCallback callback;

    /**
     * Creates a new instance from an existing X509TrustManager.
     * 
     * @param trustManager
     *            X509TrustManager to wrap.
     * @param callback
     *            {@link CheckServerTrustedCallback} from the user-interface.
     * @param localTrustStore
     *            {@link KeyStore} (loaded) to use as a trust store; use its
     *            store method to save it.
     */
    public ServerCallbackWrappingTrustManager(X509TrustManager trustManager,
            CheckServerTrustedCallback callback, KeyStore localTrustStore) {
        this.trustManager = trustManager;
        this.localTrustStore = localTrustStore;
        this.callback = callback;
    }

    /**
     * Creates a new instance from an existing X509TrustManager.
     * 
     * @param trustManager
     *            X509TrustManager to wrap.
     * @param callback
     *            {@link CheckServerTrustedCallback} from the user-interface.
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public ServerCallbackWrappingTrustManager(X509TrustManager trustManager,
            CheckServerTrustedCallback callback) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        this(trustManager, callback, KeyStore.getInstance(KeyStore
                .getDefaultType()));
        this.localTrustStore.load(null);
    }

    /**
     * Checks that the client is trusted; in this case, it delegates this check
     * to the trust manager it wraps
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        this.trustManager.checkClientTrusted(chain, authType);
    }

    /**
     * Checks that the server is trusted; in this case, it accepts anything.
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        try {
            this.trustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            try {
                boolean certTrusted = false;
                Enumeration<String> aliases = this.localTrustStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    Certificate cert = this.localTrustStore
                            .getCertificate(alias);
                    if (chain[0].equals(cert)) {
                        certTrusted = true;
                        break;
                    }
                }
                if (certTrusted
                        || this.callback.checkServerTrusted(chain, authType)) {
                    this.localTrustStore.setCertificateEntry(UUID.randomUUID()
                            .toString(), chain[0]);
                } else {
                    throw e;
                }
            } catch (KeyStoreException kse) {
                throw new CertificateException(kse);
            }
        }
    }

    /**
     * Returns the accepted issuers; in this case, it's an empty array.
     */
    public X509Certificate[] getAcceptedIssuers() {
        return this.trustManager.getAcceptedIssuers();
    }

    /**
     * Wrapper factory class that wraps existing X509TrustManagers into
     * X509TrustManagers that trust any clients.
     * 
     * @author Bruno Harbulot.
     */
    public static class Wrapper implements X509TrustManagerWrapper {
        private final CheckServerTrustedCallback callback;
        private final KeyStore localTrustStore;

        public Wrapper(CheckServerTrustedCallback callback,
                KeyStore localTrustStore) {
            super();
            this.callback = callback;
            this.localTrustStore = localTrustStore;
        }

        /**
         * Builds an X509TrustManager from another X509TrustManager.
         * 
         * @param trustManager
         *            original X509TrustManager.
         * @return wrapped X509TrustManager.
         */
        public X509TrustManager wrapTrustManager(X509TrustManager trustManager) {
            if (localTrustStore != null) {
                return new ServerCallbackWrappingTrustManager(
                        (X509TrustManager) trustManager, callback,
                        localTrustStore);
            } else {
                try {
                    return new ServerCallbackWrappingTrustManager(
                            (X509TrustManager) trustManager, callback);
                } catch (KeyStoreException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    public static interface CheckServerTrustedCallback {
        public boolean checkServerTrusted(X509Certificate[] chain,
                String authType);
    }
}