/*-----------------------------------------------------------------------

  This file is part of the jSSLutils library.
  
Copyright (c) 2008-2010, The University of Manchester, United Kingdom.
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

package org.jsslutils.sslcontext;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jsslutils.keystores.KeyStoreLoader;

/**
 * This class is a factory that provides methods for creating an SSLContext
 * configured with the settings set in this factory: using the SunX509 algorithm
 * for both the key manager and the trust manager. These managers are created
 * from the KeyStores passed to the constructor. Unlike the PKIX implementation,
 * this implementation does not support CRLs.
 * 
 * @author Bruno Harbulot
 * 
 */
public class X509SSLContextFactory extends DefaultSSLContextFactory {
    private final static Logger LOGGER = Logger
            .getLogger(X509SSLContextFactory.class.getName());

    public final static String KEYSTORE_FILE_PROP = "org.jsslutils.prop.keyStore";
    public final static String KEYSTORE_TYPE_PROP = "org.jsslutils.prop.keyStoreType";
    public final static String KEYSTORE_PROVIDER_PROP = "org.jsslutils.prop.keyStoreProvider";
    public final static String KEYSTORE_PASSWORD_PROP = "org.jsslutils.prop.keyStorePassword";
    public final static String KEYSTORE_PROVIDER_CLASS_PROP = "org.jsslutils.prop.keyStoreProviderClass";
    public final static String KEYSTORE_PROVIDER_ARGFILE_PROP = "org.jsslutils.prop.keyStoreProviderArgFile";
    public final static String KEYSTORE_PROVIDER_ARGTEXT_PROP = "org.jsslutils.prop.keyStoreProviderArgText";

    public final static String KEY_PASSWORD_PROP = "org.jsslutils.prop.keyPassword";

    public final static String TRUSTSTORE_FILE_PROP = "org.jsslutils.prop.trustStore";
    public final static String TRUSTSTORE_TYPE_PROP = "org.jsslutils.prop.trustStoreType";
    public final static String TRUSTSTORE_PROVIDER_PROP = "org.jsslutils.prop.trustStoreProvider";
    public final static String TRUSTSTORE_PASSWORD_PROP = "org.jsslutils.prop.trustStorePassword";
    public final static String TRUSTSTORE_PROVIDER_CLASS_PROP = "org.jsslutils.prop.trustStoreProviderClass";
    public final static String TRUSTSTORE_PROVIDER_ARGFILE_PROP = "org.jsslutils.prop.trustStoreProviderArgFile";
    public final static String TRUSTSTORE_PROVIDER_ARGTEXT_PROP = "org.jsslutils.prop.trustStoreProviderArgText";

    private KeyStore keyStore;
    private char[] keyPassword;
    private KeyStore trustStore;

    private CallbackHandler keyPasswordCallbackHandler;
    private CallbackHandler keyStorePasswordCallbackHandler;
    private CallbackHandler trustStorePasswordCallbackHandler;

    private X509KeyManagerWrapper keyManagerWrapper;
    private X509TrustManagerWrapper trustManagerWrapper;

    /**
     * Builds an SSLContextFactory using the SunX509 algorithm in the
     * TrustManagerFactory.
     */
    public X509SSLContextFactory() {
        this(null, (char[]) null, null);
    }

    /**
     * Builds an SSLContextFactory using the SunX509 algorithm in the
     * TrustManagerFactory.
     * 
     * @param keyStore
     *            KeyStore that contains the key.
     * @param keyPassword
     *            password to the key.
     * @param trustStore
     *            KeyStore that contains the trusted X.509 certificates.
     */
    public X509SSLContextFactory(KeyStore keyStore, String keyPassword,
            KeyStore trustStore) {
        this(keyStore,
                (keyPassword != null) ? keyPassword.toCharArray() : null,
                trustStore);
    }

    /**
     * Builds an SSLContextFactory using the SunX509 algorithm in the
     * TrustManagerFactory.
     * 
     * @param keyStore
     *            KeyStore that contains the key.
     * @param keyPassword
     *            password to the key.
     * @param trustStore
     *            KeyStore that contains the trusted X.509 certificates.
     */
    public X509SSLContextFactory(KeyStore keyStore, char[] keyPassword,
            KeyStore trustStore) {
        this.keyStore = keyStore;
        this.trustStore = trustStore;
        setKeyPassword(keyPassword);
    }

    /**
     * Configures some this factory based on values in the properties. In
     * addition to the properties described in
     * {@link DefaultSSLContextFactory#configure(Properties)}, the following
     * properties are used:
     * 
     * <table>
     * <tbody>
     * <tr>
     * <th>Property name</th>
     * <th>Description</th>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.keyStore</td>
     * <td>Path to the {@link KeyStore} file to use as the keystore; use "NONE"
     * if it's not file-based.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.keyStoreType</td>
     * <td>Keystore type for the keystore.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.keyStoreProvider</td>
     * <td>Name of the security {@link Provider} to use to load the keystore.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.keyStorePassword</td>
     * <td>Password to load the keystore.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.keyStoreProviderClass</td>
     * <td>Name of the {@link Provider} class to use to load the keystore,
     * typically used with a provider arg file or text; this takes precedence
     * over loading via provider name.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.keyStoreProviderArgFile</td>
     * <td>Path to the file to use as an argument when instantiating the
     * keystore {@link Provider} via its class name</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.keyStoreProviderArgText</td>
     * <td>Text content of the argument when instantiating the keystore
     * {@link Provider} via its class name.</td>
     * </tr>
     * 
     * <tr>
     * <td>org.jsslutils.prop.keyPassword</td>
     * <td>Password to use the key itself from the keystore.</td>
     * </tr>
     * 
     * <tr>
     * <td>org.jsslutils.prop.trustStore</td>
     * <td>Path to the {@link KeyStore} file to use as the truststore; use
     * "NONE" if it's not file-based.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.trustStoreType</td>
     * <td>Keystore type for the truststore.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.trustStoreProvider</td>
     * <td>Name of the security {@link Provider} to use to load the truststore.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.trustStorePassword</td></td>
     * <td>Password to load the truststore.</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.trustStoreProviderClass</td>
     * <td>Name of the {@link Provider} class to use to load the truststore,
     * typically used with a provider arg file or text; this takes precedence
     * over loading via provider name.</td>
     * </tr>
     * 
     * <tr>
     * <td>org.jsslutils.prop.trustStoreProviderArgFile</td>
     * <td>Path to the file to use as an argument when instantiating the
     * truststore {@link Provider} via its class name</td>
     * </tr>
     * <tr>
     * <td>org.jsslutils.prop.trustStoreProviderArgText</td>
     * <td>Text content of the argument when instantiating the truststore
     * {@link Provider} via its class name.</td>
     * </tr>
     * </tbody>
     * </table>
     * 
     * @param properties
     *            properties to use for the configuration.
     */
    @Override
    public void configure(Properties properties)
            throws SSLContextFactoryException {
        super.configure(properties);
        try {
            if (getKeyStore() == null) {
                KeyStoreLoader ksl = new KeyStoreLoader();
                ksl.setKeyStorePath(properties.getProperty(KEYSTORE_FILE_PROP));
                ksl.setKeyStoreType(properties.getProperty(KEYSTORE_TYPE_PROP));
                ksl.setKeyStoreProvider(properties
                        .getProperty(KEYSTORE_PROVIDER_PROP));
                ksl.setKeyStorePassword(properties
                        .getProperty(KEYSTORE_PASSWORD_PROP));
                ksl
                        .setKeyStorePasswordCallbackHandler(this.keyStorePasswordCallbackHandler);
                ksl.setKeyStoreProviderClass(properties
                        .getProperty(KEYSTORE_PROVIDER_CLASS_PROP));
                ksl.setKeyStoreProviderArgFile(properties
                        .getProperty(KEYSTORE_PROVIDER_ARGFILE_PROP));
                ksl.setKeyStoreProviderArgText(properties
                        .getProperty(KEYSTORE_PROVIDER_ARGTEXT_PROP));
                this.keyStore = ksl.loadKeyStore();
            }
            
            setKeyPassword(properties.getProperty(KEY_PASSWORD_PROP));

            if (getTrustStore() == null) {
                KeyStoreLoader ksl = new KeyStoreLoader();
                ksl.setKeyStorePath(properties
                        .getProperty(TRUSTSTORE_FILE_PROP));
                ksl.setKeyStoreType(properties
                        .getProperty(TRUSTSTORE_TYPE_PROP));
                ksl.setKeyStoreProvider(properties
                        .getProperty(TRUSTSTORE_PROVIDER_PROP));
                ksl.setKeyStorePassword(properties
                        .getProperty(TRUSTSTORE_PASSWORD_PROP));
                ksl
                        .setKeyStorePasswordCallbackHandler(this.trustStorePasswordCallbackHandler);
                ksl.setKeyStoreProviderClass(properties
                        .getProperty(TRUSTSTORE_PROVIDER_CLASS_PROP));
                ksl.setKeyStoreProviderArgFile(properties
                        .getProperty(TRUSTSTORE_PROVIDER_ARGFILE_PROP));
                ksl.setKeyStoreProviderArgText(properties
                        .getProperty(TRUSTSTORE_PROVIDER_ARGTEXT_PROP));
                this.trustStore = ksl.loadKeyStore();
            }
        } catch (KeyStoreException e) {
            throw new SSLContextFactoryException(e);
        } catch (NoSuchProviderException e) {
            throw new SSLContextFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SSLContextFactoryException(e);
        } catch (CertificateException e) {
            throw new SSLContextFactoryException(e);
        } catch (IOException e) {
            throw new SSLContextFactoryException(e);
        } catch (UnsupportedCallbackException e) {
            throw new SSLContextFactoryException(e);
        }
    }

    /**
     * Sets the key store.
     * 
     * @param keyStore
     *            the key store.
     */
    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * Sets the trust store.
     * 
     * @param trustStore
     *            the trust store.
     */
    public void setTrustStore(KeyStore trustStore) {
        this.trustStore = trustStore;
    }

    /**
     * Returns the key store.
     * 
     * @return the key store.
     */
    protected KeyStore getKeyStore() {
        return this.keyStore;
    }

    /**
     * Returns the trust store.
     * 
     * @return the trust store.
     */
    protected KeyStore getTrustStore() {
        return this.trustStore;
    }
    
    /**
     * Sets the key password
     * 
     * @param keyPassword
     */
    public void setKeyPassword(String keyPassword) {
        setKeyPassword(
                (keyPassword != null) ? keyPassword.toCharArray() : null);
    }

    /**
     * Sets the key password
     * 
     * @param keyPassword
     */
    public void setKeyPassword(char[] keyPassword) {
        if (keyPassword != null) {
            this.keyPassword = new char[keyPassword.length];
            System.arraycopy(keyPassword, 0, this.keyPassword, 0,
                    keyPassword.length);
        } else {
            if (this.keyPassword != null) {
                Arrays.fill(this.keyPassword, ' ');
            }
        }
    }

    /**
     * Sets the CallbackHandler that will be used to obtain the key password if
     * this password is still null. (Optional.)
     * 
     * @param keyPasswordCallbackHandler
     *            CallbackHandler that will be used to get the password.
     */
    public void setKeyPasswordCallbackHandler(
            CallbackHandler keyPasswordCallbackHandler) {
        this.keyPasswordCallbackHandler = keyPasswordCallbackHandler;
    }

    /**
     * Sets the CallbackHandler that will be used to obtain the key password if
     * this password is still null. (Optional.)
     * 
     * @param keyStorePasswordCallbackHandler
     *            CallbackHandler that will be used to get the password.
     */
    public void setKeyStorePasswordCallbackHandler(
            CallbackHandler keyStorePasswordCallbackHandler) {
        this.keyStorePasswordCallbackHandler = keyStorePasswordCallbackHandler;
    }

    /**
     * Sets the CallbackHandler that will be used to obtain the key password if
     * this password is still null. (Optional.)
     * 
     * @param trustStorePasswordCallbackHandler
     *            CallbackHandler that will be used to get the password.
     */
    public void setTrustStorePasswordCallbackHandler(
            CallbackHandler trustStorePasswordCallbackHandler) {
        this.trustStorePasswordCallbackHandler = trustStorePasswordCallbackHandler;
    }

    /**
     * Builds KeyManagers from the key store provided in the constructor, using
     * a SunX509 KeyManagerFactory.
     * 
     * @return Key managers corresponding to the key store.
     */
    protected KeyManager[] getRawKeyManagers()
            throws SSLContextFactoryException {
        if (this.keyStore != null) {
            try {
                KeyManagerFactory kmf = KeyManagerFactory
                        .getInstance("SunX509");
                if ((this.keyPassword != null)
                        || (this.keyPasswordCallbackHandler == null)) {
                    kmf.init(this.keyStore, this.keyPassword);
                } else {
                    PasswordCallback passwordCallback = new PasswordCallback(
                            "Key password? ", false);
                    this.keyPasswordCallbackHandler
                            .handle(new Callback[] { passwordCallback });
                    char[] password = passwordCallback.getPassword();
                    kmf.init(this.keyStore, password);
                    if (password != null) {
                        Arrays.fill(password, ' ');
                    }
                }
                return kmf.getKeyManagers();
            } catch (NoSuchAlgorithmException e) {
                throw new SSLContextFactoryException(e);
            } catch (KeyStoreException e) {
                throw new SSLContextFactoryException(e);
            } catch (UnrecoverableKeyException e) {
                throw new SSLContextFactoryException(e);
            } catch (IOException e) {
                throw new SSLContextFactoryException(e);
            } catch (UnsupportedCallbackException e) {
                throw new SSLContextFactoryException(e);
            }
        } else {
            return null;
        }
    }

    /**
     * Sets the key manager wrapper.
     * 
     * @param keyManagerWrapper
     */
    public void setKeyManagerWrapper(X509KeyManagerWrapper keyManagerWrapper) {
        this.keyManagerWrapper = keyManagerWrapper;
    }

    /**
     * Gets the trust managers. If a trust manager wrapper has been set, the
     * "raw" trust managers will be wrapped.
     * 
     * @return trust managers.
     */
    @Override
    public KeyManager[] getKeyManagers() throws SSLContextFactoryException {
        KeyManager[] keyManagers = getRawKeyManagers();
        X509KeyManagerWrapper wrapper = this.keyManagerWrapper;
        if ((wrapper != null) && (keyManagers != null)) {
            try {
                for (int i = 0; i < keyManagers.length; i++) {
                    if (keyManagers[i] instanceof X509KeyManager)
                        keyManagers[i] = wrapper
                                .wrapKeyManager((X509KeyManager) keyManagers[i]);
                }
            } catch (SecurityException e) {
                LOGGER
                        .log(
                                Level.WARNING,
                                "Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
                                e);
            } catch (IllegalArgumentException e) {
                LOGGER
                        .log(
                                Level.WARNING,
                                "Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
                                e);
            }
        }
        return keyManagers;
    }

    /**
     * Builds TrustManagers from the trust store provided in the constructor,
     * using a SunX509 TrustManagerFactory.
     * 
     * @return SunX509-based trust managers corresponding to the trust store.
     */
    protected TrustManager[] getRawTrustManagers()
            throws SSLContextFactoryException {
        if (this.trustStore != null) {
            try {
                TrustManagerFactory tmf = TrustManagerFactory
                        .getInstance("SunX509");
                tmf.init(this.trustStore);
                return tmf.getTrustManagers();
            } catch (NoSuchAlgorithmException e) {
                throw new SSLContextFactoryException(e);
            } catch (KeyStoreException e) {
                throw new SSLContextFactoryException(e);
            }
        } else {
            return null;
        }
    }

    /**
     * Sets the trust manager wrapper.
     * 
     * @param trustManagerWrapper
     */
    public void setTrustManagerWrapper(
            X509TrustManagerWrapper trustManagerWrapper) {
        this.trustManagerWrapper = trustManagerWrapper;
    }

    /**
     * Gets the trust managers. If a trust manager wrapper has been set, the
     * "raw" trust managers will be wrapped.
     * 
     * @return trust managers.
     */
    @Override
    public TrustManager[] getTrustManagers() throws SSLContextFactoryException {
        TrustManager[] trustManagers = getRawTrustManagers();
        X509TrustManagerWrapper wrapper = this.trustManagerWrapper;
        if ((wrapper != null) && (trustManagers != null)) {
            try {
                for (int i = 0; i < trustManagers.length; i++) {
                    if (trustManagers[i] instanceof X509TrustManager)
                        trustManagers[i] = wrapper
                                .wrapTrustManager((X509TrustManager) trustManagers[i]);
                }
            } catch (SecurityException e) {
                LOGGER
                        .log(
                                Level.WARNING,
                                "Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
                                e);
            } catch (IllegalArgumentException e) {
                LOGGER
                        .log(
                                Level.WARNING,
                                "Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
                                e);
            }
        }
        return trustManagers;
    }
}
