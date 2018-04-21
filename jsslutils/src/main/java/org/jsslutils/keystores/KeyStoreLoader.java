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
package org.jsslutils.keystores;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * This class is a factory that provides methods for loading a KeyStore.
 * 
 * @author Bruno Harbulot
 * 
 */
public final class KeyStoreLoader {
    private volatile String keyStorePath;
    private volatile InputStream keyStoreInputStream;
    private volatile String keyStoreType;
    private volatile String keyStoreProvider;
    private volatile String keyStoreProviderClass;
    private volatile String keyStoreProviderArgFile;
    private volatile String keyStoreProviderArgText;
    private volatile char[] keyStorePassword;
    private volatile CallbackHandler keyStorePasswordCallbackHandler;

    /**
     * Sets the KeyStore path.
     * 
     * @param keyStorePath
     *            the KeyStore path
     */
    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    /**
     * Sets the KeyStore InputStream. If null, falls back to KeyStore path. This
     * InputStream will be closed by {@link KeyStoreLoader#loadKeyStore(char[])}
     * .
     * 
     * @param keyStoreInputStream
     *            the KeyStore InputStream
     */
    public void setKeyStoreInputStream(InputStream keyStoreInputStream) {
        this.keyStoreInputStream = keyStoreInputStream;
    }

    /**
     * Sets the KeyStore type.
     * 
     * @param keyStoreType
     *            the KeyStore type
     */
    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    /**
     * Sets the KeyStore provider.
     * 
     * @param keyStoreProvider
     *            the KeyStore provider
     */
    public void setKeyStoreProvider(String keyStoreProvider) {
        this.keyStoreProvider = keyStoreProvider;
    }

    /**
     * Sets the KeyStore provider class name.
     * 
     * @param keyStoreProviderClass
     *            the KeyStore provider class name
     */
    public void setKeyStoreProviderClass(String keyStoreProviderClass) {
        this.keyStoreProviderClass = keyStoreProviderClass;
    }

    /**
     * Sets the KeyStore provider argument file name.
     * 
     * @param keyStoreProviderArgFile
     *            the KeyStore provider argument file name
     */
    public void setKeyStoreProviderArgFile(String keyStoreProviderArgFile) {
        this.keyStoreProviderArgFile = keyStoreProviderArgFile;
    }

    /**
     * Sets the KeyStore provider argument text content (UTF-8).
     * 
     * @param keyStoreProviderArgText
     *            the KeyStore provider argument text content (UTF-8)
     */
    public void setKeyStoreProviderArgText(String keyStoreProviderArgText) {
        this.keyStoreProviderArgText = keyStoreProviderArgText;
    }

    /**
     * Set the KeyStore password.
     * 
     * @param keyStorePassword
     *            the KeyStore password
     */
    public void setKeyStorePassword(String keyStorePassword) {
        setKeyStorePassword((keyStorePassword != null) ? keyStorePassword
                .toCharArray() : null);
    }

    /**
     * Set the KeyStore password. This makes a copy of the char[] into an
     * internal char[], which will be cleared either when you use
     * {@link KeyStoreLoader#loadKeyStore()} or set it to null.
     * 
     * @param keyStorePassword
     *            the KeyStore password
     */
    public void setKeyStorePassword(char[] keyStorePassword) {
        if (keyStorePassword != null) {
            this.keyStorePassword = new char[keyStorePassword.length];
            System.arraycopy(keyStorePassword, 0, this.keyStorePassword, 0,
                    keyStorePassword.length);
        } else {
            if (this.keyStorePassword != null) {
                Arrays.fill(this.keyStorePassword, ' ');
            }
        }
    }

    /**
     * Sets the KeyStore password CallbackHander (used to get the password if no
     * password is provided).
     * 
     * @param keyStorePasswordCallbackHandler
     *            the KeyStore password CallbackHandler.
     */
    public void setKeyStorePasswordCallbackHandler(
            CallbackHandler keyStorePasswordCallbackHandler) {
        this.keyStorePasswordCallbackHandler = keyStorePasswordCallbackHandler;
    }

    /**
     * Loads a KeyStore according to the parameters initialised using the
     * setters.
     * 
     * @param password
     *            KeyStore password (will use password set with
     *            setKeyStorePassword if this argument is null).
     * @return KeyStore loaded from the value initialised with the setters.
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnsupportedCallbackException
     */
    public KeyStore loadKeyStore(char[] password) throws KeyStoreException,
            NoSuchProviderException, IOException, NoSuchAlgorithmException,
            CertificateException, UnsupportedCallbackException,
            SecurityException {
        KeyStore keyStore = null;
        if (this.keyStorePath != null) {
            if (this.keyStoreProviderClass != null) {
                Provider provider;
                try {
                    @SuppressWarnings("unchecked")
                    Class<Provider> providerClass = (Class<Provider>) Class
                            .forName(this.keyStoreProviderClass);

                    if (this.keyStoreProviderArgText != null) {
                        InputStream configInputStream = new ByteArrayInputStream(
                                this.keyStoreProviderArgText.getBytes("UTF-8"));

                        try {
                            Constructor<Provider> constructor = providerClass
                                    .getConstructor(InputStream.class);
                            try {
                                provider = constructor
                                        .newInstance(configInputStream);
                            } catch (IllegalArgumentException e) {
                                throw new NoSuchProviderException(
                                        "Unable to build the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (InstantiationException e) {
                                throw new NoSuchProviderException(
                                        "Unable to instantiate the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (IllegalAccessException e) {
                                throw new NoSuchProviderException(
                                        "Unable to access the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (InvocationTargetException e) {
                                throw new NoSuchProviderException(
                                        "Unable to invoke the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            }
                        } catch (NoSuchMethodException e) {
                            try {
                                Constructor<Provider> constructor = providerClass
                                        .getConstructor();
                                try {
                                    provider = constructor.newInstance();
                                    provider.load(configInputStream);
                                } catch (IllegalArgumentException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to build the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                } catch (InstantiationException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to instantiate the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                } catch (IllegalAccessException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to access the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                } catch (InvocationTargetException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to invoke the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                }
                            } catch (NoSuchMethodException e1) {
                                throw new NoSuchProviderException(
                                        "Provider class doesn't seem to have a suitable constructor: "
                                                + this.keyStoreProviderClass);
                            }
                        }
                    } else if (this.keyStoreProviderArgFile != null) {
                        try {
                            Constructor<Provider> constructor = providerClass
                                    .getConstructor(String.class);
                            try {
                                provider = constructor
                                        .newInstance(this.keyStoreProviderArgFile);
                            } catch (IllegalArgumentException e) {
                                throw new NoSuchProviderException(
                                        "Unable to build the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (InstantiationException e) {
                                throw new NoSuchProviderException(
                                        "Unable to instantiate the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (IllegalAccessException e) {
                                throw new NoSuchProviderException(
                                        "Unable to access the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (InvocationTargetException e) {
                                throw new NoSuchProviderException(
                                        "Unable to invoke the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            }
                        } catch (NoSuchMethodException e) {
                            try {
                                Constructor<Provider> constructor = providerClass
                                        .getConstructor();
                                try {
                                    provider = constructor.newInstance();
                                    InputStream configInputStream = null;
                                    try {
                                        configInputStream = new FileInputStream(
                                                this.keyStoreProviderArgFile);
                                        provider.load(configInputStream);
                                    } finally {
                                        if (configInputStream != null) {
                                            configInputStream.close();
                                        }
                                    }
                                } catch (IllegalArgumentException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to build the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                } catch (InstantiationException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to instantiate the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                } catch (IllegalAccessException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to access the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                } catch (InvocationTargetException e1) {
                                    throw new NoSuchProviderException(
                                            "Unable to invoke the provider with a text argument: "
                                                    + this.keyStoreProviderClass);
                                }
                            } catch (NoSuchMethodException e1) {
                                throw new NoSuchProviderException(
                                        "Provider class doesn't seem to have a suitable constructor: "
                                                + this.keyStoreProviderClass);
                            }
                        }
                    } else {
                        try {
                            Constructor<Provider> constructor = providerClass
                                    .getConstructor();
                            try {
                                provider = constructor.newInstance();
                            } catch (IllegalArgumentException e1) {
                                throw new NoSuchProviderException(
                                        "Unable to build the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (InstantiationException e1) {
                                throw new NoSuchProviderException(
                                        "Unable to instantiate the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (IllegalAccessException e1) {
                                throw new NoSuchProviderException(
                                        "Unable to access the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            } catch (InvocationTargetException e1) {
                                throw new NoSuchProviderException(
                                        "Unable to invoke the provider with a text argument: "
                                                + this.keyStoreProviderClass);
                            }
                        } catch (NoSuchMethodException e1) {
                            throw new NoSuchProviderException(
                                    "Provider class doesn't seem to have a suitable constructor: "
                                            + this.keyStoreProviderClass);
                        }
                    }
                } catch (ClassNotFoundException e) {
                    throw new NoSuchProviderException(
                            "KeyStoreLoader unable to load class: "
                                    + this.keyStoreProviderClass);
                } catch (ClassCastException e) {
                    throw new NoSuchProviderException(
                            "KeyStoreLoader unable to load provider class: "
                                    + this.keyStoreProviderClass);
                }

                Security.addProvider(provider);

                keyStore = KeyStore.getInstance(
                        this.keyStoreType != null ? this.keyStoreType
                                : KeyStore.getDefaultType(), provider);
            } else if (this.keyStoreProvider != null) {
                keyStore = KeyStore.getInstance(
                        this.keyStoreType != null ? this.keyStoreType
                                : KeyStore.getDefaultType(),
                        this.keyStoreProvider);
            } else {
                keyStore = KeyStore
                        .getInstance(this.keyStoreType != null ? this.keyStoreType
                                : KeyStore.getDefaultType());
            }
            InputStream keyStoreInputStream = this.keyStoreInputStream;
            try {
                if (keyStoreInputStream == null) {
                    keyStoreInputStream = new FileInputStream(
                            this.keyStorePath);
                }
                if (password == null) {
                    password = this.keyStorePassword;
                }
                CallbackHandler pwCallbackHandler = this.keyStorePasswordCallbackHandler;
                if ((password == null) && (pwCallbackHandler != null)) {
                    PasswordCallback passwordCallback = new PasswordCallback(
                            "KeyStore password? ", false);
                    pwCallbackHandler
                            .handle(new Callback[] { passwordCallback });
                    password = passwordCallback.getPassword();
                }
                keyStore.load(keyStoreInputStream, password);
            } finally {
                if (keyStoreInputStream != null) {
                    keyStoreInputStream.close();
                }
            }
        }
        return keyStore;
    }

    /**
     * Loads a KeyStore according to the parameters initialised using the
     * setters. The stored password will be cleared after calling this method.
     * 
     * @return KeyStore loaded from the value initialised with the setters.
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnsupportedCallbackException
     */
    public KeyStore loadKeyStore() throws KeyStoreException,
            NoSuchProviderException, IOException, NoSuchAlgorithmException,
            CertificateException, UnsupportedCallbackException {
        try {
            return loadKeyStore(this.keyStorePassword);
        } finally {
            if (this.keyStorePassword != null) {
                Arrays.fill(this.keyStorePassword, ' ');
            }
        }
    }

    /**
     * Builds a new KeyStoreLoader initialised with the values passed in the
     * javax.net.ssl.keyStore, javax.net.ssl.keyStoreType,
     * javax.net.ssl.keyStoreProvider and javax.net.ssl.keyStorePassword system
     * properties, for using the KeyStore as a key store (as opposed to a trust
     * store).
     * 
     * @return KeyStore initialised with the default keystore system properties.
     */
    public static KeyStoreLoader getKeyStoreDefaultLoader() {
        KeyStoreLoader ksLoader = new KeyStoreLoader();
        ksLoader.setKeyStorePath(System.getProperty("javax.net.ssl.keyStore"));
        ksLoader.setKeyStoreType(System
                .getProperty("javax.net.ssl.keyStoreType"));
        ksLoader.setKeyStoreProvider(System
                .getProperty("javax.net.ssl.keyStoreProvider"));
        ksLoader.setKeyStorePassword(System
                .getProperty("javax.net.ssl.keyStorePassword"));
        return ksLoader;
    }

    /**
     * Builds a new KeyStoreLoader initialised with the values passed in the
     * javax.net.ssl.trustStore, javax.net.ssl.trustStoreType,
     * javax.net.ssl.trustStoreProvider and javax.net.ssl.trustStorePassword
     * system properties, for using the KeyStore as a trust store.
     * 
     * @return KeyStore initialised with the default keystore system properties.
     */
    public static KeyStoreLoader getTrustStoreDefaultLoader() {
        KeyStoreLoader ksLoader = new KeyStoreLoader();
        ksLoader
                .setKeyStorePath(System.getProperty("javax.net.ssl.trustStore"));
        ksLoader.setKeyStoreType(System
                .getProperty("javax.net.ssl.trustStoreType"));
        ksLoader.setKeyStoreProvider(System
                .getProperty("javax.net.ssl.trustStoreProvider"));
        ksLoader.setKeyStorePassword(System
                .getProperty("javax.net.ssl.trustStorePassword"));
        return ksLoader;
    }

    /**
     * KeyStoreLoaders are likely to contain sensitive information; cloning is
     * therefore not allowed.
     */
    protected final KeyStoreLoader clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }
}
