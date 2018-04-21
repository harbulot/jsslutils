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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * This class is a factory that provides methods for creating an SSLContext
 * configured with the settings set in this factory: using the PKIX algorithm
 * for both the key manager and the trust manager. These managers are created
 * from the KeyStores passed to the constructor. This implementation build a
 * trust store that supports revocation and CRLs, see the CRL-related methods.
 * 
 * The "org.jsslutils.prop.crlReloadInterval" system property may be used to
 * configure the reload interval for CRLs (when re-loaded automatically), in
 * seconds (0 won't reload them).
 * 
 * @author Bruno Harbulot
 * 
 */
public class PKIXSSLContextFactory extends X509SSLContextFactory {
    private final static Logger LOGGER = Logger.getLogger(PKIXSSLContextFactory.class.getCanonicalName());
    
    public final static String CRL_RELOAD_INTERVAL_PROP = "org.jsslutils.prop.crlReloadInterval";

    protected boolean enableRevocation;
    protected Set<CRL> crlCollection = new HashSet<CRL>();
    private CertificateFactory certificateFactory = null;
    private ScheduledThreadPoolExecutor crlReloaderScheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(
            2);

    public PKIXSSLContextFactory() {
        this(null, (char[]) null, null, true);
    }

    /**
     * Builds an SSLContextFactory using the PKIX algorithm in the
     * TrustManagerFactory.
     * 
     * @param keyStore
     *            KeyStore that contains the key.
     * @param keyPassword
     *            password to the key.
     * @param trustStore
     *            KeyStore that contains the trusted X.509 certificates.
     * @param enableRevocation
     *            sets whether certificate revocation should be enabled.
     */
    public PKIXSSLContextFactory(KeyStore keyStore, char[] keyPassword,
            KeyStore trustStore, boolean enableRevocation) {
        super(keyStore, keyPassword, trustStore);
        this.enableRevocation = enableRevocation;
    }

    /**
     * Builds an SSLContextFactory using the PKIX algorithm in the
     * TrustManagerFactory.
     * 
     * @param keyStore
     *            KeyStore that contains the key.
     * @param keyPassword
     *            password to the key.
     * @param trustStore
     *            KeyStore that contains the trusted X.509 certificates.
     * @param enableRevocation
     *            sets whether certificate revocation should be enabled.
     */
    public PKIXSSLContextFactory(KeyStore keyStore, String keyPassword,
            KeyStore trustStore, boolean enableRevocation) {
        super(keyStore, keyPassword, trustStore);
        this.enableRevocation = enableRevocation;
    }

    /**
     * Builds an SSLContextFactory using the PKIX algorithm in the
     * TrustManagerFactory. Certificate revocation is enabled by default.
     * 
     * @param keyStore
     *            KeyStore that contains the key.
     * @param keyPassword
     *            password to the key.
     * @param trustStore
     *            KeyStore that contains the trusted X.509 certificates.
     */
    public PKIXSSLContextFactory(KeyStore keyStore, char[] keyPassword,
            KeyStore trustStore) {
        this(keyStore, keyPassword, trustStore, true);
    }

    /**
     * Builds an SSLContextFactory using the PKIX algorithm in the
     * TrustManagerFactory. Certificate revocation is enabled by default.
     * 
     * @param keyStore
     *            KeyStore that contains the key.
     * @param keyPassword
     *            password to the key.
     * @param trustStore
     *            KeyStore that contains the trusted X.509 certificates.
     */
    public PKIXSSLContextFactory(KeyStore keyStore, String keyPassword,
            KeyStore trustStore) {
        this(keyStore, keyPassword, trustStore, true);
    }

    /**
     * Builds TrustManagers from the trust store provided in the constructor,
     * using a PKIX TrustManagerFactory. The TrustManagerFactory parameters used
     * are those provided by getTrustParams().
     * 
     * @return PKIX-based trust managers corresponding to the trust store.
     */
    @Override
    protected TrustManager[] getRawTrustManagers()
            throws SSLContextFactoryException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            ManagerFactoryParameters trustParams = getTrustParams();
            if (trustParams != null) {
                tmf.init(trustParams);
            } else {
                tmf.init((KeyStore) null);
            }
            return tmf.getTrustManagers();
        } catch (NoSuchAlgorithmException e) {
            throw new SSLContextFactoryException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SSLContextFactoryException(e);
        } catch (KeyStoreException e) {
            throw new SSLContextFactoryException(e);
        }
    }

    /**
     * Returns the ManagerFactoryParameters used for initialising the
     * TrustManagerFactory in getTrustManagers(). You can override it, but the
     * default behaviour is to build a CertPathTrustManagerParameters from the
     * PKIXParameters returned by getPKIXParameters().
     * 
     * @return ManagerFactoryParameters used by getTrustManagers().
     * @throws SSLContextFactoryException
     */
    protected ManagerFactoryParameters getTrustParams()
            throws SSLContextFactoryException {
        PKIXParameters pkixParams = getPKIXParameters();
        if (pkixParams != null) {
            ManagerFactoryParameters trustParams = new CertPathTrustManagerParameters(
                    pkixParams);
            return trustParams;
        } else {
            return null;
        }
    }

    /**
     * Returns the PKIXParameters used for initialising the
     * ManagerFactoryParameters in getTrustParams(). You can override it, but
     * the default behaviour is to build a PKIXBuilderParameters from the
     * trustStore, enable the revocation according to enableRevocation and adds
     * the CertStore provided by getCertStore().
     * 
     * @return PKIXParameters used by getTrustParams()
     * @throws SSLContextFactoryException
     */
    protected PKIXParameters getPKIXParameters()
            throws SSLContextFactoryException {
        KeyStore trustStore = getTrustStore();
        try {
            if (trustStore != null) {
                PKIXParameters pkixParams = new PKIXBuilderParameters(
                        getTrustStore(), null);
                CertStore certStore = getCertStore();
                if (certStore != null) {
                    pkixParams.setRevocationEnabled(this.enableRevocation);
                    pkixParams.addCertStore(getCertStore());
                } else {
                    pkixParams.setRevocationEnabled(Boolean.parseBoolean(System
                            .getProperty("com.sun.security.enableCRLDP",
                                    "false")));
                }
                return pkixParams;
            } else {
                return null;
            }
        } catch (KeyStoreException e) {
            throw new SSLContextFactoryException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SSLContextFactoryException(e);
        }
    }

    /**
     * Returns the CertStore added to the PKIXParameters in getPKIXParameters().
     * You can override it, but the default behaviour is to build a CertStore
     * using the Collection of X509CRL obtained from getCrlCollection(). Typical
     * extensions would probably consist of using an LDAP-based CertStore.
     * 
     * @return CertStore used by getPKIXParameters().
     * @throws SSLContextFactoryException
     */
    protected CertStore getCertStore() throws SSLContextFactoryException {
        try {
            Collection<? extends CRL> crlCollection = getCrlCollection();
            if ((crlCollection != null) && (crlCollection.size() > 0)) {
                CollectionCertStoreParameters collecCertStoreParams = new CollectionCertStoreParameters(
                        crlCollection);
                return CertStore.getInstance("Collection",
                        collecCertStoreParams);
            } else {
                return null;
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new SSLContextFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SSLContextFactoryException(e);
        }
    }

    /**
     * Returns the Collection of X509CRLs used to initialise the
     * CollectionCertStoreParameters used in getCertStore().
     * 
     * @return Collection of X509CRL ultimately checked by the trust manager.
     * @throws SSLContextFactoryException
     */
    public Collection<? extends CRL> getCrlCollection()
            throws SSLContextFactoryException {
        return Collections.unmodifiableCollection(this.crlCollection);
    }

    /**
     * Adds CRLs to the collection used by getCrlCollection() (and thus the
     * trust manager by default).
     * 
     * @param crlCollection
     *            collection of CRLs to add.
     * @throws SSLContextFactoryException
     */
    public void addCrlCollection(Collection<? extends CRL> crlCollection)
            throws SSLContextFactoryException {
        this.crlCollection.addAll(crlCollection);
    }

    /**
     * Adds a CRL to the collection used by getCrlCollection() (and thus the
     * trust manager by default).
     * 
     * @param crl
     *            CRL to add.
     * @throws SSLContextFactoryException
     */
    public void addCrl(CRL crl) throws SSLContextFactoryException {
        this.crlCollection.add(crl);
    }

    /**
     * Adds a CRL from an InputStream to the collection used by
     * getCrlCollection() (and thus the trust manager by default).
     * 
     * @param crlInputStream
     *            InputStream containing the CRL to read (this is not closed by
     *            this method).
     * @throws SSLContextFactoryException
     */
    public void addCrl(InputStream crlInputStream)
            throws SSLContextFactoryException {
        this.crlCollection.add(loadCrl(crlInputStream));
    }

    /**
     * Adds a CRL from a URL to the collection used by getCrlCollection() (and
     * thus the trust manager by default).
     * 
     * @param crlUrl
     *            URL of the CRL to fetch.
     * @throws SSLContextFactoryException
     * @throws IOException
     * @throws MalformedURLException
     */
    public void addCrl(String crlUrl) throws SSLContextFactoryException,
            MalformedURLException, IOException {
        long reloadInterval = 0;
        try {
            reloadInterval = Long.valueOf(System.getProperty(
                    CRL_RELOAD_INTERVAL_PROP, "0"));
        } catch (NumberFormatException e) {
        }
        addCrl(crlUrl, reloadInterval);
    }

    /**
     * Adds a CRL from a URL to the collection used by getCrlCollection() (and
     * thus the trust manager by default); this CRL will be reloaded
     * periodically.
     * 
     * @param crlUrl
     *            URL of the CRL to fetch.
     * @param reloadInterval
     *            number of seconds between reloads.
     * @throws SSLContextFactoryException
     * @throws MalformedURLException
     * @throws IOException
     */
    public void addCrl(final String crlUrl, long reloadInterval)
            throws SSLContextFactoryException, MalformedURLException,
            IOException {
        if (reloadInterval > 0) {
            final Callable<X509CRL> reloaderCallable = addReloadableCrl(crlUrl);
            Runnable reloader = new Runnable() {
                public void run() {
                    try {
                        reloaderCallable.call();
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Unable to reload CRL.", e);
                    }
                }
            };
            crlReloaderScheduledThreadPoolExecutor.scheduleAtFixedRate(reloader,
                    0L, reloadInterval, TimeUnit.SECONDS);
        } else {
            this.crlCollection.add(loadCrl(crlUrl));
        }
    }

    /**
     * Adds a CRL from a URL to the collection used by getCrlCollection() (and
     * thus the trust manager by default). This CRL will be reloaded by the
     * Callable returned; this callable is not scheduled in an executor at this
     * stage (up to the user of this method).
     * 
     * @param crlUrl
     *            URL of the CRL to fetch.
     * @return Callable<X509CRL> that reloads the CRL (call() will return the
     *         new CRL).
     * @throws SSLContextFactoryException
     * @throws MalformedURLException
     * @throws IOException
     */
    public Callable<X509CRL> addReloadableCrl(String crlUrl)
            throws SSLContextFactoryException, MalformedURLException,
            IOException {
        ReloadableX509CRL crl = new ReloadableX509CRL(crlUrl);
        Callable<X509CRL> reloader = crl.getReloaderCallable();
        try {
            reloader.call();
        } catch (Exception e) {
            throw new SSLContextFactoryException(e);
        }
        this.crlCollection.add(crl);
        return reloader;
    }

    /**
     * Builds a CRL object from an InputStream.
     * 
     * @param crlInputStream
     *            InputStream containing the CRL to read (this is not closed by
     *            this method).
     * @return X509CRL built from the representation obtained from this
     *         InputStream.
     * @throws SSLContextFactoryException
     */
    public synchronized CRL loadCrl(InputStream crlInputStream)
            throws SSLContextFactoryException {
        try {
            if (this.certificateFactory == null) {
                this.certificateFactory = CertificateFactory
                        .getInstance("X.509");
            }
            X509CRL crl = (X509CRL) this.certificateFactory
                    .generateCRL(crlInputStream);
            return crl;
        } catch (CertificateException e) {
            throw new SSLContextFactoryException(e);
        } catch (CRLException e) {
            throw new SSLContextFactoryException(e);
        }
    }

    /**
     * Builds a CRL object from a URL.
     * 
     * @param crlUrl
     *            URL of the CRL to fetch.
     * @return X509CRL built from the representation obtained from this URL.
     * @throws SSLContextFactoryException
     * @throws IOException
     * @throws MalformedURLException
     */
    public CRL loadCrl(String crlUrl) throws SSLContextFactoryException,
            IOException, MalformedURLException {
        InputStream is = null;
        try {
            URL url = new URL(crlUrl);
            is = url.openStream();
            return loadCrl(new BufferedInputStream(is));
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }
}
