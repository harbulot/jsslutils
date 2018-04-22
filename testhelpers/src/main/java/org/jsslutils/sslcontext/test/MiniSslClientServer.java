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

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * This class contains both a client and a server that can be used to build
 * small tests, to test the SSLContextFactory.
 * 
 * These examples come with a demo CA (a few certificates and keys). These are
 * not to be used in real-life application. DO NOT add them to your set of
 * trusted certificates in your web-browser or similar application.
 * 
 * @author Bruno Harbulot.
 * 
 */
public abstract class MiniSslClientServer {

    public final static String CERTIFICATES_DIRECTORY = "org/jsslutils/certificates/";
    public final static String KEYSTORE_PASSWORD = "testtest";

    protected volatile boolean stopServer = false;
    protected boolean verboseExceptions = false;
    protected volatile int serverTimeout = 4000;
    protected int testPort = 31050;
    private int serverRequestNumber = 1;

    protected final LinkedBlockingQueue<Future<Object>> serverRequestsFutures = new LinkedBlockingQueue<Future<Object>>();
    protected volatile Exception listeningServerException;

    protected String getCertificatesDirectory() {
        return CERTIFICATES_DIRECTORY + "local/";
    }

    /**
     * Returns the store of CA certificates, to be used as a trust store. The
     * default value is to load 'dummy.jks', part of this test suite.
     * 
     * @return KeyStore containing the certificates to trust.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     */
    public KeyStore getCaKeyStore() throws IOException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream ksis = ClassLoader
                .getSystemResourceAsStream(getCertificatesDirectory()
                        + "cacert.jks");
        ks.load(ksis, KEYSTORE_PASSWORD.toCharArray());
        ksis.close();
        return ks;
    }

    /**
     * Returns the keystore containing the key and the certificate to be used by
     * the server.
     * 
     * @return KeyStore containing the server credentials.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     */
    public KeyStore getServerCertKeyStore() throws IOException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream ksis = ClassLoader
                .getSystemResourceAsStream(getCertificatesDirectory()
                        + "localhost.p12");
        ks.load(ksis, KEYSTORE_PASSWORD.toCharArray());
        ksis.close();
        return ks;
    }

    /**
     * Returns the keystore containing a test key and certificate that is to be
     * trusted by the server. This is the "good" keystore in that its
     * certificate has not been revoked by the demo CA. This should work
     * whether-or-not CRLs are used.
     * 
     * @return KeyStore containing the "good" client credentials.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     */
    public KeyStore getGoodClientCertKeyStore() throws IOException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream ksis = ClassLoader
                .getSystemResourceAsStream(getCertificatesDirectory()
                        + "testclient.p12");
        ks.load(ksis, KEYSTORE_PASSWORD.toCharArray());
        ksis.close();
        return ks;
    }

    /**
     * Returns the keystore containing a test key and certificate that is not to
     * be trusted by the server when CRLs are enabled. This is the "bad"
     * keystore in that its certificate has been revoked by the demo CA. This
     * should pass work when CRLs checks are disabled, but fail when they are
     * used.
     * 
     * @return KeyStore containing the "bad" client credentials.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     */
    public KeyStore getBadClientCertKeyStore() throws IOException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream ksis = ClassLoader
                .getSystemResourceAsStream(getCertificatesDirectory()
                        + "testclient_r.p12");
        ks.load(ksis, KEYSTORE_PASSWORD.toCharArray());
        ksis.close();
        return ks;
    }

    /**
     * Returns a collection of CRLs to be used by the tests. This is loaded from
     * 'newca.crl'.
     * 
     * @return CRLs
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws CRLException
     */
    public Collection<X509CRL> getLocalCRLs() throws IOException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException,
            CRLException {
        InputStream inStream = ClassLoader
                .getSystemResourceAsStream(getCertificatesDirectory()
                        + "testca-crl.pem");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) cf.generateCRL(inStream);
        inStream.close();
        ArrayList<X509CRL> crls = new ArrayList<X509CRL>();
        crls.add(crl);
        return crls;
    }

    /**
     * Sets the number of requests the mini server is supposed to accept. This
     * defaults to 1, with a 4-second timeout.
     * 
     * @param serverRequestNumber
     */
    protected void setServerRequestNumber(int serverRequestNumber) {
        this.serverRequestNumber = serverRequestNumber;
    }

    /**
     * Creates and binds the SSLServerSocket to a port after trying a few port
     * numbers.
     * 
     * @param sslServerContext
     *            SSLContext from which to build the socket and its
     *            SSLSocketFactory.
     * @return Bound SSLServerSocket.
     */
    protected SSLServerSocket prepareServerSocket(SSLContext sslServerContext) {
        SSLServerSocketFactory sslServerSocketFactory = sslServerContext
                .getServerSocketFactory();

        SSLServerSocket serverSocket = null;
        int attempts = 10;
        while (attempts > 0) {
            try {
                serverSocket = (SSLServerSocket) sslServerSocketFactory
                        .createServerSocket(++testPort);
                serverSocket.setWantClientAuth(true);
                System.out.println("Server listening at: https://localhost:"
                        + testPort + "/");
                break;
            } catch (IOException e) {
                System.err.println("Could not listen on port: " + testPort);
            }
            serverSocket = null;
            attempts--;
        }
        return serverSocket;
    }

    /**
     * Starts the mini server.
     * 
     * @param serverSocket
     *            bound SSLServerSocket for this server.
     */
    protected Thread runServer(final SSLServerSocket serverSocket) {
        Thread serverThread = new Thread(new Runnable() {

            public void run() {
                ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(
                        2, 10, 60, TimeUnit.SECONDS,
                        new LinkedBlockingQueue<Runnable>());
                try {
                    int max = MiniSslClientServer.this.serverRequestNumber;
                    for (int i = max; (i > 0 || max == 0) && (!stopServer); i--) {
                        Socket acceptedSocket = null;
                        try {
                            serverSocket.setSoTimeout(serverTimeout);
                            acceptedSocket = serverSocket.accept();
                            Future<Object> f = threadPoolExecutor
                                    .submit(new RequestHandler(acceptedSocket));
                            serverRequestsFutures.put(f);
                        } catch (IOException e) {
                            MiniSslClientServer.this.listeningServerException = e;
                        } catch (InterruptedException e) {
                            MiniSslClientServer.this.listeningServerException = e;
                        }
                    }
                } catch (RuntimeException e) {
                    MiniSslClientServer.this.listeningServerException = e;
                }
            }
        });
        serverThread.start();
        return serverThread;
    }

    /**
     * This runs the main test: it runs a client and a server.
     * 
     * @param sslClientContext
     *            SSLContext to be used by the client.
     * @param sslServerContext
     *            SSLContext to be used by the server.
     * @return true if the server accepted the SSL certificate.
     * @throws SSLContextFactoryException
     * @throws IOException
     */
    public boolean runTest(SSLContext sslClientContext,
            SSLContext sslServerContext) throws IOException,
            InterruptedException {
        this.listeningServerException = null;
        boolean result = false;

        final SSLServerSocket serverSocket = prepareServerSocket(sslServerContext);

        assertNotNull("Server socket not null", serverSocket);
        assertTrue("Server socket is bound", serverSocket.isBound());

        Thread serverThread = runServer(serverSocket);

        Exception clientException = null;

        try {
            clientException = makeClientRequest(sslClientContext);
        } finally {
            synchronized (serverSocket) {
                if (!serverSocket.isClosed())
                    serverSocket.close();
            }
        }
        synchronized (serverSocket) {
            assertTrue(serverSocket.isClosed());
        }

        try {
            serverThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Throwable serverRequestException = null;
        Future<?> serverRequestFuture = serverRequestsFutures.poll();
        try {
            serverRequestFuture.get();
        } catch (ExecutionException e) {
            serverRequestException = e.getCause();
        }

        System.out.println();
        System.out.println("Server request exception: "
                + serverRequestException);
        System.out.println("Client exception: " + clientException);
        System.out.println("Listening server exception: "
                + this.listeningServerException);

        result = true;
        if (serverRequestException != null) {
            assertTrue(serverRequestException instanceof SSLException);
            SSLException sslException = (SSLException) serverRequestException;
            Throwable cause = printSslException("! Server: ", sslException,
                    null);
            result = (cause == null)
                    || !(cause instanceof CertPathValidatorException);
            if (result == true) {
                throw new RuntimeException(sslException);
            }
        }
        System.out.println("SSL connection succeeeded? " + result);
        System.out.println();

        return result;
    }

    /**
     * @param sslClientContext
     * @throws IOException
     */
    protected Exception makeClientRequest(SSLContext sslClientContext)
            throws IOException {
        SSLSocketFactory sslClientSocketFactory = sslClientContext
                .getSocketFactory();

        PrintWriter cout = null;
        BufferedReader cin = null;
        SSLSocket sslClientSocket = null;
        try {
            sslClientSocket = (SSLSocket) sslClientSocketFactory.createSocket(
                    "localhost", testPort);
            assertTrue("Client socket connected", sslClientSocket.isConnected());

            sslClientSocket.setSoTimeout(500);
            cin = new BufferedReader(new InputStreamReader(sslClientSocket
                    .getInputStream()));
            String inputLine = null;

            cout = new PrintWriter(sslClientSocket.getOutputStream(), true);
            cout.println("GET / HTTP/1.1");
            cout.println("Host: localhost");
            cout.println();
            while ((inputLine = cin.readLine()) != null) {
                System.out.println("Server says: " + inputLine);
            }
            return null;
        } catch (SSLException e) {
            printSslException("! Client: ", e, sslClientSocket);
            return e;
        } catch (IOException e) {
            e.printStackTrace();
            fail();
            return e;
        } finally {
            if (cin != null) {
                cin.close();
            }
            if (cout != null) {
                cout.close();
            }
        }
    }

    /**
     * Small class that handles a server request.
     */
    protected static class RequestHandler implements Callable<Object> {
        private final Socket acceptedSocket;

        public RequestHandler(Socket acceptedSocket) {
            this.acceptedSocket = acceptedSocket;
        }

        public Object call() throws Exception {
            System.out.println("Accepted connection.");
            try {
                PrintWriter out = new PrintWriter(acceptedSocket
                        .getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(
                        acceptedSocket.getInputStream()));
                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    System.out.println("Client says: " + inputLine);
                    if (inputLine.length() == 0)
                        break;
                }

                String theOutput = "HTTP/1.0 200 OK\r\n";
                theOutput += "Content-type: text/plain\r\n";
                theOutput += "\r\n";
                theOutput += "Hello World\r\n";
                if (this.acceptedSocket instanceof SSLSocket) {
                    SSLSocket sslSocket = (SSLSocket) this.acceptedSocket;
                    SSLSession sslSession = sslSocket.getSession();
                    if (sslSession != null) {
                        System.out.println("Cipher suite: "
                                + sslSession.getCipherSuite());
                        theOutput += "Cipher suite: "
                                + sslSession.getCipherSuite() + "\r\n";
                        theOutput += "Client certificates: \r\n";

                        X509Certificate[] certs = null;
                        try {
                            certs = (X509Certificate[]) sslSession
                                    .getPeerCertificates();
                        } catch (SSLPeerUnverifiedException e) {
                        }
                        if (certs != null) {
                            for (X509Certificate cert : certs) {
                                theOutput += " - "
                                        + cert.getSubjectX500Principal()
                                                .getName() + "\r\n";
                            }
                        }
                    }
                }
                out.print(theOutput);

                out.close();
                in.close();
            } finally {
                acceptedSocket.close();
            }
            return null;
        }
    }

    /**
     * Used for printing out more info when there's a problem.
     * 
     * @param prefix
     * @param sslException
     * @param socket
     * @return possible exception or throwable.
     */
    protected Throwable printSslException(String prefix,
            SSLException sslException, SSLSocket socket) {
        Throwable cause = sslException;
        while ((cause = cause.getCause()) != null) {
            if (cause instanceof CertPathValidatorException) {
                CertPathValidatorException certException = (CertPathValidatorException) cause;
                CertPath certPath = certException.getCertPath();
                List<? extends Certificate> certificates = certPath
                        .getCertificates();
                int index = certException.getIndex();
                if (index >= 0) {
                    Certificate pbCertificate = certificates.get(index);
                    if (pbCertificate instanceof X509Certificate) {
                        System.out.println(prefix
                                + "Problem caused by cert: "
                                + ((X509Certificate) pbCertificate)
                                        .getSubjectX500Principal().getName());
                    } else {
                        System.out.println(prefix + "Problem caused by cert: "
                                + pbCertificate);
                    }
                } else {
                    System.out.println(prefix + "Unknown index: " + cause);
                }
                break;
            } else {
                System.out.println(prefix + cause);
                if (socket != null) {
                    printSslSocketInfo(socket);
                }
            }
        }
        return cause;
    }

    /**
     * Used for printing out more info when there's a problem.
     * 
     * @param socket
     */
    protected void printSslSocketInfo(SSLSocket socket) {
        System.out.println("Socket: " + socket);
        SSLSession session = socket.getSession();
        if (session != null) {
            System.out.println("Session: " + session);
            System.out.println("  Local certificates: "
                    + (session.getLocalCertificates() != null ? Arrays
                            .asList(session.getLocalCertificates()) : null));
            System.out.println("  Local principal: "
                    + session.getLocalPrincipal());
            SSLSessionContext context = session.getSessionContext();
            if (context != null) {
                System.out.println("Session context: " + context);
            }
        }
    }

}
