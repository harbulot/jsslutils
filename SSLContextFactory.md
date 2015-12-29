# Introduction #

Many Java applications that use SSL rely on the configuration of [KeyStores](http://java.sun.com/j2se/1.5.0/docs/api/java/security/KeyStore.html). The default configuration is often based on VM properties such as `javax.net.ssl.keyStore`, `javax.net.ssl.keyStorePassword`, `javax.net.ssl.keyStoreProvider` and `javax.net.ssl.trustStore`.

However, this does not make it possible to configure conveniently more advanced uses such as Certificate Revocation Lists (CRLs) or custom [TrustManagers](http://java.sun.com/j2se/1.5.0/docs/api/javax/net/ssl/TrustManager.html).
In most cases, configuring these settings is done in order to create and initialise an [SSLContext](http://java.sun.com/j2se/1.5.0/docs/api/javax/net/ssl/SSLContext.html), which is subsequently used for creating instances  of `SSLSocketFactory` and `SSLSocket`.

The package `org.jsslutils.sslcontext` provides `SSLSocketFactory` and sub-classes that can be used to separate the configuration of the `SSLContext` from the classes using it.


For more details, please have a look at the [API documentation](http://jsslutils.googlecode.com/svn/trunk/javadoc/index.html).

# SSLContextFactories #

## SSLContextFactory ##

**`SSLContextFactory`** is default SSLContextFactory. It builds an SSLContext from default values, in particular, using `SSLContext.init(null,null,null)`, which calls the default relevant factories from highest priority provider.

Classes consuming an instance of SSLSocketFactory (subclasses included) should expect **`buildSSLContext(String contextProtocol)`** (~~`newInitializedSSLContext(..)`~~ prior to version 0.3) and **`buildSSLContext()`** to return an initialised `SSLContext` ready to be used from creating socket factories.

## X509SSLContextFactory ##

**`X509SSLContextFactory`** is a subclass of `SSLSocketFactory` that creates an SSLSocketFactory using the **SunX509** algorithm for both [KeyManagerFactory](http://java.sun.com/j2se/1.5.0/docs/api/javax/net/ssl/KeyManagerFactory.html) and [TrustManagerFactory](http://java.sun.com/j2se/1.5.0/docs/api/javax/net/ssl/TrustManagerFactory.html). It can be initialised with a `KeyStore` for the key store (holding the private credentials) and the trust store.

## PKIXSSLContextFactory ##

**`PKIXSSLContextFactory`** is a subclass of `X509SSLContextFactory` that uses a **PKIX**-based trust manager. It also comprises methods to set up CRLs.


# X509TrustManagerWrapper #

It is possible to wrap the `TrustManager`s created by an `SSLContextFactory` to add or relax certain rules using `SSLContextFactory.setTrustManagerWrapper(..)`.

## TrustAllClientsWrappingTrustManager ##
For example, the following will create an `X509SSLContextFactory` that uses X.509 trust managers. However, it will trust any client using the `TrustAllClientsWrappingTrustManager.Wrapper`.

```
X509SSLContextFactory sslContextFactory = 
	new X509SSLContextFactory(getServerCertKeyStore(), "testtest", getCaKeyStore());
sslContextFactory.setTrustManagerWrapper(new TrustAllClientsWrappingTrustManager.Wrapper());
SSLServerSocket socket = prepareServerSocket(sslContextFactory.buildSSLContext());
```

## GsiWrappingTrustManager ##

Similarly, the `GsiWrappingTrustManager` should accept grid proxy-certificates. The current implementation does not strictly follow RFC 3820, yet. The GSI wrapping trust manager looks for the first non-CA certificate that has signed subsequent certificates in the chain and checks that the Subject DN of those certificates has been built by adding further 'CN=' entries to that non-CA certificate.


# X509KeyManagerWrapper #

Similarly, it is possible to wrap the `KeyManager`s created by an `SSLContextFactory` to choose a particular alias for example, using `SSLContextFactory.setKeyManagerWrapper(..)`.

## FixedServerAliasKeyManager ##

This `KeyManager` will always choose the same alias for server sockets.

The following example shows how to configure an `X509SSLContextFactory` to produce an `SSLContext` that will always pick alias _host.example.org_ (which coincidentally, may correspond to a certificate for that host name).

```
X509SSLContextFactory sslContextFactory =
    new X509SSLContextFactory(keyStore, "keypassword", trustStore);
sslContextFactory.setKeyManagerWrapper(new FixedServerAliasKeyManager.Wrapper("host.example.org"));
```