This is not intended to be a massive library. I develop it depending on the use-cases I encounter. Please get in touch if you have comments or suggestions.

# Original motivation #

The original objectives for this library was to provide a consistent way of setting SSL-related parameters in [Restlet](http://www.restlet.org/) and [Jetty](http://www.mortbay.org/jetty/).

## Restlet ##

I am the SSL extension committer for Restlet. The SSL related documentation can be found in the [Restlet Wiki](http://wiki.restlet.org/).

## Jetty ##

The use in conjunction with Jetty was addressed in [JETTY-554](http://jira.codehaus.org/browse/JETTY-554), fixed in Jetty 7.0.0pre4. I also posted some examples on [the Jetty-dev list](http://permalink.gmane.org/gmane.comp.java.jetty.general/11386). (Please use `buildSSLContext` instead of `newInitializedSSLContext`.)

# Changes #

## Version 0.5 ##

  * Now using [org.jsslutils](http://www.jsslutils.org/) package name and Maven group ID.
  * Added sample SSLImplementation for Apache Tomcat 6.
  * Fixed issue with trust parameters when no trust store was specified explicitly.

## Version 0.4 ##

  * Changed methods for adding CRLs in PKIXSSLContextFactory into `addCrl`.
  * Added a `FixedServerAliasKeyManager` class, see [(restlet-discuss) SSL + Virtual Hosts and Issue #489?](http://restlet.tigris.org/servlets/ReadMsg?list=discuss&msgNo=5712).
  * Added an example [SecureProtocolSocketFactory](http://hc.apache.org/httpclient-3.x/apidocs/org/apache/commons/httpclient/protocol/SecureProtocolSocketFactory.html) for using SSLContext with [Apache HTTP Client](http://hc.apache.org/httpclient-3.x/).

## Version 0.3 ##

  * Marked `newInitializedSSLContext` as deprecated in jSSLutils 0.3+, it is replaced with `buildSSLContext`. (Sorry about the inconvenience, but there were only 3 or 4 downloads at the time of the change.)
  * Added a `KeyStoreLoader` utility class, the aim of which is to load a keystore, perhaps from default system properties and allow for `KeyStore`s that are not file-based for example.
  * Added KeyManager wrappers similarly to the TrustManager wrappers to support features such as [X509ExtendedKeyManager.chooseEngineClientAlias](http://java.sun.com/javase/6/docs/api/javax/net/ssl/X509ExtendedKeyManager.html).

## Version 0.2.1 ##

  * Packaging for [Maven](http://maven.apache.org/).
  * Separated the demo certificates into their own Maven bundle.

## Version 0.2 ##
  * Added TrustManager wrappers.
  * Removed TrustAllClientsSSLContextFactory: this feature has now been replaced with a TrustManager wrapper.
  * Added a GSI TrustManager wrapper.

## Version 0.1 ##
  * SSLContextFactory.
  * X509SSLContextFactory.
  * PKIXSSLContextFactory.
  * TrustAllClientsSSLContextFactory.
  * Test cases.