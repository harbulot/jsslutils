# Introduction #

By default, [Apache Tomcat](http://tomcat.apache.org/tomcat-6.0-doc/ssl-howto.html) uses JSSE and builds an SSLContext with default trust-managers based on the keystore and truststore attributes in the `<Connector />` configuration.

There is a way to customise this, via the `SSLImplementation` attribute. This option is no longer mentioned in the [documentation after Tomcat 3.3](http://tomcat.apache.org/tomcat-3.3-doc/tomcat-ssl-howto.html), but it has been consistently updated and it still works with Tomcat 6.

# Sample SSLImplementation based on jSSLutils #

This mechanism is quite flexible and allows you to specify additional options in the connector.

The [jsslutils-extra-apachetomcat6 Maven module](http://code.google.com/p/jsslutils/source/browse/trunk/extra/apachetomcat6/), available in the code repository of jSSLutils is an example that shows how to use it to achieve two goals:
  * accept any certificate (for example, if you wish to accept self-signed certificates -- to be used carefully),
  * accept GSI proxy certificates.
You could do add other options if you wanted to customise the jSSLutils wrappers, or more generally the SSLContext, in a different way.

To use it, place the [jar file compiled from this code](http://jsslutils.googlecode.com/files/jsslutils-extra-apachetomcat6-0.5.2.jar) and the main jSSLutils jar file in the `lib` directory of Tomcat.

## Configuration to accept any certificate ##

This will accept **any** certificate for which the client has the private key. It doesn't even check the time validity. Effectively, the truststore settings are useless here.
The point of this is to let the webapp do the verification.
In the same way as you would configure the SSL connector in the server configuration file, add the `SSLImplementation` and `acceptAnyCert` as follows:

```
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
               maxThreads="150" scheme="https" secure="true"
               keystoreFile="..." keystoreType="..." keystorePass="..."
               truststoreType="..." truststoreFile="..." truststorePass="..." SSLImplementation="org.jsslutils.extra.apachetomcat6.JSSLutilsImplementation"
acceptAnyCert="true" clientAuth="want" sslProtocol="TLS" />
```

## Configuration to accept GSI proxy certificates ##

Similarly, use the `SSLImplementation` and `acceptProxyCerts` option, as follows:
```
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
               maxThreads="150" scheme="https" secure="true"
               keystoreFile="..." keystoreType="..." keystorePass="..."
               truststoreType="..." truststoreFile="..." truststorePass="..." SSLImplementation="org.jsslutils.extra.apachetomcat6.JSSLutilsImplementation"
acceptAnyCert="false" acceptProxyCerts="true" clientAuth="want" sslProtocol="TLS" />
```

# Licence #

This module is released under the Apache License 2, since it is based on the `JSSESocketFactory` and `JSSEImplementation` in Apache Tomcat's [org.apache.tomcat.util.net.jsse](http://tomcat.apache.org/tomcat-6.0-doc/api/org/apache/tomcat/util/net/jsse/package-frame.html) package which is distributed under this licence.