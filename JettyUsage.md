# Jetty SSL Configuration #

The `setSslContext` method was added to the [Jetty](http://www.mortbay.org/) SSL connectors (see [JETTY-554](http://jira.codehaus.org/browse/JETTY-554)) in version 7.0.0pre4, so it is possible to use jSSLutils with Jetty. This can be used for configuring Certificate Revocation Lists (CRLs).

The following configuration is for Jetty 7.0.1. For these examples to work, `jsslutils-1.0.5.jar` needs to be on Jetty's classpath. One way to do this is to put `jsslutils-1.0.5.jar` in `$JETTY_HOME/lib/ext` and use the `ext` option:


```
java -jar start.jar OPTIONS=ext,default etc/jetty.xml etc/jetty-ssl.xml
```

Note that you may need further options in the `OPTIONS` list depending on what you wish to run. Please refer to the [Jetty documentation for this](http://wiki.eclipse.org/Jetty/Feature/Start.jar); some sensible values can be found in the `start.ini` file that can be found in the Jetty bundle (main directory).

Further details about this configuration syntax can be found on the [Jetty Wiki](http://docs.codehaus.org/display/JETTY/Syntax+Reference).

## Example jetty-sslcontext.xml, using jsslutils.keystores.KeyStoreLoader ##

```
<Configure id="Server" class="org.eclipse.jetty.server.Server">
  <!-- Use the KeyStoreLoader to load the key store into "keystore" -->
  <New class="org.jsslutils.keystores.KeyStoreLoader">
    <Set name="keyStoreType">PKCS12</Set>
    <Set name="keyStorePath">/path/to/your/pkcs12keystore.p12</Set>
    <Set name="keyStorePassword">THE_KEYSTORE_PASSWORD</Set>
    <Call id="keystore" name="loadKeyStore"><Arg /></Call>
  </New>
  
  <!-- Use the KeyStoreLoader to load the trust store into "truststore" -->
  <New class="org.jsslutils.keystores.KeyStoreLoader">
    <Set name="keyStoreType">JKS</Set>
    <Set name="keyStorePath">/path/to/your/jksTruststore.jks</Set>
    <Set name="keyStorePassword">THE_TRUSTSTORE_PASSWORD</Set>
    <Call id="truststore" name="loadKeyStore"><Arg /></Call>
  </New>

  <!-- Creates a PKIX-based SSLContext into "context" -->
  <New class="org.jsslutils.sslcontext.PKIXSSLContextFactory">
    <Arg><Ref id="keystore" /></Arg>
    <Arg>THE_KEY_PASSWORD</Arg>
    <Arg><Ref id="truststore" /></Arg>
    <!-- Adds remote CRLs -->
    <Call name="addCrl">
       <Arg>http://ca.grid-support.ac.uk/pub/crl/root-crl.crl</Arg>
    </Call>
    <Call name="addCrl">
       <Arg>http://ca.grid-support.ac.uk/pub/crl/ca-crl.crl</Arg>
    </Call>
    <Call id="context" name="buildSSLContext">
      <Arg>TLS</Arg>
    </Call>
  </New>

  <!-- Adds a connector that uses this SSLContext -->
  <Call name="addConnector">
    <Arg>
      <New class="org.eclipse.jetty.server.ssl.SslSelectChannelConnector">
	<Set name="Port">8443</Set>
	<Set name="maxIdleTime">30000</Set>
        <Set name="Acceptors">2</Set>
        <Set name="AcceptQueueSize">100</Set>
        <Set name="sslContext">
          <Ref id="context" />
        </Set>
        <Set name="wantClientAuth">true</Set>
      </New>
    </Arg>
  </Call>
</Configure>
```


## Example jetty-sslcontext.xml, using KeyStore and FileInputStream ##

```
<Configure id="Server" class="org.eclipse.jetty.server.Server">
  <New class="java.lang.String"><Arg>THE_TRUSTSTORE_PASSWORD</Arg><Call id="tspassword" name="toCharArray" /></New>
  <!-- For PKCS#12 KeyStores, the key password and the keystore password are the same. -->
  <New class="java.lang.String"><Arg>THE_KEY_AND_KEYSTORE_PASSWORD</Arg><Call id="kspassword" name="toCharArray" /></New>

  <New class="org.jsslutils.sslcontext.PKIXSSLContextFactory">
    <Arg>
      <Call class="java.security.KeyStore" name="getInstance">
        <Arg>PKCS12</Arg>
        <Call name="load">
          <Arg><New class="java.io.FileInputStream"><Arg>/path/to/your/pkcs12keystore.p12</Arg></New></Arg>
          <Arg><Ref id="kspassword" /></Arg>
        </Call>
      </Call>
    </Arg>
    <Arg><Ref id="kspassword" /></Arg>
    <Arg>
      <Call class="java.security.KeyStore" name="getInstance">
        <Arg>JKS</Arg>
        <Call name="load">
          <Arg><New class="java.io.FileInputStream"><Arg>/path/to/your/jksTruststore.jks</Arg></New></Arg>
          <Arg><Ref id="tspassword" /></Arg>
        </Call>
      </Call>
    </Arg>
    <Call name="addCrl">
       <Arg>http://ca.grid-support.ac.uk/pub/crl/root-crl.crl</Arg>
    </Call>
    <Call name="addCrl">
       <Arg>http://ca.grid-support.ac.uk/pub/crl/ca-crl.crl</Arg>
    </Call>
    <Call id="context" name="buildSSLContext">
      <Arg>TLS</Arg>
    </Call>
  </New>

  <Call name="addConnector">
    <Arg>
      <New class="org.eclipse.jetty.server.ssl.SslSelectChannelConnector">
	<Set name="Port">8443</Set>
	<Set name="maxIdleTime">30000</Set>
        <Set name="Acceptors">2</Set>
        <Set name="AcceptQueueSize">100</Set>
        <Set name="sslContext">
          <Ref id="context" />
        </Set>
        <Set name="wantClientAuth">true</Set>
      </New>
    </Arg>
  </Call>
</Configure>
```