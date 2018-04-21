# jSSLutils

This project aims to provide a set of utilities regarding the use of SSL in Java.

This mainly consists of a set of `SSLContextFactory` classes and a demo CA for testing purposes in the subversion tree.

The original motivation for this library was to provide a consistent way of setting SSL-related parameters in Restlet and Jetty, in particular for providing more advanced features such as support for Certificate Revocation Lists (CRLs).

## Licence

Although the main project is licensed under the New BSD Licence, some sub-modules in the extra directory may be under a different licence (APL, LGPL).

## Release Notes

Version 1.0.7 was released in 2010. This project has not been actively maintained since. However, version 1.0.8 is a release made in 2018 aimed to address a few issues.

One of the main changes is an upgrade of the BouncyCastle libraries. It is used in two places: tests for the main `jsslutils` module (which does not affect the main code of that module), and the GSI proxy certificate verification module.

Here are a few notes about the status of the modules in version 1.0.8:

* `jsslutils`: This is the core library, and this mostly consists of convenience classes related to using `SSLContext` in Java. There have been a few changes in the Java world in that respect since 2010 (in particular, support for Server Name Indication), but those classes can still be relevant today.
* `jsslutils-extra-gsi`: The current usage of [GSI](https://en.wikipedia.org/wiki/Grid_Security_Infrastructure) is unknown, but this module may still be relevant to people working in this field. One of the main changes from version 1.0.7 and 1.0.8 is an upgrade of the BouncyCastle libraries. Its API has changed since 2010, so a reasonable effort to adapt the code to the new API was made. This has been tested against the unit tests already in place, but this has not been tested against GSI services in the field. **Users should check whether they wish or need to update, and review the code for their own needs.**
* `jsslutils-extra-apachehttpclient3`: Apache HTTP Client 3.x has been deprecated for a long time. Newer versions can use an `SSLContext`. It's probably worth upgrading to a newer version of Apache HTTP Client/Components if you can, instead of relying on this.
* `jsslutils-extra-apachetomcat5`: This was removed in version 1.0.8.
* `jsslutils-extra-apachetomcat6`: Apache Tomcat 6 is also an old version. This code has been left as an example, but it's probably a good idea to upgrade to a newer version of Apache Tomcat, and possibly adapt this accordingly.


Some unit/integration tests in version 1.0.7 were relying on services that have now disappeared. Testing the behaviour of jSSLutils with the default JVM truststore is now disabled by default (no services have been hard-coded in the test). If you want to run those tests, you can define two URLs as system properties when running the tests. For example: `-Djsslutils.test.known_ca_url=https://something-with-a-good-cert.example/` and `-Djsslutils.test.unknown_ca_url=https://something-with-a-bad-cert.example/`.

In principle, this project is still compatible with Java 5, but it was only tested with Java 8.
