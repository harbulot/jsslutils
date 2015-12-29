# jSSLutils #

This project aims to provide a set of utilities regarding the use of SSL in Java.

This mainly consists of a set of [SSLContextFactory](SSLContextFactory.md) classes and a demo CA for testing purposes in the subversion tree.

The original motivation for this library was to provide a consistent way of setting SSL-related parameters in [Restlet](http://www.restlet.org/) and [Jetty](http://www.mortbay.org/jetty/), in particular for providing more advanced features such as support for Certificate Revocation Lists (CRLs). Please have a look at the [Roadmap](Roadmap.md) for details.


**I'll try to keep the API as stable as possible, but depending on feedback and suggestion, some features could change. If you are using or planning to use this project, please get in touch.**

Suggestions and comments are welcome, either through the issue-tracking system or via the [discussion group](http://groups.google.com/group/jsslutils-discuss).


### Licence ###

Although the main project is licensed under the New BSD Licence, some sub-modules in the _extra_ directory may be under a different licence (APL, LGPL).

### Project owner ###
Bruno Harbulot, [The University of Manchester](http://www.rcs.manchester.ac.uk/).