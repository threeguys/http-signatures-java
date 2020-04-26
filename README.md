# http-signatures-java

##### Pure java library implementing HTTP Signatures

An implementation of HTTP Signing according to https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00

I have a need to use request-based authentication in another project I'm working on. While I was doing research and
looking for ways to possibly implement it, I found this active RFC draft going back a few years and it looks reasonably
sane, thus viola...

### Dependencies

The project is current using maven as a build environment and has only one test dependency (junit4) and is compatible
with Java 8. I plan on adding filters for Spring Boot and Netty, as well as nginx and Envoy implementations (obviously
not in java). The main <a href="http-signatures">http-signatures</a> library will be maintained as dependency-free
as possible, currently there are zero runtime dependencies. The only real reason to include more dependencies here
would be broader algorithm support beyond what's provided in the JVM. 

# License

Released under Apache 2.0 License. Please see <a href="LICENSE">LICENSE</a> for more details.

# Contributing

Please see <a href="CONTRIBUTING.md">CONTRIBUTING.md</a> for more information about contributing.


