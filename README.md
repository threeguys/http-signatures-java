# http-signatures-java

### Pure java implementation of HTTP Signatures

#### NOTE: Not for production use (yet...)

As with any security related software, bugs are devastating and can have a much larger business
impact that other types of bugs. I plan on trying to make this library as rock solid and 
production ready as possible, however the implementation is currently very immature and
still in very active development.

Once I have a minimal feature set and have been able to create several different example
implementations to validate the use cases, I plan on seeking reviews from the folks writing
the spec. Until then, please feel free to point out bugs, this has been a hackathon type
effort thus far so there's a pretty good chance of some ugly dark corners.

### What is this? 

An implementation of HTTP Signing according to https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00

I have a need to use request-based authentication in another project I'm working on. While I was doing research and
looking for ways to possibly implement it, I found this active RFC draft going back a few years and it looks reasonably
sane, thus viola...

### Dependencies

The project is current using maven as a build environment and has only three test dependencies (junit4 and bouncycastle)
and is compatible with Java 8. I plan on adding filters for Spring Boot and Netty, as well as nginx and Envoy
implementations (obviously not in java). The main <a href="http-signatures">http-signatures</a> library will be
maintained as dependency-free as possible, currently there are zero runtime dependencies. The only real reason to
include more dependencies here would be broader algorithm support beyond what's provided in the JVM. 

## Examples: http-signature-examples

#### Spring Boot
There's an example echo server that will validate signed requests under
<a href="http-signature-examples/echo-spring-boot-server">echo-spring-boot-server</a> and a client that will
register itself and make varying types of request, according to command line parameters under
<a href="http-signature-examples/echo-spring-boot-client">echo-spring-boot-client</a>.

#### Netty
Example server: <a href="http-signature-examples/echo-netty-server">echo-netty-server</a>
Example client: <a href="http-signature-examples/echo-netty-client">echo-netty-client</a> 

# Roadmap
My tentative plans are as follow:
* Fully test and document <a href="http-signatures">http-signatures</a>
* Write up on how to use this to make your service secure
* Add DynamoDb KeyProvider implementation for server-side public key management

# License

Released under Apache 2.0 License. Please see <a href="LICENSE">LICENSE</a> for more details.

# Contributing

Please see <a href="CONTRIBUTING.md">CONTRIBUTING.md</a> for more information about contributing.
