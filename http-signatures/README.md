# http-signatures

### Pure java HTTP Signatures with zero runtime dependencies

#### Disclaimer: Not for production use (yet...)
This is still in active development and not completely tested or reviewed. Please feel free to make 
pull requests or crititques and suggestions. At some point, I will release version 1.0 once it has
been sufficiently tested and reviewed.

## Verifying Signatures

Thanks to <a href="https://medium.com/@bn121rajesh/rsa-sign-and-verify-using-openssl-behind-the-scene-bf3cac0aade2">
this medium article</a> on verifying signatures using OpenSSL. Currently the only way to get this data is
to set a breakpoint in HttpSignerImpl to get the plaintext.


### Verifying a key

NOTE: All output here is related to the keys
<a href="https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#name-example-keys">published in
the RFC</a> so there is nothing being exposed. Please beware if you're using anything in here, it's already
been well published before it made it into this repo.  

```
openssl rsa -in private.pem -text -noout
```

## Open Questions

### Verification of examples in the RFC
I am still unable to verify the examples posted in the RFC using OpenSSL, waiting to figure this one out.
Right now, the library is self verifying.

### Trailing newlines in the input
The spec is not entirely clear on if there is a final newline. It makes my code easier if there is so for now,
I'm assuming a newline is appropriate and the library uses it.