## WebAuthn - authenticating users to services using public key cryptography

WebAuthn is a web standard published by the W3C. Its goal is to
standardize an interfacefor authenticating users to web-based
applications and services using public key cryptography. Modern web
browsers support WebAuthn functionality.

WebAuthn provides two funcitons: register and authenticate. Usually the
public and private keypair is stored on an external token (Yuikey etc.)
or part of the platform (TPM). After the public key is registered, it can
be used to authenticate to the same service.

This module does not preserve a database of registered public keys, their
credential ID, usernames and pending challenges - instead this data must
be stored by a client of this API in a database or other persistent
storage.

[WebAuthn specification at W3C](https://w3c.github.io/webauthn/)

A basic demonstration server is provided (`bin/webauthn_demo`),
running at [webauthn-demo.robur.coop](https://webauthn-demo.robur.coop).

## Documentation

[API documentation](https://roburio.github.io/webauthn/doc) is available online.

## Installation

`opam install webauthn` will install this library.
