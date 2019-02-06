# Gopaque [![GoDoc](https://godoc.org/github.com/cretz/gopaque/gopaque?status.svg)](https://godoc.org/github.com/cretz/gopaque/gopaque)

Gopaque implements the OPAQUE protocol in Go. OPAQUE is a way to register users with a server without having to send the
user's password to the server during registration or authentication. An introduction to OPAQUE (and PAKEs in general)
can be found at this article:
[Let's talk about PAKE](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/). Gopaque uses the
[Kyber](https://github.com/dedis/kyber) library to implement
[this pending RFC](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-01) using elliptic curves.

To install:

    go get -u github.com/cretz/gopaque/gopaque

The documentation, API, and examples are in the [Godoc](https://godoc.org/github.com/cretz/gopaque/gopaque).

**WARNING: This is a trivial implementation, the author is not a cryptographer, and the code has not been reviewed. Use
at your own risk.**

Other known OPAQUE implementations:

* https://github.com/frekui/opaque (Go)
* https://github.com/stef/libsphinx (C)