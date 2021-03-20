// Package oonet is an experimental net/measurement implementation.
//
// The code in here attempts to evolve the previous next concepts
// to merge the good parts of both implementations.
//
// The first implementation (./legacy/netx) relied too much on
// context for changing the behavior. This made is quite complex
// to understand, because there were too many unknowns when
// reading code using it.
//
// The second implementation (./netx) used the decorator pattern
// extensively. This led to understandable code, but constructing
// measurement clients was quite burdensome. Also, it was not
// living up to the two initial promises of next:
//
// 1. that you write the code you would normally write for
// performing requests and netx does all the measurement magic;
//
// 2. that it's possible to collect measurements even when
// we are communicating directly with, say, OONI server.
//
// This third implementation aims to strike a balance between
// the previous ones. We use the context only to pass around the
// state related to measurements. Otherwise, we have a bunch of
// functionality that works also with default clients. For
// example, if you use HTTPXDefaultClient, you can use http3
// by specifying the `h3` or `http3` scheme.
//
// This should enable us to emit log messages for all events
// and to collect some shallow measurements when communicating
// with OONI servers. It would also allow us to change the
// underlying protocol that we use (e.g. QUIC instead of using
// the standard library's HTTP). It would also allow us to
// construct very custom clients for measurements.
//
// Among its major improvements, this implementation features
// full support for easily using QUIC and for parroting. By
// using the utls library, we're able to speak HTTP2 with the
// TLS ClientHello of Chrome 83. This won't always work but
// it might be useful to measurements and for evasion.
//
// Another major improvements is better code to read in
// advance a sizeable snapshot of the body and for dealing
// in a clean way with very large bodies. Now, if the
// body is truncated, you know that with an error.
//
// Of course, being this experimental code, many unknowns
// still exist. Also, we certainly need to write (or better
// adapt) unit testing from other packages. The code in
// here is mostly a refactoring of existing code with some
// enhancements failitated by more experience with Go.
//
// There are currently no plans of merging this into the
// master branch. This code might just disappear if we
// find out that it's not improving the statu quo.
package oonet
