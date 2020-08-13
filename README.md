[![Build Status](https://travis-ci.org/dtikhonov/lsquic-tutorial.svg?branch=master)](https://travis-ci.org/dtikhonov/lsquic-tutorial)

# lsquic-tutorial
lsquic tutorial teaches one how to build an application using [lsquic](https://github.com/litespeedtech/lsquic).

## Description
The tutorial program, tut.c, contains client and server logic for a simple echo program.
The client connects to the server and sends lines of text; the server reverses the lines of text and sends them back.

The tutorial program was written as an educational aid.  Various aspects of the ways LSQUIC
is used in it are considered in [Netdev 0x14 slides](https://github.com/dtikhonov/talks/blob/master/netdev-0x14/lsquic-slides.md).
In addition to the slides, please refer to the [LSQUIC API Reference](https://lsquic.readthedocs.io/en/latest/apiref.html).

tut.c contains several versions of reading and writing from stream to illustrate different ways of
using the library.  There are also two ways to send packets.

## Building
To build the tutorial:
```bash
git submodule update --init --recursive
cmake .
make
```

This clones and builds BoringSSL, so it may take a few minutes.

## Usage

### All options
```bash
sh$ ./tut -h
Usage: tut [-c cert -k key] [options] IP port

   -c cert.file    Certificate.
   -k key.file     Key file.
   -f log.file     Log message to this log file.  If not specified, the
                     are printed to stderr.
   -L level        Set library-wide log level.  Defaults to 'warn'.
   -l module=level Set log level of specific module.  Several of these
                     can be specified via multiple -l flags or by combining
                     these with comma, e.g. -l event=debug,conn=info.
   -v              Verbose: log program messages as well.
   -b VERSION      Use callbacks version VERSION.
   -p VERSION      Use packets_out version VERSION.
   -w VERSION      Use server write callback version VERSION.
   -o opt=val      Set lsquic engine setting to some value, overriding the
                     defaults.  For example,
                           -o version=ff00001c -o cc_algo=2
   -G DIR          Log TLS secrets to a file in directory DIR.
   -h              Print this help screen and exit.
```

### Running the server
Both client and server logic are contained in the `tut` program.  It knows it is meant to run in the server
mode when `-c` and `-k` options are specified:

```bash
sh$ ./tut -c mycert-cert.pem -k mycert-key.pem ::0 12345 -p 1 -L debug -f server.log
```

The server can select one of two versions of "on stream write" callbacks.  Use `-w` command-line option for that.

### Running the client
```bash
sh$ ./tut ::1 12345 -L debug -f client.log
Hello!
!olleH
^D
sh$
```

The server can select one of three versions of "on stream read" callbacks.  Use `-b` command-line option for that.

Both client and server can use the `-p` option to select one of two "send packets out" callbacks.

## HTTP/3 Client
As a bonus, a simple [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3) client is provided.  Example:

```bash
sh$ ./h3cli -M HEAD www.litespeedtech.com 443 /
HTTP/1.1 200 OK
x-powered-by: PHP/7.3.5
x-logged-in: False
x-content-powered-by: K2 v2.7.1 (by JoomlaWorks)
content-type: text/html; charset=utf-8
expires: Wed, 17 Aug 2005 00:00:00 GMT
last-modified: Wed, 12 Aug 2020 18:54:05 GMT
cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
pragma: no-cache
etag: "23485-1597258445;gz"
vary: Accept-Encoding
x-frame-options: SAMEORIGIN
x-lsadc-cache: hit
date: Thu, 13 Aug 2020 02:48:06 GMT
server: LiteSpeed
```

Besides www.litespeedtech.com, other websites to try are www.facebook.com and www.google.com.

## More Information
Latest QUIC and HTTP/3 GitHub artefacts can be found [here](https://github.com/quicwg/base-drafts).
The QUIC IETF Working Group materials are [here](https://datatracker.ietf.org/wg/quic/about/).

The [LSQUIC GitHub Repo](https://github.com/litespeedtech/lsquic) contains several more advanced examples, among
them HTTP/3 client and server programs.
