Keygen FAST Bitcoin Generator
===============

Forked from Fast Vanity Bitcoin address generator for Linux using the
[secp256k1_fast_unsafe](https://github.com/llamasoft/secp256k1_fast_unsafe) library.

Modified by 'magnuspub' From the original work of `gandalf@winds.org`

Example
-------
Example program execution:
(Note: Do _not_ send coins to this address!)

    $ keygen >> btc.list
    $ cat btc.list
     Address: 1Vanity8HEFQDR7ZFsAUFeRR67AG38PcR Privkey: L3jTmJvNtjNrUw5SJJGFfGTog46fLutsQJ4XG66YWHMV5UmgFWqZ
     ...
    $ cat pattern.list
     1Vanity8HEFQDR7ZFsAUFeRR67AG38PcR
     ...
    $ cat ./btc.list |awk '/Address/ {print $2}' |awk 'NR==FNR{arr[$0];next} $0 in arr' '/pattern.list' -

Build Prerequisites
-------------------
Successful compilation depends on installing these additional programs:

* GCC
* Make
* Libtool
* Autotools
* GMP

Installing prerequisites on RedHat or Fedora Core:

    $ yum -y install gcc make automake autoconf libtool gmp-devel

Installing prerequisites on Ubuntu:

    $ sudo apt-get install build-essential automake autoconf libtool libgmp3-dev

Build Instructions
------------------
Simply run make:

    $ make

This will automatically configure the secp256k1 library and compile the
project using default options. To change compile options in secp256k1, cd to
secp256k1 and run configure with your new options, and then rerun make in the
top level directory.

If the gmp development library is not installed on your system, you may remove
-lgmp from the LDLIBS line in the Makefile. See below for other prerequisites.

For slow CPUs, you might get a better hash rate by lowering the "#define STEP"
value in keygen.c. Similarly, server CPUs with large amounts of fast memory
might benefit by increasing the STEP value.

Warning
-------
**Please verify all generated addresses before use!**

This software is beta and may contain bugs. Do not send coins to an address
without first checking that the generated private/public keys are correct.

License
-------
This software is distributed under the GPLv2 license. Most individual portions
are placed under compatible MIT or BSD licenses. See each respective file for
details.

