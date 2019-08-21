ROUND5 IMPLEMENTATIONS
======================

Below you find the instructions to run three implementations of Round5, `Reference`, `Optimized`, and `Configurable` as described in the Round5 specification. These implementations can run all Round5 parameter sets.

The contents are as follows:

* Prerequisites
* Building the implementations
* Running the example application


Prerequisites
-------------

To be able to build and run the implementations of the algorithm, the
following conditions must be met:

* The OpenSSL library (preferably 1.1.1, or later) must be installed.
  Use `sudo apt-get install libssl-dev` for most Linux distributions.
  On a Mac, an easy way is to use [brew](https://brew.sh), install it with
  `brew install openssl@1.1` and then add it to the `CPATH` and
  `LIBRARY_PATH` environment variables:
  ```
  export CPATH=${CPATH+$CPATH:}/usr/local/opt/openssl@1.1/include
  export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}/usr/local/opt/openssl@1.1/lib
  ```

* The Keccak library must be installed on your system.
  This is done as follows:

  1. Linux: Install xsltproc (e.g.  `sudo apt-get install xsltproc`, on
     a Mac it should already be installed with XCode).

  2. Clone the [XKCP git repository](https://github.com/XKCP/XKCP.git).

  3. Build the library, e.g. using `make generic64/libkeccak.a` (for
     alternatives, see the github page).

  4. Add the library to your `CPATH` and `LIBRARY_PATH` environment variables:
  ```
  export CPATH=${CPATH+$CPATH:}<XKCP_DIRECTORY>/bin/generic64
  export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}<XKCP_DIRECTORY>/bin/generic64
  ```

  Note: if you already have installed the keccak library, make sure it is a
  version where [issue #51](https://github.com/XKCP/XKCP/issues/51) has been
  fixed. If this issue has not been fixed, the reference implementations will
  not produce the same results as the other implementations.

* To generate the developer documentation, you will need to have Doxygen as
  well as Graphviz installed. Use `sudo apt-get install doxygen; sudo apt-get
  install graphviz` for most Linux distributions. On a Mac, use e.g.
  [brew](https://brew.sh) to install both packages (`brew install doxygen; brew
  install graphviz`).


Building the implementations
----------------------------

After installing the prerequisites, you can build the implementations
using `make`.

### Make targets ###

The following make targets are available:

* `build`: Builds the available implementations. This is the default target.

* `all`: Builds the available implementations including the developer
  documentation.

* `reference`: Build just the “reference” implementation.

* `configurable`: Build just the “configurable” implementation.

* `optimized`: Build just the “optimized” implementation.

* `doc`: Generates the developer documentation for the implementations.
  One can also individually specify a subcategory to create the
  documentation for.

  - `doc-reference`: generates the documentation only for the reference
    implementation.

  - `doc-configurable`: generates the documentation only for the configurable
    implementation.

* `clean`: Removes all build artifacts. One can also individually specify a
  subcategory to clean.

  - `clean-reference`: cleans only the reference implementation build
    artifacts.

  - `clean-configurable`: cleans only the configurable implementation build
    artifacts.

  - `clean-optimized`: cleans only the optimized implementation build artifacts.


### Make variables ###

The following make variables can be used to influence the build of the implementations.

* `ALG`: With this variable, the algorithm implemented by the NIST api is
  specified. For instance, to use `R5ND_1PKE_5d` write:
  ```
  make ALG=R5ND_1PKE_5d
  ``` 

  The default is `R5ND_1KEM_0d`. Otherwise, it can be one of: `R5ND_1KEM_0d`,
  `R5ND_3KEM_0d`, `R5ND_5KEM_0d`, `R5ND_1PKE_0d`, `R5ND_3PKE_0d`,
  `R5ND_5PKE_0d`, `R5ND_1KEM_5d`, `R5ND_3KEM_5d`, `R5ND_5KEM_5d`,
  `R5ND_1PKE_5d`, `R5ND_3PKE_5d`, `R5ND_5PKE_5d`, `R5N1_1KEM_0d`,
  `R5N1_3KEM_0d`, `R5N1_5KEM_0d`, `R5N1_1PKE_0d`, `R5N1_3PKE_0d`,
  `R5N1_5PKE_0d`, `R5ND_0KEM_2iot`, `R5ND_0PKE_4iot`, `R5ND_1KEM_4longkey`,
  `R5N1_3PKE_0smallCT`.

* Instead of specifying `ALG`, it is possible to select `ALG_TYPE`, `NIST_LEVEL`,
  `KEM_PKE`, and `XEF`. For instance:
  ```
  make ALG=ND NIST_LEVEL=1 KEM_PKE=PKE XEF=1
  ```

  - `ALG_TYPE`: Specifies the algorithm type (`ND` means ring-based, `N1` means
    non-ring based) implemented by the NIST api. The default is `ND`.

  - `NIST_LEVEL`: Specifies the NIST security level. It can be 1, 3, or 5. The
    default is 1.

  - `KEM_PKE`: Specifies the type of algorithm. It can be `KEM` or `PKE`. The
    default is `KEM`.

  - `XEF`: When defined, specifies that the error correction variants of the
    parameter sets should be used (e.g. `R5ND_1KEM_5d` will be used instead of
    `R5ND_1KEM_0d`).

* The following four variables, namely `TAU`, `TAU2_LEN`, `AES`, and
  `NO_OPENSSL_SHAKE`, control the way matrix A is computed. For instance:
  ```
  make TAU=1 AES=1
  ```

  - `TAU`: Specifies the value of the `TAU` parameter (0, 1, or 2), i.e. the
    method for the generation of A.

  - `TAU2_LEN`: Specifies the length of the random vector when A is generated
    with `TAU` equals 2 (defaults to the value of algorithm parameter `q`).

    Note: this must be a power of two and larger than algorithm parameter `d`.

  - `AES`: When set to anything other than the empty string or 0, this
    specifies that the deterministic random values should be generated using
    AES in CTR mode on “zero” input blocks (with the key equal to the seed)
    instead of using the default method (i.e. Shake).  The AES method can be
    faster, especially on platforms with a well optimized OpenSSL AES
    implementation.

  - `NO_OPENSSL_SHAKE`: When OpenSSL 1.1.1 (or later) is installed, the default
    is to make use of OpenSSL's Shake implementation. Set this variable to
    anything other than the empty string to disable the use of OpenSSL's Shake.

* Timing and cache attack countermeasures can be enabled by means of
  `CM_CACHE` (only applicable to the optimized implementations).
  For instance:
  ```
  make CM_CACHE=1
  ```

* To indicate that the 64-bit shift left operator with a variable amount can be
  considered constant-time on your platform, set `SHIFT_LEFT64_CONSTANT_TIME`
  to anything other than the empty string (only applicable to the optimized
  implementation with cache attack counter measures (`CM_CACHE`) enabled). For
  instance:
  ```
  make CM_CACHE=1 SHIFT_LEFT64_CONSTANT_TIME=1
  ```

* To allow the use of AVX2 optimisations, set `AVX2` to anything other than the
  empty string (only applicable to the optimized implementation, requires an AVX2
  compatible CPU/compiler).
  For instance:
  ```
  make AVX2=1
  ```

   Please note that this option also enables the cache attack countermeasures
   (see `CM_CACHE`).

* To compile the code for generating NIST KATs, set `NIST_KAT_GENERATION` to
  anything other than the empty string. For instance:
  ```
  make NIST_KAT_GENERATION=1
  ```

  This replaces the “true” random bytes generator with the NIST (deterministic)
  random bytes generator and enables the output of intermediate results.

* Finally, the following flag is used for debugging purposes: `DEBUG`.
  When set to anything other than the empty string, this variable enables the
  _debug_ build of the implementation. The _debug_ build generates additional
  debugging output when run. For instance:
  ```
  make DEBUG=1
  ```


Running the example application
-------------------------------

The example application is called `example` (found in the `build` directory of
the implementation).

In the optimized implementation, you can run it for the parameters chosen while
making it as:
```
./example
```

In the reference and configurable implementations, the application can be executed
for any configuration at runtime and takes the following arguments:

* `-a <PARAMETER-SET-NAME>` to specify the name of the parameter set to
  use. Here <PARAMETER-SET-NAME> is the name of the parameter set to use
  (i.e. one of `R5ND_1KEM_0d`, `R5ND_3KEM_0d`, `R5ND_5KEM_0d`, `R5ND_1PKE_0d`,
  `R5ND_3PKE_0d`, `R5ND_5PKE_0d`, `R5ND_1KEM_5d`, `R5ND_3KEM_5d`,
  `R5ND_5KEM_5d`, `R5ND_1PKE_5d`, `R5ND_3PKE_5d`, `R5ND_5PKE_5d`,
  `R5N1_1KEM_0d`, `R5N1_3KEM_0d`, `R5N1_5KEM_0d`, `R5N1_1PKE_0d`,
  `R5N1_3PKE_0d`, `R5N1_5PKE_0d`, `R5ND_0KEM_2iot`, `R5ND_0PKE_4iot`,
  `R5ND_1KEM_4longkey`, `R5N1_3PKE_0smallCT`).

* `-t N` to specify the tau variant, where N is a number between 0 and 2, as
  described in the specification (ignored for parameter sets that make use of
  the ring construction).

For instance, in reference you can run:
```
./example -a R5ND_1KEM_4longkey
```

