ROUND5 REFERENCE IMPLEMENTATION
===============================

CONTENTS
--------

* Prerequisites
* Building the implementations
* Running the example applications


Prerequisites
-------------

To be able to build and run the implementations of the algorithm, the
following conditions must be met:

* The OpenSSL library (preferably 1.1.1, or later) must be installed.
  Use `apt-get install libssl-dev` for most Linux distributions.
  On a Mac, an easy way is to use [brew](https://brew.sh), install it with
  `brew install openssl@1.1` and then add it to the `CPATH` and
  `LIBRARY_PATH` environment variables:

  ```
  export CPATH=${CPATH+$CPATH:}/usr/local/opt/openssl@1.1/include
  export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}/usr/local/opt/openssl@1.1/openssl/lib
  ```

* The Keccak library must be installed in your system.
  This is done as follows:

  1. Linux: Install xsltproc (e.g.  `sudo apt-get install xsltproc`, on
     a Mac it should already be installed).

  2. Clone the [XKCP git repository](https://github.com/XKCP/XKCP.git).

  3. Build the library, e.g. using `make generic64/libkeccak.a` (for alternatives, see the github page).

  4. Add the library to your `CPATH` and `LIBRARY_PATH` environment variables:

    ```
    export CPATH=${CPATH+$CPATH:}<XKCP_DIRECTORY>/bin/generic64
    export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}<XKCP_DIRECTORY>/bin/generic64
    ```

Building the implementations
----------------------------

After installing the prerequisites, you can build the implementations
using `make`.

### Make targets ###

The following make targets are available:

* `build`:

  Builds the available implementations. This is the default target.

* `all`:

  Builds the available implementations including the developer documentation.

* `reference`:

  Build just the “reference” implementation.

* `doc`:

  Generates the developer documentation for the implementations.
  One can also individually specify a subcategory to create the
  documentation for.

  - `doc-reference`: generates the documentation only for the reference implementation.

* `clean`:

  Removes all build artifacts. One can also individually specify a
  subcategory to clean.

  - `clean-reference`:  cleans only the reference implementation artifacts.

### Make variables ###

The following make variables can be used to influence the build of the implementations.

* `ALG`:

  With this variable, the algorithm implemented by the NIST api is
  specified. Can be one of `R5ND_1KEM_0c`, `R5ND_1PKE_0c`, `R5ND_3KEM_0c`,
  `R5ND_3PKE_0c`, `R5ND_5KEM_0c`, `R5ND_5PKE_0c`, `R5ND_1KEM_5c`,
  `R5ND_1PKE_5c`, etc. The default is `R5ND_1KEM_0c`.

* `ALG_TYPE`:

  Alternative to specifying `ALG`. Specifies the algorithm type (`ND` or `N1`)
  implemented by the NIST api. The default is `ND`.

* `NIST_LEVEL`:

  Alternative to specifying `ALG`. Specifies the NIST level implemented by
  the NIST api. Can be 1, 3, or 5. The default is 1.

* `KEM_PKE`:

  Alternative to specifying `ALG`. Specifies the type of algorithm
  implemented by the NIST api. Can be `KEM` or `PKE`. The default
  is `KEM`.

* `XEF`:

  Alternative to specifying `ALG`. When defined, specifies the error correction
  variants of the parameter sets should be used (e.g. `R5ND_1KEM_5c` will be
  used instead of `R5ND_1KEM_0c`).

* `TAU`:

  Specifies the value of the `TAU` parameter (0, 1, or 2), i.e. the method for
  the generation of A.

  This option compiles all sources with `-DROUND5_API_TAU=<TAU>`.

* `AES`:

  When set to anything other than the empty string or 0, this specifies that
  the deterministic random values should be generated using AES in CTR mode
  on “zero” input blocks (with the key equal to the seed) instead of using
  the default method (i.e. Shake).  The AES method can be faster, especially
  on platforms with a well optimized OpenSSL AES implementation.

  This option compiles all sources with `-DUSE_AES_DRBG`.

* `NO_OPENSSL_SHAKE`:

  When OpenSSL 1.1.1 (or later) is installed, the default is to make use of
  OpenSSL's Shake implementation. Set this variable to anything other than
  the empty string to disable the use of OpenSSL's Shake.

  This option compiles all sources with `-DNO_OPENSSL_SHAKE`.

* `DEBUG`:

  When set to anything other than the empty string, this variable enables the
  _debug_ build of the implementation. The _debug_ build generates additional
  debugging output when run.

  This option compiles all sources with `-DDEBUG` and debug
  symbols. Compiler optimizations are turned off.

* `CFLAGS`:

  Additional C compiler flags. Can be used to specify additional options.
  For instance `CFLAGS=-DCM_CACHE` enables the cache attack countermeasures
  in the tiny implementation and `CFLAGS=-DROUND5_INTERMEDIATE` enables the
  generation of intermediate output (used when generating KAT files, much
  less verbose than `DEBUG`).


Running the example applications
--------------------------------

The example applications are `kem_example` for Round5.KEM and
`encrypt_example` for Round5.PKE (found in the build directory of the
implementation).

The applications take as argument `-a N` to specify the api parameter
set to use, where N is a number between 0 and 81 and `-t N` to specify
the tau variant, where N is a number between 0 and 2, as described in
the specification (ignored for parameter sets that make use of the ring
construction).

For the definition of the parameter sets, see the file
`reference/src/r5_parameter_sets.c`.

