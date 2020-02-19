ROUND5
=======

[Round5](https://round5.org/) is a compact and fast post-quantum public-key encryption scheme and a [NIST PQC second round candidate](https://csrc.nist.gov/projects/post-quantum-cryptography/round-2-submissions). Round5 relies on the General Learning with Rounding (GLWR) problem to unify the well-studied Learning with Rounding (LWR) and Ring Learning with Rounding (RLWR) lattice-problems. It enables a single description and implementation of Round5's IND-CPA KEM, IND-CCA KEM and an IND-CCA PKE algorithms. This unified approach allows the Round5 proposal to fulfil the requirements of many different applications.

Round5 currently defines 21 parameter sets. A parameter set is denoted as:

					R5N{1,D}_{1,3,5}{CPA,CCA}_{0,5}{version}
		
where:

* {1,D} refers whether it is a non-ring (1) or ring (D) parameter set.
* {1,3,5} refers to the NIST security level that is strictly fulfilled.
* {CPA,CCA} refers to the cryptographic algorithm it instantiates. 
* {0,5} identifies the number of correctable bits, 0 means no errors are corrected and this description is equivalent to the original Round2; 5 means that up to 5 errors can be corrected.
* {version} is a letter to indicate the version of published parameters. Round5 parameters for the second round of NIST PQC are version "d". 

Round5's IND-CPA KEM algorithm relies on `R5N{1,D}_{1,3,5}CPA_{0,5}{version}`parameter sets. 
Round5's IND-CCA KEM and IND-CCA KEM algorithm require `R5N{1,D}_{1,3,5}CCA_{0,5}{version}`parameter sets. 
The reason for defining both an IND-CPA and an IND-CCA KEM is because ephemeral handshakes can be made up to `40%`
 more efficient, in particular, bandwidth wise.
 
This code base includes three implementations. 
 
 * The `reference` implementation focuses on describing the underlying operations in Round5. This code is capable to run any parameter set at run time. This code does not run fast.
 * The `optimized` code includes optimizations for speed and countermeasures against side-channel attacks. It also includes optimizations using AVX2 instructions.   
 * The `configurable` code provides good performance as well, but it is capable to execute at runtime any parameter set.

The implementations include the code of [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and cSHAKE ([SP800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final)) so that Round5 KEM algorithms can run without external libraries.

In addition to this implementation, Markku-Juhani O. Saarinen also maintains the [r5embed](https://github.com/r5embed/r5embed) implementation that is specially crafted for embedded platforms. 


CONTENTS
--------

* Prerequisites
* Building the implementations
* Running the example application and targets
* KATs


Prerequisites
-------------

To be able to build and run the implementations of the algorithm, the
following conditions must be met:

* The OpenSSL library (1.1.1, or later) must be installed.
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


Building the implementations
----------------------------

After installing the prerequisites, you can build the implementations
using `make`.
If you build an IND-CPA parameter set, then you will build the IND-CPA KEM algorithm only.
If you build an IND-CCA parameter set, then you will build both the IND-CCA KEM and the IND-CCA PKE algorithms.

### Make targets ###

Several targets are available including:

* `build`: Builds the available implementations. This is the default target.

* `reference`: Build just the “reference” implementation.

* `configurable`: Build just the “configurable” implementation.

* `optimized`: Build just the “optimized” implementation.

* `clean`: Removes all build artifacts. 

### Make variables ###

The following make variables can be used to influence the build of the implementations.

* ***ALG:*** With this variable, the parameter set implemented by the NIST api is
  specified. For instance, to use `R5ND_1CCA_5d` write:
  ```
  make ALG=R5ND_1CCA_5d
  ``` 

  The default is `R5ND_1CPA_0d`. Otherwise, it can be one of: `R5ND_1CPA_0d`,
  `R5ND_3CPA_0d`, `R5ND_5CPA_0d`, `R5ND_1CCA_0d`, `R5ND_3CCA_0d`,
  `R5ND_5CCA_0d`, `R5ND_1CPA_5d`, `R5ND_3CPA_5d`, `R5ND_5CPA_5d`,
  `R5ND_1CCA_5d`, `R5ND_3CCA_5d`, `R5ND_5CCA_5d`, `R5N1_1CPA_0d`,
  `R5N1_3CPA_0d`, `R5N1_5CPA_0d`, `R5N1_1CCA_0d`, `R5N1_3CCA_0d`,
  `R5N1_5CCA_0d`, `R5ND_0CPA_2iot`, `R5ND_0CCA_4iot`, `R5ND_1CPA_4longkey`,
  `R5N1_3CCA_0smallCT`.

* ***ALG\_TYPE, NIST\_LEVEL, CPA_CCA and XEF:*** Instead of specifying `ALG`, it is possible to select `ALG_TYPE`, `NIST_LEVEL`,
  `CPA_CCA`, and `XEF`. For instance:
  ```
  make ALG=ND NIST_LEVEL=1 CPA_CCA=CCA XEF=1
  ```

  - `ALG_TYPE`: Specifies the algorithm type (`ND` means ring-based, `N1` means
    non-ring based) implemented by the NIST api. The default is `ND`.

  - `NIST_LEVEL`: Specifies the NIST security level. It can be 1, 3, or 5. The
    default is 1.

  - `CPA_CCA`: Specifies the type of parameter set. It can be `CPA` or `CCA`. The
    default is `CPA` and it is suitable for the IND-CPA secure Round5 KEM. The `CCA` 
    parameter sets are required in the IND-CCA secure Round5 KEM and PKE.

  - `XEF`: When defined, specifies that the error correction variants of the
    parameter sets should be used (e.g. `R5ND_1CPA_5d` will be used instead of
    `R5ND_1CPA_0d`).

* ***TAU and TAU2\_LEN:*** The variables `TAU`, `TAU2_LEN` control the way matrix A is computed. For instance:
  ```
  make TAU=1 
  ```

  - `TAU`: Specifies the value of the `TAU` parameter (0, 1, or 2), i.e. the
    method for the generation of A.

  - `TAU2_LEN`: Specifies the length of the random vector when A is generated
    with `TAU` equals 2 (defaults to the value of algorithm parameter `q`).

    Note: this must be a power of two and larger than algorithm parameter `d`.
    
* ***AES and STANDALONE:*** These variables define the way a random seed is expanded to generate A. The default approach is to use the SHA3 XOF functions instantiated by means of the `XKCP` library. Alternatively, the seed can be expanded by means of AES or a standalone library of FIPS202 / SP800-185.

  - `AES`: If this flag is set, then the seed is expanded by means of AES in CTR mode.

  - `STANDALONE`: If this flag is set, then the seed is expanded by means of FIPS202 / SP800-185 using the standalone library.

* ***CM\_CACHE and CM\_CT:*** Timing and cache attack countermeasures can be enabled by means of the
  `CM_CACHE` and `CM_CT` flags. These flags are only applicable to the optimized implementation.
  For instance: `make CM_CACHE=1`
  - If no flag is used, then the implementation is suitable for platforms without a cache.
  - The `CM_CACHE` introduces countermeasures against cache-attacks, but it is not fully constant-time.
  - The `CM_CT` flag delivers a fully constant time implementatiton.
  - To indicate that the 64-bit shift left operator with a variable amount can be considered constant-time on your platform, set `SHIFT_LEFT64_CONSTANT_TIME` to anything other than the empty string `SHIFT_LEFT64_CONSTANT_TIME=1`

* ***AVX2:*** To allow the use of AVX2 optimisations, set `AVX2` to anything other than the
  empty string (only applicable to the optimized implementation, requires an AVX2
  compatible CPU/compiler).
  For instance: `make AVX2=1`. Please note that this option implies `CM_CT`.
   
* ***KATs:*** To compile the code for generating NIST KATs, set `NIST_KAT_GENERATION` to
  anything other than the empty string. For instance:
  ```
  make NIST_KAT_GENERATION=1
  ```

  This replaces the “true” random bytes generator with the NIST (deterministic)
  random bytes generator and enables the output of intermediate results.

* ***TIMING:*** The `TIMING` flag can be set to obtain timing performance of Round5 KEMs. To this end, run `make TIMING=1`. This will provide timing values averaged out over 1000 executions. If you want to get the timing values averaged out over `N` executions, then run `make TIMING=N`


* ***DEBUG:*** Finally, the following flag is used for debugging purposes: `DEBUG`.
  When set to anything other than the empty string, this variable enables the
  _debug_ build of the implementation. The _debug_ build generates additional
  debugging output when run. For instance:
  ```
  make DEBUG=1
  ```


Running the example application and targets
-------------------------------------------

There are several examples in the `examples` directory. 
The applications are found in the `build` directory of the implementations.

In the optimized implementation, you can run it for the parameters chosen while
making it as:
```
./sample_kem
```
If you made the application with the `TIMING` flag, running this application will give you the timing.

In the reference and configurable implementations, the application can be executed
for any configuration at runtime and takes the following arguments:

* `-a <PARAMETER-SET-NAME>` to specify the name of the parameter set to
  use. Here <PARAMETER-SET-NAME> is the name of the parameter set to use
  (i.e. one of `R5ND_1CPA_0d`, `R5ND_3CPA_0d`, `R5ND_5CPA_0d`, `R5ND_1CCA_0d`,
  `R5ND_3CCA_0d`, `R5ND_5CCA_0d`, `R5ND_1CPA_5d`, `R5ND_3CPA_5d`,
  `R5ND_5CPA_5d`, `R5ND_1CCA_5d`, `R5ND_3CCA_5d`, `R5ND_5CCA_5d`,
  `R5N1_1CPA_0d`, `R5N1_3CPA_0d`, `R5N1_5CPA_0d`, `R5N1_1CCA_0d`,
  `R5N1_3CCA_0d`, `R5N1_5CCA_0d`, `R5ND_0CPA_2iot`, `R5ND_1CPA_4longkey`, `R5N1_3CCA_0smallCT`).

* `-t N` to specify the tau variant, where N is a number between 0 and 2, as
  described in the specification (ignored for parameter sets that make use of
  the ring construction).

For instance, in reference you can run:
```
./sample_kem -a R5ND_1CPA_4longkey
```
Round5 is a flexible scheme so that the user can pick up the best parameter set and configuration for different platforms and applications. Next, we give some examples assuming the usage of the optimized implementation.

* For an embedded target requiring an ephemeral handshake do:

	`make ALG=R5ND_0CPA_2iot	STANDALONE=1`
	
  and use the IND-CPA KEM by running `./build/sample_kem`.

* For a PC requiring a long-term public-key and fast operation, use:

	`make ALG=R5ND_3CCA_5d	AVX2=1`
	
	and use Round5's IND-CCA KEM by running `./build/sample_kem`.

* If you need long-term encryption, with high-security, and you do not worry about the exchange of the public-key, and you need a short ciphertext, then use:

	`make ALG=R5N1_3CCA_0smallCT	AVX2=1`
	
	and use Round5's IND-CCA PKE by running `./build/sample_pke`.

KATs
----

Next to the implementations, there is an additional folder called `kats`.
This folder contains scripts to generate and check kats. 
It also contains the fingerprints of the KATs.


