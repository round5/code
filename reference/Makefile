################################################################################
#
# Makefile for the Round5 implementations.
#
# The following make variables can be used to influence the build of the
# implementations.
#
# * ALG:
#
#   With this variable, the algorithm implemented by the NIST api is
#   specified. Can be one of R5ND_1KEM_0c, R5ND_1PKE_0c, R5ND_3KEM_0c,
#   R5ND_3PKE_0c, R5ND_5KEM_0c, R5ND_5PKE_0c, R5ND_1KEM_5c,
#   R5ND_1PKE_5c, etc. The default is R5ND_1KEM_0c.
#
# * ALG_TYPE:
#
#   Alternative to specifying ALG. Specifies the algorithm type (ND or N1)
#   implemented by the NIST api. The default is ND.
#
# * NIST_LEVEL:
#
#   Alternative to specifying ALG. Specifies the NIST level implemented by
#   the NIST api. Can be 1, 3, or 5. The default is 1.
#
# * KEM_PKE:
#
#   Alternative to specifying ALG. Specifies the type of algorithm
#   implemented by the NIST api. Can be KEM or PKE. The default
#   is KEM.
#
# * XEF:
#
#   Alternative to specifying ALG. When defined, specifies the error correction
#   variants of the parameter sets should be used (e.g. R5ND_1KEM_5c will be
#   used instead of R5ND_1KEM_0c).
#
# * TAU:
#
#   Specifies the value of the TAU parameter (0, 1, or 2), i.e. the method for
#   the generation of A.
#
#   This option compiles all sources with -DROUND5_API_TAU=<TAU>.
#
# * AES:
#
#   When set to anything other than the empty string or 0, this specifies that
#   the deterministic random values should be generated using AES in CTR mode
#   on “zero” input blocks (with the key equal to the seed) instead of using
#   the default method (i.e. Shake).  The AES method can be faster, especially
#   on platforms with a well optimized OpenSSL AES implementation.
#
#   This option compiles all sources with -DUSE_AES_DRBG.
#
# * NO_OPENSSL_SHAKE:
#
#   When OpenSSL 1.1.1 (or later) is installed, the default is to make use of
#   OpenSSL's Shake implementation. Set this variable to anything other than
#   the empty string to disable the use of OpenSSL's Shake.
#
#   This option compiles all sources with -DNO_OPENSSL_SHAKE.
#
# * DEBUG:
#
#   When set to anything other than the empty string, this variable enables the
#   debug build of the implementation. The debug build generates additional
#   debugging output when run.
#
#   This option compiles all sources with -DDEBUG and debug
#   symbols. Compiler optimizations are turned off.
#
# * CFLAGS:
#
#   Additional C compiler flags. Can be used to specify additional options.
#   For instance CFLAGS=-DCM_CACHE enables the cache attack countermeasures
#   in the tiny implementation and CFLAGS=-DROUND5_INTERMEDIATE enables the
#   generation of intermediate output (used when generating KAT files, much
#   less verbose than DEBUG).
#
################################################################################

# The implementation
implementation := $(notdir $(CURDIR))

################################################################################
# Variant Setup ################################################################
################################################################################

# The variant of the algorithm for the tiny implementation is set using the ALG
# variable. Alternatively it can also be set by specifying KEM_PKE (either KEM
# or PKE) and/or NIST_LEVEL (1, 3, or 5). The type of the algorithm (ND, T0, T1,
# or T2) is derived from the implementation.
#
# The default is KEM, NIST level 1.

# Set default algorithm type (ring)
ifneq (N1,$(ALG_TYPE))
    override ALG_TYPE := ND
endif

# NIST level (1, 3, 5)
ifeq (,$(NIST_LEVEL))
    NIST_LEVEL := 1
endif

# PKE or KEM
ifeq (,$(KEM_PKE))
    KEM_PKE := KEM
endif

# Set the algorithm (if none set)
ifndef ALG
    ALG := R5$(ALG_TYPE)_$(NIST_LEVEL)$(KEM_PKE)_0c
    ifdef XEF
        ifeq (ND,$(ALG_TYPE))
            override ALG := R5$(ALG_TYPE)_$(NIST_LEVEL)$(KEM_PKE)_5c
        endif
    endif
endif

################################################################################
# Dir/File Setup ###############################################################
################################################################################

srcdir    = src
builddir  = build
objdir    = $(builddir)/.o
depdir    = $(builddir)/.d
docdir    = doc

srcs     := $(wildcard $(srcdir)/*.c) $(wildcard $(srcdir)/examples/*.c)
objs     := $(srcs:$(srcdir)/%.c=$(objdir)/%.o)

examples := $(patsubst $(srcdir)/examples/%.c, $(builddir)/%, $(wildcard $(srcdir)/examples/*.c))

ifeq (tiny,$(implementation))
    tests := $(patsubst $(srcdir)/tests/%.c, $(builddir)/%, $(wildcard $(srcdir)/tests/*.c))
endif

################################################################################
# Compiler Setup ###############################################################
################################################################################

CC          = gcc

# Compiler flags, allow to set *additional* parameters at the command-line
override CFLAGS += -I $(srcdir) -std=c99 -pedantic -Wall -Wextra -Wconversion -Wcast-qual -Wcast-align

# Define version to build
override CFLAGS += -D$(ALG)
ifdef TAU
    override CFLAGS += -DROUND5_API_TAU=$(TAU)
endif

# Disable OpenSSL's Shake?
ifdef NO_OPENSSL_SHAKE
    override CFLAGS += -DNO_OPENSSL_SHAKE
endif

# Use AES in CTR mode instead of cSHAKE for the generation of deterministic random numbers
ifdef AES
    override CFLAGS += -DUSE_AES_DRBG
endif

# If debug is specified, compile differently
ifndef DEBUG
    override CFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv
else
    override CFLAGS += -g -DDEBUG
endif

DEPFLAGS    = -MT $@ -MMD -MP -MF $(depdir)/$*.Td

POSTCOMPILE = mv -f $(depdir)/$*.Td $(depdir)/$*.d && touch $@

LDFLAGS    +=

LDLIBS     += -lcrypto -lkeccak -lm

################################################################################
# Main Target Rules ############################################################
################################################################################

# Builds the example/test applications
build: $(examples) $(tests) createAfixed

# Builds all, including docs
all: build doc

ifneq (tiny,$(implementation))
# Builds the createAfixed application (reference/optimized)
createAfixed: $(builddir)/createAfixed
else ifeq (1,$(TAU))
# Builds the createAfixed application (tiny with TAU = 1)
createAfixed: $(builddir)/createAfixed
else
# Dummy rule for createAfixed
createAfixed: ;
endif

ifneq (tiny,$(implementation))
# Updates/creates the documentation (not for tiny)
# An html version is built in doc/html, a LaTeX version in doc/latex
#
# Requires doxygen to be installed (with dot support)
# The Doxygen configuration is found in Doxyfile
doc: Doxyfile
	@doxygen && echo "Documentation successfully generated for $(implementation)"

ifeq (optimized,$(implementation))
Doxyfile: ../reference/Doxyfile
	@cat $^ | sed "s/^\(PROJECT_BRIEF.*\)reference/\1$(implementation)/" > $@
endif

# Generates a pdf of the latex documentation
# The pdf can be found in doc/latex/refman.pdf
pdf: doc
	@$(MAKE) -C $(docdir)/latex

# latex is an alias for pdf
latex: pdf
else
# Dummy rules for doc, pdf, latex
doc pdf latex: ;
endif

# Remove the generated documentation and build files
clean: clean-build clean-doc

# Remove only the generated build files
clean-build:
	@rm -fr $(builddir)

# Remove only the generated dependency files
clean-dep:
	@rm -fr $(depdir)

# Remove only the generated object files
clean-obj:
	@rm -fr $(objdir)

# Remove only the generated documentation
clean-doc:
	@rm -fr $(docdir)

# Above are all "phony" targets
.PHONY: build all doc pdf latex clean clean-obj clean-dep clean-doc clean-all createAfixed

################################################################################
# Object Creation ##############################################################
################################################################################

# Special rule for tiny tests
$(objdir)/tests/test_%.o: $(srcdir)/tests/test_%.c $(depdir)/tests/test_%.d
	@mkdir -p $(dir $@) $(patsubst $(objdir)/%, $(depdir)/%,$(dir $@))
	$(CC) $(filter-out -std=c99 -pedantic,$(CFLAGS)) $(DEPFLAGS) -c $< -o $@
	@$(POSTCOMPILE)

# Basic rule for standard object files
$(objdir)/%.o: $(srcdir)/%.c $(depdir)/%.d
	@mkdir -p $(dir $@) $(patsubst $(objdir)/%, $(depdir)/%,$(dir $@))
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@
	@$(POSTCOMPILE)

################################################################################
# Executable Creation ##########################################################
################################################################################

ifneq (tiny,$(implementation))
# createAfixed for reference/optimized
$(builddir)/createAfixed: $(objdir)/parameters.o $(objdir)/r5_parameter_sets.o $(objdir)/rng.o $(objdir)/drbg.o $(objdir)/misc.o $(objdir)/r5_memory.o $(objdir)/r5_hash.o $(objdir)/shake.o $(objdir)/little_endian.o $(objdir)/a_fixed.o $(objdir)/a_random.o $(objdir)/createAfixed/createAfixed.o
	$(CC) $(LDFLAGS) $^ $(LOADLIBS) $(LDLIBS) -o $@
else ifeq (1,$(TAU))
# createAfixed for tiny with tau=1
$(builddir)/createAfixed: $(objdir)/rng.o $(objdir)/drbg.o $(objdir)/misc.o $(objdir)/r5_memory.o $(objdir)/r5_hash.o $(objdir)/shake.o $(objdir)/little_endian.o $(objdir)/a_fixed.o $(objdir)/a_random.o $(objdir)/createAfixed/createAfixed.o
	$(CC) $(LDFLAGS) $^ $(LOADLIBS) $(LDLIBS) -o $@
endif

# Template for building executables
define exe_template
$(1): $$(patsubst $(builddir)/%,$(objdir)/$(2)/%.o,$(1)) $(filter-out $(objdir)/tests/%.o $(objdir)/examples/%.o, $(objs))
	@mkdir -p $(dir $$@)
	$(CC) $(LDFLAGS) $$^ $(LOADLIBS) $(LDLIBS) -o $$@
endef

$(foreach exe,$(examples),$(eval $(call exe_template,$(exe),examples)))

$(foreach exe,$(tests),$(eval $(call exe_template,$(exe),tests)))

################################################################################
# Dependency Creation and Inclusion ############################################
################################################################################

# Don't complain if dependency file does not yet exist
$(depdir)/%.d: ;

# Keep dependency files
.PRECIOUS: $(depdir)/%.d

# Include dependency files
include $(wildcard $(patsubst $(srcdir)/%,$(depdir)/%.d,$(basename $(srcs))))
