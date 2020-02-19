 ################################################################################
#
# Makefile for the Round5 implementations.
#
# Please see main README.md file for an explanation of the make variables that
# can be used to specify the build behaviour.
#
################################################################################

# The implementation
implementation := $(notdir $(CURDIR))

################################################################################
# Variant Setup ################################################################
################################################################################

# The variant of the algorithm for the optimized implementation is set using the ALG
# variable. Alternatively it can also be set by specifying CPA_CCA (either CPA
# or CCA) and/or NIST_LEVEL (1, 3, or 5). The type of the algorithm (ND, T0, T1,
# or T2) is derived from the implementation.
#
# The default is CPA, NIST level 1.

# Set default algorithm type (ring)
ifneq (N1,$(ALG_TYPE))
    override ALG_TYPE := ND
endif

# NIST level (1, 3, 5)
ifeq (,$(NIST_LEVEL))
    NIST_LEVEL := 1
endif

# CCA or CPA
ifeq (,$(CPA_CCA))
    CPA_CCA := CPA
endif

# Set the algorithm (if none set)
ifndef ALG
    ALG := R5$(ALG_TYPE)_$(NIST_LEVEL)$(CPA_CCA)_0d
    ifdef XEF
        ifeq (ND,$(ALG_TYPE))
            override ALG := R5$(ALG_TYPE)_$(NIST_LEVEL)$(CPA_CCA)_5d
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

# RNG depends on KAT-generation setting
ifdef NIST_KAT_GENERATION
    rngsrc = $(srcdir)/rng/nist_rng.c
else
    rngsrc = $(srcdir)/rng/true_rng.c
endif
rngobj   := $(rngsrc:$(srcdir)/%.c=$(objdir)/%.o)

srcs     := $(wildcard $(srcdir)/*.c) $(rngsrc) $(wildcard $(srcdir)/examples/*.c)
objs     := $(srcs:$(srcdir)/%.c=$(objdir)/%.o)

examples := $(patsubst $(srcdir)/examples/%.c, $(builddir)/%, $(wildcard $(srcdir)/examples/*.c))


################################################################################
# Compiler Setup ###############################################################
################################################################################

CC           = gcc

AFLFUZZER_CC = afl-gcc

LIBFUZZER_CC = clang

# Compiler flags, allow to set *additional* parameters at the command-line
override CFLAGS += -I $(srcdir) -std=c99 -pedantic -Wall -Wextra -Wconversion -Wcast-qual -Wcast-align

# Define version to build
override CFLAGS += -D$(ALG)

# TAU?
ifdef TAU
    override CFLAGS += -DROUND5_API_TAU=$(TAU)
endif

# TAU2_LEN?
ifdef TAU2_LEN
    override CFLAGS += -DROUND5_API_TAU2_LEN=$(TAU2_LEN)
endif


# Use AES in CTR mode instead of cSHAKE for the generation of deterministic random numbers
ifdef AES
    override CFLAGS += -DUSE_AES_DRBG
endif

# Use standalone library of FIPS202 SP800-185
ifdef STANDALONE
    override CFLAGS += -DSTANDALONE
endif

# Generating NIST KATs?
ifdef NIST_KAT_GENERATION
    override CFLAGS += -DNIST_KAT_GENERATION
endif

# Enable cache attack counter measures?
ifdef CM_CACHE
    override CFLAGS += -DCM_CACHE
endif

# Enable constant-time countermeasures?
ifdef CM_CT
    override CFLAGS += -DCM_CT
endif

# Enable time measurement of KEMs
ifdef TIMING
    override CFLAGS += -DTIMING=$(TIMING)
endif

# Enable AVX2?
ifdef AVX2
    override CFLAGS += -DAVX2
endif

# 64-bit shift left with variable shift amount constant-time?
ifdef SHIFT_LEFT64_CONSTANT_TIME
    override CFLAGS += -DSHIFT_LEFT64_CONSTANT_TIME
endif

# If debug is specified, compile differently
ifndef DEBUG
    override CFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv
else
    override CFLAGS += -g -DDEBUG -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv
endif

# Compute challenges
ifdef CHALLENGE
    override CFLAGS += -DCHALLENGE
endif

DEPFLAGS    = -MT $@ -MMD -MP -MF $(depdir)/$*.Td

POSTCOMPILE = mv -f $(depdir)/$*.Td $(depdir)/$*.d && touch $@

LDFLAGS    +=

LDLIBS     += -lcrypto -lkeccak -lm


################################################################################
# Main Target Rules ############################################################
################################################################################

# Builds the example/test applications
build: $(examples) createAfixed

# Builds all, including docs
all: build doc

ifneq (optimized,$(implementation))
# Builds the createAfixed application (reference/configurable)
createAfixed: $(builddir)/createAfixed
else ifeq (1,$(TAU))
# Builds the createAfixed application (optimized with TAU = 1)
createAfixed: $(builddir)/createAfixed
else
# Dummy rule for createAfixed
createAfixed: ;
endif

ifneq (optimized,$(implementation))
# Updates/creates the documentation (not for optimized)
# An html version is built in doc/html, a LaTeX version in doc/latex
#
# Requires doxygen to be installed (with dot support)
# The Doxygen configuration is found in Doxyfile
doc: Doxyfile
	@doxygen && echo "Documentation successfully generated for $(implementation)"

ifeq (configurable,$(implementation))
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

# Special rule for nist_rng.c
$(objdir)/%/nist_rng.o: $(srcdir)/%/nist_rng.c $(depdir)/%/nist_rng.d
	@mkdir -p $(dir $@) $(patsubst $(objdir)/%, $(depdir)/%,$(dir $@))
	$(CC) $(filter-out -W%, $(CFLAGS)) $(DEPFLAGS) -c $< -o $@
	@$(POSTCOMPILE)

# Basic rule for standard object files
$(objdir)/%.o: $(srcdir)/%.c $(depdir)/%.d
	@mkdir -p $(dir $@) $(patsubst $(objdir)/%, $(depdir)/%,$(dir $@))
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@
	@$(POSTCOMPILE)


################################################################################
# Executable Creation ##########################################################
################################################################################

ifneq (optimized,$(implementation))
# createAfixed for reference/configurable
$(builddir)/createAfixed: $(objdir)/parameters.o $(objdir)/r5_parameter_sets.o $(rngobj)  $(objdir)/misc.o $(objdir)/r5_memory.o $(objdir)/r5_hash.o $(objdir)/shaking.o $(objdir)/keccakf1600.o $(objdir)/aesdrbg.o $(objdir)/little_endian.o $(objdir)/a_fixed.o $(objdir)/a_random.o $(objdir)/createAfixed/createAfixed.o
	$(CC) $(LDFLAGS) $^ $(LOADLIBS) $(LDLIBS) -o $@
else ifeq (1,$(TAU))
# createAfixed for optimized with tau=1
$(builddir)/createAfixed: $(rngobj)  $(objdir)/misc.o $(objdir)/r5_memory.o $(objdir)/r5_hash.o $(objdir)/shaking.o $(objdir)/keccakf1600.o $(objdir)/aesdrbg.o $(objdir)/little_endian.o $(objdir)/a_fixed.o $(objdir)/a_random.o $(objdir)/createAfixed/createAfixed.o
	$(CC) $(LDFLAGS) $^ $(LOADLIBS) $(LDLIBS) -o $@
endif

# Template for building executables
define exe_template
$(1): $$(patsubst $(builddir)/%,$(objdir)/$(2)/%.o,$(1)) $(filter-out $(objdir)/examples/%.o, $(objs))
	@mkdir -p $(dir $$@)
	$(CC) $(LDFLAGS) $$^ $(LOADLIBS) $(LDLIBS) -o $$@
endef

$(foreach exe,$(examples),$(eval $(call exe_template,$(exe),examples)))


# Fuzzers
FUZZER_CFLAGS = $(filter-out -march=native -mtune=native -O2 -O3 -fomit-frame-pointer -fwrapv -DDEBUG -std=c99 -pedantic,$(CFLAGS)) -g -O1

aflfuzzer: $(srcdir)/*.c $(rngsrc) $(srcdir)/fuzzer/fuzz_target.c
	@mkdir -p $(builddir)
	$(AFLFUZZER_CC) -I $(srcdir) $(FUZZER_CFLAGS) $^ $(LDFLAGS) $(LOADLIBS) $(LDLIBS) -o $(builddir)/$@

libfuzzer: $(srcdir)/*.c $(rngsrc) $(srcdir)/fuzzer/fuzz_target.c
	@mkdir -p $(builddir)
	$(LIBFUZZER_CC) -I $(srcdir) $(FUZZER_CFLAGS) -DLIBFUZZER -fsanitize=fuzzer,address $^ $(LDFLAGS) $(LOADLIBS) $(LDLIBS) -o $(builddir)/$@

.PHONY: aflfuzzer libfuzzer


################################################################################
# Dependency Creation and Inclusion ############################################
################################################################################

# Don't complain if dependency file does not yet exist
$(depdir)/%.d: ;

# Keep dependency files
.PRECIOUS: $(depdir)/%.d

# Include dependency files
include $(wildcard $(patsubst $(srcdir)/%,$(depdir)/%.d,$(basename $(srcs))))
