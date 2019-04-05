# Makefile for the ROUND5 project software
#
# See README.md for information on the various make targets.
#
# NOTE: It is assumed that openssl and libkeccak are available and part of the
# CPATH/LIBRARY_PATH!

# Setup directories
implementations = reference configurable optimized
clean_implementations = $(addprefix clean-,$(implementations))
doc_implementations = $(addprefix doc-,$(implementations))

build: $(implementations)

all: build doc


doc: $(doc_implementations)



clean: $(clean_implementations)

$(implementations):
	@$(MAKE) -C $@

$(doc_implementations):
	@$(MAKE) -C $(patsubst doc-%,%,$@) doc



$(clean_implementations):
	@$(MAKE) -C $(patsubst clean-%,%,$@) clean

.PHONY: build all $(implementations) doc $(doc_implementations) clean $(clean_implementations)
