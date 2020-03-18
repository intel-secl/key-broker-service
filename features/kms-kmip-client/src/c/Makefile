# /*
# Copyright (C) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
# */

#
# Root Makefile
# Arvind Rawat
#
#
KCROOT=.
OBJROOTR=$(KCROOT)/build
BIN=$(KCROOT)/bin
LIB=$(KCROOT)/lib

RMOBJROOTR=$(KCROOT)/build/
RMBIN=$(KCROOT)/bin
RMLIB=$(KCROOT)/lib

BUILD_TARGETS=  makedirstructure \
				kmipclient-g  \

TARGETS=$(BUILD_TARGETS) clean

.PHONY: $(TARGETS)

all: $(BUILD_TARGETS)

install:
	chmod +x $(LIB)/libkmipclient.so
	mkdir -p $(PREFIX)/lib/
	cp $(LIB)/libkmipclient.so $(PREFIX)/lib/

makedirstructure:
	mkdir -p $(BIN)
	mkdir -p $(LIB)
	mkdir -p $(OBJROOTR)

kmipclient-g:
	mkdir -p $(OBJROOTR)/kcobjects
	$(MAKE) debug=$(debug) -f kmipclient-g.mak

clean:
	rm -f $(RMOBJROOTR)/*objects/*.o
	rm -f $(RMOBJROOTR)/*objects/*.s
	rm -f $(RMOBJROOTR)/*.o
	rm -f $(RMOBJROOTR)/*/*.o
	rm -f $(RMOBJROOTR)/*/*.s
	rm -rf $(RMOBJROOTR)/*
	rm -f $(RMBIN)/*.exe
	rm -f $(RMBIN)/*
	rm -f $(RMLIB)/*.so
