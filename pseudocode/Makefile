# Copyright © 2015 Bart Massey
# This work is available under the "MIT License".
# Please see the file LICENSE in the source
# distribution of this software for license terms.

TARGETS = rc4.mdwn encrypt.mdwn decrypt.mdwn

.SUFFIXES: .pseu .mdwn

.pseu.mdwn:
	pseuf --markdown $*.pseu

all: $(TARGETS)

clean:
	-rm -f $(TARGETS)
