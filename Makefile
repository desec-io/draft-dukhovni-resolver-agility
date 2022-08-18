VERSION = 00
DOCNAME = draft-dukhovni-resolver-agility
today := $(shell TZ=UTC date +%Y-%m-%dT00:00:00Z)

all: build/$(DOCNAME)-$(VERSION).txt build/$(DOCNAME)-$(VERSION).html

build/$(DOCNAME)-$(VERSION).txt: build/$(DOCNAME).xml
	xml2rfc --text -o $@ $<

build/$(DOCNAME)-$(VERSION).html: build/$(DOCNAME).xml
	xml2rfc --html -o $@ $<

build/$(DOCNAME).xml: $(DOCNAME).md
	sed -e 's/@DOCNAME@/$(DOCNAME)-$(VERSION)/g' \
	    -e 's/@TODAY@/${today}/g'  $< | mmark > $@ || rm -f $@

clean:
	rm -f build/$(DOCNAME).xml build/$(DOCNAME)-$(VERSION).txt build/$(DOCNAME)-$(VERSION).html
