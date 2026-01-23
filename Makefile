# Top-Level Makefile

SUBDIRS := src/entropy/size/main src/entropy/proxy/size/main

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d clean; \
	done
