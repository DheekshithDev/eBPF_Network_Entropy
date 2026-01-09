# Top-Level Makefile

SUBDIRS := src/entropy/size/main

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $(SUBDIRS)

clean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d clean; \
	done
