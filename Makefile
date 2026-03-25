SUBDIRS := pocs

.PHONY: all $(SUBDIRS)

all: tdxutils.ko modkmap.ko $(CBIN) $(CXXBIN) $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

tdxutils.ko: tdxutils/tdxutils_main.c tdxutils/tdxutils_mwait.c tdxutils/tdxutils.h
	sh -c "cd tdxutils && make"
	mv tdxutils/tdxutils.ko .

modkmap.ko: modkmap/modkmap.c modkmap/modkmap.h modkmap/device_register.h
	sh -c "cd modkmap && make"
	mv modkmap/modkmap.ko .

clean:
	sh -c "cd tdxutils  && make clean"
	sh -c "cd modkmap && make clean"
	rm -f $(CBIN) $(CXXBIN) *.o *.ko
	make -C timings clean
	make -C prompt-recovery clean
	make -C pocs clean
