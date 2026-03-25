CSRC = $(wildcard *.c)
CBIN = $(CSRC:.c=)
CFLAGS = -Wno-unused-function -Wno-unused-const-variable -Os -static -I../include -I../modkmap -I../tdxutils

.PHONY: all

all: $(CBIN)

%: %.c
	$(CC) $(CFLAGS) $< -o $@ -l:libncurses.a -l:libtinfo.a -l:libm.a

clean:
	rm -f $(CBIN) *.o
