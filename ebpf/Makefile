CLANG := clang
CFLAGS := -O2 -g -Wall -target bpf

all: policy.o

policy.o: policy.c
	$(CLANG) $(CFLAGS) -c policy.c -o policy.o

clean:
	rm -f policy.o

.PHONY: all clean