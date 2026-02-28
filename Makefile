# Configurações Gerais
CFLAGS = -Wall -O3 -pthread -D_GNU_SOURCE
# A flag -static é o segredo aqui
LDFLAGS = -static -lpthread -lm
SRCS = main.c utils.c layer4.c layer7.c
TARGET = mhddos

# Lista de Compiladores (Cross-Compilers)
# Você precisa instalar esses pacotes no seu Ubuntu/Debian uma única vez
CC_X86     = gcc
CC_MIPS    = mips-linux-gnu-gcc
CC_MIPSEL  = mipsel-linux-gnu-gcc
CC_ARMV7   = arm-linux-gnueabihf-gcc
CC_ARM64   = aarch64-linux-gnu-gcc

# Alvo padrão: compila para todos
all: x86 mips mipsel armv7 arm64

x86:
	$(CC_X86) $(CFLAGS) $(SRCS) -o $(TARGET)_x64 $(LDFLAGS)

mips:
	$(CC_MIPS) $(CFLAGS) $(SRCS) -o $(TARGET)_mips $(LDFLAGS)

mipsel:
	$(CC_MIPSEL) $(CFLAGS) $(SRCS) -o $(TARGET)_mipsel $(LDFLAGS)

armv7:
	$(CC_ARMV7) $(CFLAGS) $(SRCS) -o $(TARGET)_armv7 $(LDFLAGS)

arm64:
	$(CC_ARM64) $(CFLAGS) $(SRCS) -o $(TARGET)_arm64 $(LDFLAGS)

clean:
	rm -f $(TARGET)_*

.PHONY: all clean x86 mips mipsel armv7 arm64