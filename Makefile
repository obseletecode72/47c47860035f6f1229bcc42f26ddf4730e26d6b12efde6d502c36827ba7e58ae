CC = gcc
CFLAGS = -Wall -O2 -pthread -D_GNU_SOURCE
LDFLAGS = -lssl -lcrypto -lpthread -lm
TARGET = mhddos
SRCS = main.c utils.c layer4.c layer7.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c mhddos.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
