# Enhanced PE Crypter Makefile
CC = gcc
CFLAGS = -Wall -O2 -std=c99 -D_WIN32_WINNT=0x0601
LDFLAGS = -lkernel32 -luser32 -ladvapi32 -lpsapi

ENHANCED_DIR = ../enhanced_components
TESTING_DIR = ../testing

# Main enhanced crypter with integration
CRYPTER_SOURCES = \
	$(ENHANCED_DIR)/integration/crypter_integration.c \
	$(ENHANCED_DIR)/enhanced_loader/enhanced_loader.c \
	$(ENHANCED_DIR)/enhanced_loader/payload_decryption.c \
	$(ENHANCED_DIR)/eat_hooking/eat_hooker.c \
	$(ENHANCED_DIR)/eat_hooking/api_hooks.c \
	$(ENHANCED_DIR)/evasion/vm_detection.c \
	$(ENHANCED_DIR)/evasion/sandbox_detection.c \
	$(ENHANCED_DIR)/evasion/debugger_detection.c

# Validation sources  
VALIDATION_SOURCES = \
	$(TESTING_DIR)/validation_suite.c \
	$(ENHANCED_DIR)/eat_hooking/eat_hooker.c \
	$(ENHANCED_DIR)/evasion/vm_detection.c \
	$(ENHANCED_DIR)/evasion/sandbox_detection.c \
	$(ENHANCED_DIR)/evasion/debugger_detection.c

.PHONY: all clean test help

all: enhanced_crypter validation_suite

enhanced_crypter: $(CRYPTER_SOURCES)
	@echo "Building complete enhanced crypter..."
	$(CC) $(CFLAGS) -o enhanced_crypter.exe $^ $(LDFLAGS)
	@echo "✅ Enhanced crypter built successfully!"

validation_suite: $(VALIDATION_SOURCES)
	@echo "Building validation suite..."
	$(CC) $(CFLAGS) -o validation_suite.exe $^ $(LDFLAGS)
	@echo "✅ Validation suite built successfully!"

test: validation_suite
	@echo "Running validation tests..."
	./validation_suite.exe

clean:
	rm -f *.exe

help:
	@echo "Enhanced PE Crypter Build System"
	@echo "================================"
	@echo "Targets:"
	@echo "  all              - Build enhanced crypter and validation suite"
	@echo "  enhanced_crypter - Build only the enhanced crypter"
	@echo "  validation_suite - Build only the validation suite"
	@echo "  test             - Build and run validation tests"
	@echo "  clean            - Remove all built executables"
	@echo "  help             - Show this help message"
