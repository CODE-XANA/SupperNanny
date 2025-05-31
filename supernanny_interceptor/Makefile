EBPF_DIR := src/ebpf/kern
VMLINUX := $(EBPF_DIR)/vmlinux.h
BPF_SRC := $(EBPF_DIR)/exec_intercept.c
BPF_OBJ := $(EBPF_DIR)/exec_intercept.o

BPF_CLANG_FLAGS := -O2 -g -target bpf \
	-D__TARGET_ARCH_x86 \
	-I$(EBPF_DIR)

.PHONY: all clean vmlinux

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	@echo "[+] Compiling eBPF program..."
	clang $(BPF_CLANG_FLAGS) -c $< -o $@
	@which llvm-strip >/dev/null && llvm-strip -g $@ || true
	@echo "[✓] eBPF program compiled: $@"

$(VMLINUX):
	@echo "[+] vmlinux.h missing, generating..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX); \
		echo "[✓] vmlinux.h generated."; \
	else \
		echo "[✗] Cannot find /sys/kernel/btf/vmlinux. Install BTF-enabled kernel or copy vmlinux.h manually."; \
		exit 1; \
	fi

clean:
	@rm -f $(BPF_OBJ)
	@echo "[✓] Cleaned."
