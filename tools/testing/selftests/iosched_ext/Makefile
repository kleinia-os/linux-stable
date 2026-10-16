# SPDX-License-Identifier: GPL-2.0
include ../../../build/Build.include
include ../../../scripts/Makefile.arch
include ../../../scripts/Makefile.include

TEST_GEN_PROGS := bio_merge
TEST_PROGS := fallback_bypass_use_sched.sh requeue_without_fallback_bypass.sh \
	bpf_in_flight_offline_evacuate.sh find_blkg_refcount.sh \
	offline_teardown_capture.sh capture_blkgs_partial.sh toctou_atomic_dec.sh

OVERRIDE_TARGETS := 1
include ../lib.mk

CURDIR := $(abspath .)
REPOROOT := $(abspath ../../../..)
TOOLSDIR := $(REPOROOT)/tools
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOLDIR := $(TOOLSDIR)/bpf/bpftool
APIDIR := $(TOOLSINCDIR)/uapi
GENDIR := $(REPOROOT)/include/generated

OUTPUT_DIR := $(OUTPUT)/build
OBJ_DIR := $(OUTPUT_DIR)/obj
INCLUDE_DIR := $(OUTPUT_DIR)/include
BPFOBJ_DIR := $(OBJ_DIR)/libbpf
BPFOBJ := $(BPFOBJ_DIR)/libbpf.a
LIBBPF_OUTPUT := $(BPFOBJ)
BPF_OBJ_DIR := $(OBJ_DIR)/iosched_ext

DEFAULT_BPFTOOL := $(OUTPUT_DIR)/host/sbin/bpftool
HOST_OBJ_DIR := $(OBJ_DIR)/host/bpftool
HOST_LIBBPF_OUTPUT := $(OBJ_DIR)/host/libbpf/
HOST_LIBBPF_DESTDIR := $(OUTPUT_DIR)/host/
HOST_DESTDIR := $(OUTPUT_DIR)/host/

VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux) \
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux) \
		     ../../../../vmlinux \
		     /sys/kernel/btf/vmlinux \
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux for VMLINUX_BTF at any of "$(VMLINUX_BTF_PATHS)")
endif

BPFTOOL ?= $(DEFAULT_BPFTOOL)

CFLAGS += -g -O2 -Wall -Werror -I$(INCLUDE_DIR) -I$(GENDIR) \
	  -I$(LIBDIR) -I$(TOOLSINCDIR) -I$(APIDIR)
LDFLAGS = -lelf -lz -lzstd

IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null | \
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')

define get_sys_includes
$(shell $(1) $(2) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
endef

ifneq ($(CROSS_COMPILE),)
CLANG_TARGET_ARCH = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif

CLANG_SYS_INCLUDES = $(call get_sys_includes,$(CLANG),$(CLANG_TARGET_ARCH))
BPF_CFLAGS = -g -D__TARGET_ARCH_$(SRCARCH) \
	     $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian) \
	     -I$(INCLUDE_DIR) -I$(APIDIR) -I$(TOOLSINCDIR) \
	     -I$(REPOROOT)/include $(CLANG_SYS_INCLUDES) \
	     -Wall -Wno-compare-distinct-pointer-types \
	     -Wno-incompatible-function-pointer-types \
	     -Wno-microsoft-anon-tag -fms-extensions -O2 -mcpu=v3

MAKE_DIRS := $(sort $(OUTPUT_DIR) $(OBJ_DIR)/libbpf $(OBJ_DIR)/bpftool $(HOST_OBJ_DIR) \
	       $(INCLUDE_DIR) $(BPF_OBJ_DIR))

$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
	   $(APIDIR)/linux/bpf.h | $(OBJ_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(OBJ_DIR)/libbpf/ \
		    ARCH=$(ARCH) CC="$(CC)" CROSS_COMPILE=$(CROSS_COMPILE) \
		    EXTRA_CFLAGS='-g -O0 -fPIC' \
		    DESTDIR=$(OUTPUT_DIR) prefix= all install_headers

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) \
		    $(LIBBPF_OUTPUT) | $(HOST_OBJ_DIR)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR) \
		    ARCH= CROSS_COMPILE= CC=$(HOSTCC) LD=$(HOSTLD) \
		    EXTRA_CFLAGS='-g -O0' OUTPUT=$(HOST_OBJ_DIR)/ \
		    LIBBPF_OUTPUT=$(HOST_LIBBPF_OUTPUT) \
		    LIBBPF_DESTDIR=$(HOST_LIBBPF_DESTDIR) \
		    prefix= DESTDIR=$(HOST_DESTDIR) install-bin

$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(BPF_OBJ_DIR)/%.bpf.o: %.bpf.c $(INCLUDE_DIR)/vmlinux.h | $(BPFOBJ) $(BPF_OBJ_DIR)
	$(call msg,CLNG-BPF,,$(notdir $@))
	$(Q)$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

$(INCLUDE_DIR)/%.bpf.skel.h: $(BPF_OBJ_DIR)/%.bpf.o $(INCLUDE_DIR)/vmlinux.h $(BPFTOOL) | $(INCLUDE_DIR)
	$(call msg,GEN-SKEL,,$(notdir $@))
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked1.o) $<
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked2.o) $(<:.o=.linked1.o)
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked3.o) $(<:.o=.linked2.o)
	$(Q)diff $(<:.o=.linked2.o) $(<:.o=.linked3.o)
	$(Q)$(BPFTOOL) gen skeleton $(<:.o=.linked3.o) name $(subst .bpf.skel.h,,$(notdir $@)) > $@

$(OUTPUT)/bio_merge: bio_merge.c $(INCLUDE_DIR)/bio_merge.bpf.skel.h $(BPFOBJ) | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(BPFOBJ) $(LDFLAGS)

.DEFAULT_GOAL := all

.DELETE_ON_ERROR:
.SECONDARY:

override define CLEAN
	rm -rf $(OUTPUT_DIR)
	rm -f $(TEST_GEN_PROGS)
endef
