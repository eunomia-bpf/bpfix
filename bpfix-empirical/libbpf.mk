# Shared local libbpf build for bpfix-empirical selftest loaders.
#
# Case Makefiles are executed from bpfix-empirical/cases/<case_id>, so the default
# empirical corpus root is two directories up from the case directory.

BENCH_ROOT ?= $(abspath ../..)
REPO_ROOT ?= $(abspath $(BENCH_ROOT)/..)

LIBBPF_SRC ?= $(REPO_ROOT)/vendor/libbpf/src
LIBBPF_BUILD ?= $(REPO_ROOT)/target/bpfix-empirical/libbpf-build
LIBBPF_INSTALL ?= $(REPO_ROOT)/target/bpfix-empirical/libbpf-install
LIBBPF_OBJ ?= $(LIBBPF_INSTALL)/libbpf.a
LIBBPF_INCLUDE ?= $(LIBBPF_INSTALL)
LIBBPF_UAPI_INCLUDE ?= $(LIBBPF_SRC)/../include/uapi

LOADER_CFLAGS ?= -O2 -Wall -Wextra -Werror -I$(LIBBPF_INCLUDE) -I$(LIBBPF_UAPI_INCLUDE)
LOADER_LDLIBS ?= -lelf -lz

$(LIBBPF_BUILD) $(LIBBPF_INSTALL):
	mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_BUILD) $(LIBBPF_INSTALL)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_BUILD) \
		DESTDIR=$(LIBBPF_INSTALL) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install
