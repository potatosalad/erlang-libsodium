# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT = libsodium

# Configuration.

C_SRC_DIR ?= $(CURDIR)
C_SRC_ENV ?= $(C_SRC_DIR)/env.mk
C_SRC_OUTPUT ?= $(BASEDIR)/priv/$(PROJECT)_nif
C_SRC_TYPE ?= shared

C_DEPS_DIR ?= $(BASEDIR)/c_deps

SANITIZE ?= 0
CFLAGS_SANITIZE ?= -O1 -fsanitize=address,undefined -fno-common -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-sanitize-recover=all
CXXFLAGS_SANITIZE ?= $(CFLAGS_SANITIZE)
LDFLAGS_SANITIZE ?= -fsanitize=address,undefined

# "erl" command.

ERL_CMD ?= erl
ERL = $(ERL_CMD) +A1 -noinput -boot no_dot_erlang

# Platform detection.

ifeq ($(PLATFORM),)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
PLATFORM = linux
else ifeq ($(UNAME_S),Darwin)
PLATFORM = darwin
else ifeq ($(UNAME_S),SunOS)
PLATFORM = solaris
else ifeq ($(UNAME_S),GNU)
PLATFORM = gnu
else ifeq ($(UNAME_S),FreeBSD)
PLATFORM = freebsd
else ifeq ($(UNAME_S),NetBSD)
PLATFORM = netbsd
else ifeq ($(UNAME_S),OpenBSD)
PLATFORM = openbsd
else ifeq ($(UNAME_S),DragonFly)
PLATFORM = dragonfly
else ifeq ($(shell uname -o),Msys)
PLATFORM = msys2
else
$(error Unable to detect platform. Please open a ticket with the output of uname -a.)
endif

export PLATFORM
endif

# System type and C compiler/flags.

ifeq ($(PLATFORM),msys2)
	C_SRC_OUTPUT_EXECUTABLE_EXTENSION ?= .exe
	C_SRC_OUTPUT_SHARED_EXTENSION ?= .dll
else
	C_SRC_OUTPUT_EXECUTABLE_EXTENSION ?=
	C_SRC_OUTPUT_SHARED_EXTENSION ?= .so
endif

ifeq ($(C_SRC_TYPE),shared)
	C_SRC_OUTPUT_FILE = $(C_SRC_OUTPUT)$(C_SRC_OUTPUT_SHARED_EXTENSION)
else
	C_SRC_OUTPUT_FILE = $(C_SRC_OUTPUT)$(C_SRC_OUTPUT_EXECUTABLE_EXTENSION)
endif

CFLAGS_COMMON ?= \
-O2 \
-g \
-ggdb \
-std=c2x \
-finline-functions \
-fno-omit-frame-pointer \
-D_GNU_SOURCE \
-D_REENTRANT

CXXFLAGS_COMMON ?= \
-O2 \
-g \
-ggdb \
-std=c++20 \
-finline-functions \
-fno-omit-frame-pointer \
-D_GLIBCXX_RESTRICT_EXCEPTIONS \
-D_GNU_SOURCE \
-D_REENTRANT

ifeq ($(PLATFORM),msys2)
# We hardcode the compiler used on MSYS2. The default CC=cc does
# not produce working code. The "gcc" MSYS2 package also doesn't.
	CC = /mingw64/bin/gcc
	export CC
	CXX = /mingw64/bin/g++
	export CXX
	CFLAGS ?= $(CFLAGS_COMMON) -Wall
	CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
else
# Determine whether `clang` is available
	CLANG_AVAILABLE := $(shell command -v clang >/dev/null 2>&1 && echo yes)
	ifneq ($(CLANG_AVAILABLE),)
		CC ?= clang
		CXX ?= clang++
	else ifeq ($(PLATFORM),linux)
		CC ?= gcc
		CXX ?= g++
	else
		CC ?= cc
		CXX ?= c++
	endif
	ifeq ($(PLATFORM),darwin)
		CFLAGS ?= $(CFLAGS_COMMON) -Wall
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
		LDFLAGS ?= -flat_namespace -undefined dynamic_lookup
	else ifeq ($(PLATFORM),freebsd)
		CFLAGS ?= $(CFLAGS_COMMON) -Wall
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
	else ifeq ($(PLATFORM),linux)
		CFLAGS ?= $(CFLAGS_COMMON) -Wall
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
	else ifeq ($(PLATFORM),solaris)
		CFLAGS ?= $(CFLAGS_COMMON) -fstack-protector
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -fstack-protector
	endif
endif

ifneq ($(PLATFORM),msys2)
	CFLAGS += -fPIC
	CXXFLAGS += -fPIC
endif

ifneq ($(CROSSCOMPILER),)
	CC = $(CROSSCOMPILER)gcc
	CXX = $(CROSSCOMPILER)g++
endif

ifeq ($(SANITIZE),1)
	CFLAGS += $(CFLAGS_SANITIZE)
	CXXFLAGS += $(CXXFLAGS_SANITIZE)
	LDFLAGS += $(LDFLAGS_SANITIZE)
endif

CFLAGS += \
	-I"$(ERTS_INCLUDE_DIR)" \
	-I"$(LIBSODIUM_INCLUDE_DIR)"
CXXFLAGS += \
	-I"$(ERTS_INCLUDE_DIR)" \
	-I"$(LIBSODIUM_INCLUDE_DIR)"

LDLIBS += "$(LIBSODIUM_OUTPUT_FILE)"

# Dependencies.

LIBSODIUM_VSN ?= 1.0.22
LIBSODIUM_GIT ?= https://github.com/jedisct1/libsodium.git
LIBSODIUM_SRC_DIR ?= $(C_DEPS_DIR)/libsodium
LIBSODIUM_BUILD_DIR ?= $(C_DEPS_DIR)/libsodium-build$(if $(filter 1,$(SANITIZE)),-sanitizers)
LIBSODIUM_PREFIX ?= $(LIBSODIUM_BUILD_DIR)/prefix
LIBSODIUM_INCLUDE_DIR ?= $(LIBSODIUM_PREFIX)/include
LIBSODIUM_OUTPUT_FILE ?= $(LIBSODIUM_PREFIX)/lib/libsodium.a
LIBSODIUM_CONFIGURE_FILE ?= $(LIBSODIUM_SRC_DIR)/configure
LIBSODIUM_MAKE_FILE ?= $(LIBSODIUM_BUILD_DIR)/Makefile

ALL_DEPS_OUTPUT ?= $(LIBSODIUM_OUTPUT_FILE)

# Verbosity.

V ?= 0

verbose_0 = @
verbose_2 = set -x;
verbose = $(verbose_$(V))

ifeq ($(V),3)
SHELL := $(SHELL) -x
endif

gen_verbose_0 = @echo " GEN   " $@;
gen_verbose_2 = set -x;
gen_verbose = $(gen_verbose_$(V))

dep_verbose_0 = @echo " DEP   " $(@F);
dep_verbose_2 = set -x;
dep_verbose = $(dep_verbose_$(V))

c_verbose_0 = @echo " C     " $(filter-out $(notdir $(MAKEFILE_LIST) $(C_SRC_ENV)),$(^F));
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(filter-out $(notdir $(MAKEFILE_LIST) $(C_SRC_ENV)),$(^F));
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

# Targets.

ifeq ($(PLATFORM),msys2)
core_native_path = $(shell cygpath -m $1)
else
core_native_path = $1
endif

# We skip files that contain spaces because they end up causing issues.
core_find = $(if $(wildcard $1),$(shell find $(1:%/=%) \( -type l -o -type f \) -name $(subst *,\*,$2) | grep -v " "))

ifeq ($(SOURCES),)
SOURCES := $(sort $(foreach pat,*.c *.C *.cc *.cpp,$(call core_find,$(C_SRC_DIR)/nif/,$(pat))))
endif
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))
DEPFILES = $(OBJECTS:.o=.d)

ifeq ($(FORMAT_NIF_SOURCES),)
FORMAT_NIF_SOURCES := $(shell find $(C_SRC_DIR)/nif \( -type l -o -type f \) \( -name '*.c' -o -name '*.C' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.c.h' -o -name '*.hpp' \) | grep -v " ")
endif

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c

all:: deps app

app:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

deps:: $(ALL_DEPS_OUTPUT)

test-build:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

$(C_DEPS_DIR):
	$(verbose) mkdir -p $(C_DEPS_DIR)

# The vendored sources are a git checkout without the generated configure
# script (Hex packages include it); generate it with autotools when missing.
$(LIBSODIUM_CONFIGURE_FILE): | $(C_DEPS_DIR)
	$(verbose) if [ ! -f $(LIBSODIUM_SRC_DIR)/autogen.sh ]; then \
		git clone -n $(LIBSODIUM_GIT) $(LIBSODIUM_SRC_DIR) && \
		(cd $(LIBSODIUM_SRC_DIR) && git checkout -q $(LIBSODIUM_VSN)); \
	fi
	$(dep_verbose) cd $(LIBSODIUM_SRC_DIR) && ./autogen.sh -s >/dev/null

# Configure out of tree so the vendored sources stay pristine. The build is
# portable: libsodium selects optimized implementations at runtime.
$(LIBSODIUM_MAKE_FILE): $(LIBSODIUM_CONFIGURE_FILE) $(C_SRC_DIR)/Makefile
	$(verbose) mkdir -p $(LIBSODIUM_BUILD_DIR)
	$(dep_verbose) cd $(LIBSODIUM_BUILD_DIR) && "$(LIBSODIUM_CONFIGURE_FILE)" \
			--quiet \
			--disable-dependency-tracking \
			--disable-pie \
			--disable-shared \
			--enable-static \
			--with-pic \
			--prefix="$(LIBSODIUM_PREFIX)" \
			CC="$(CC)" \
			CFLAGS="-O2 -g $(if $(filter 1,$(SANITIZE)),$(CFLAGS_SANITIZE))"

$(LIBSODIUM_OUTPUT_FILE): $(LIBSODIUM_MAKE_FILE)
	$(dep_verbose) $(MAKE) -C $(LIBSODIUM_BUILD_DIR) V=0 install >/dev/null
	$(verbose) touch $@

$(C_SRC_OUTPUT_FILE): $(ALL_DEPS_OUTPUT) $(OBJECTS)
	$(verbose) mkdir -p $(dir $@)
	$(link_verbose) $(CC) $(OBJECTS) \
		$(LDFLAGS) $(if $(filter $(C_SRC_TYPE),shared),-shared) $(LDLIBS) \
		-o $(C_SRC_OUTPUT_FILE)

$(OBJECTS): $(MAKEFILE_LIST) $(C_SRC_ENV) | $(ALL_DEPS_OUTPUT)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:: clean-c_src

clean-c_src:
	$(gen_verbose) rm -f $(C_SRC_OUTPUT_FILE) $(OBJECTS) $(DEPFILES)

distclean:: distclean-c_src-env distclean-deps

distclean-c_src-env:
	$(gen_verbose) rm -f $(C_SRC_ENV)

distclean-deps:
	$(gen_verbose) rm -rf $(C_DEPS_DIR)/libsodium-build $(C_DEPS_DIR)/libsodium-build-sanitizers

format:
	$(gen_verbose) clang-format -i $(FORMAT_NIF_SOURCES)

lint-format:
	$(gen_verbose) clang-format --dry-run --Werror $(FORMAT_NIF_SOURCES)

ifneq ($(wildcard $(C_SRC_DIR)),)
ERL_ERTS_DIR = $(shell $(ERL) -eval 'io:format("~s~n", [code:lib_dir(erts)]), halt().')

$(C_SRC_ENV):
	$(verbose) $(ERL) -eval "file:write_file(\"$(call core_native_path,$(C_SRC_ENV))\", \
		io_lib:format( \
			\"# Generated by Erlang.mk. Edit at your own risk!~n~n\" \
			\"ERTS_INCLUDE_DIR ?= ~s/erts-~s/include/~n\" \
			\"ERTS_DIR ?= $(ERL_ERTS_DIR)~n\", \
			[code:root_dir(), erlang:system_info(version)])), \
		halt()."

-include $(C_SRC_ENV)

ifneq ($(ERL_ERTS_DIR),$(ERTS_DIR))
$(shell rm -f $(C_SRC_ENV))
endif

-include $(DEPFILES)
endif
