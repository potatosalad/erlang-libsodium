# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT = libsodium

# Configuration.

C_SRC_DIR ?= $(CURDIR)
C_SRC_ENV ?= $(C_SRC_DIR)/env.mk
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT)_drv
C_SRC_TYPE ?= shared

# System type and C compiler/flags.

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

ifeq ($(PLATFORM),msys2)
# We hardcode the compiler used on MSYS2. The default CC=cc does
# not produce working code. The "gcc" MSYS2 package also doesn't.
	CC = /mingw64/bin/gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),darwin)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -arch x86_64 -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -arch x86_64 -fstack-protector -Wall
	LDFLAGS ?= -arch x86_64 -flat_namespace -undefined suppress
else ifeq ($(PLATFORM),freebsd)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),solaris)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
	LDLIBS ?= -lssp
endif

ifneq ($(PLATFORM),msys2)
	CFLAGS += -fPIC
	CXXFLAGS += -fPIC
endif

CFLAGS += -I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" -I"$(LIBSODIUM_DIR)/src/libsodium/include"
CXXFLAGS += -I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" -I"$(LIBSODIUM_DIR)/src/libsodium/include"

LDLIBS += -L"$(ERL_INTERFACE_LIB_DIR)" -lei "$(LIBSODIUM_OUTPUT_FILE)"

LIBSODIUM_VSN ?= 1.0.11
LIBSODIUM_DIR ?= $(BASEDIR)/.libsodium
LIBSODIUM_GIT ?= git://github.com/jedisct1/libsodium.git
LIBSODIUM_OUTPUT_FILE ?= $(LIBSODIUM_DIR)/src/libsodium/.libs/libsodium.a
LIBSODIUM_CONFIGURE_FILE ?= $(LIBSODIUM_DIR)/configure
LIBSODIUM_MAKE_FILE ?= $(LIBSODIUM_DIR)/Makefile

# Verbosity.

V ?= 0

verbose_0 = @
verbose_2 = set -x;
verbose = $(verbose_$(V))

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))

dep_verbose_0 = @echo " DEP   " $(1);
dep_verbose_2 = set -x;
dep_verbose = $(dep_verbose_$(V))

gen_verbose_0 = @echo " GEN   " $@;
gen_verbose_2 = set -x;
gen_verbose = $(gen_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

# Targets.

core_find = $(if $(wildcard $1),$(shell find $(1:%/=%) -type f -name $(subst *,\*,$2)))

ifeq ($(SOURCES),)
	SOURCES := $(sort $(foreach pat,*.c *.C *.cc *.cpp,$(call core_find,$(C_SRC_DIR)/,$(pat))))
endif
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

.PHONY: platform

all:: deps app

app:: $(C_SRC_OUTPUT_FILE)

ifneq ($(wildcard $(LIBSODIUM_OUTPUT_FILE)),)

deps::

else

deps:: $(LIBSODIUM_OUTPUT_FILE)

endif

test-build:: $(C_SRC_OUTPUT_FILE)

$(LIBSODIUM_DIR):
	$(verbose) if [ ! -f $(LIBSODIUM_DIR)/autogen.sh ]; then \
		git clone -n $(LIBSODIUM_GIT) $(LIBSODIUM_DIR) && \
		(cd $(LIBSODIUM_DIR) && git checkout -q $(LIBSODIUM_VSN)); \
	else \
		true; \
	fi

$(LIBSODIUM_CONFIGURE_FILE): $(LIBSODIUM_DIR)
	$(verbose) if [ ! -f $(LIBSODIUM_CONFIGURE_FILE) ]; then \
		(cd $(LIBSODIUM_DIR) && chmod +x autogen.sh && ./autogen.sh); \
	else \
		true; \
	fi

$(LIBSODIUM_MAKE_FILE): $(LIBSODIUM_CONFIGURE_FILE)
	$(verbose) if [ ! -f $(LIBSODIUM_MAKE_FILE) ]; then \
		(cd $(LIBSODIUM_DIR) && ./configure --disable-pie --enable-opt); \
	else \
		true; \
	fi

$(LIBSODIUM_OUTPUT_FILE): $(LIBSODIUM_MAKE_FILE)
	$(MAKE) -C $(LIBSODIUM_DIR)

$(C_SRC_OUTPUT_FILE): $(OBJECTS)
	$(verbose) mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) $(OBJECTS) \
		$(LDFLAGS) $(if $(filter $(C_SRC_TYPE),shared),-shared) $(LDLIBS) \
		-o $(C_SRC_OUTPUT_FILE)

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
	$(gen_verbose) rm -f $(C_SRC_OUTPUT_FILE) $(OBJECTS) $(C_SRC_ENV)

ifneq ($(wildcard $(C_SRC_ENV)),)
-include $(C_SRC_ENV)
else
ERTS_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)]).")
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)]).")
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)]).")
endif
