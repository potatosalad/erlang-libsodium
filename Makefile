PROJECT = libsodium
PROJECT_DESCRIPTION = libsodium NIF for Erlang and Elixir
PROJECT_VERSION = 2.0.0

HEX_TARBALL_FILES = Makefile erlang.mk rebar.config rebar.lock ex_doc.config README.md CHANGELOG.md LICENSE.md \
	$(shell git ls-files c_src c_deps/libsodium src)

include erlang.mk

# Common Test excludes failed cleanup callbacks from its exit status counters.
CT_RUN := rm -f "$(CT_LOGS_DIR)/junit_report.xml" && $(CT_RUN) \
	-ct_hooks cth_surefire '[{path,"$(CT_LOGS_DIR)/junit_report.xml"}]' \
	-halt_with libsodium_ct halt

.PHONY: ex-doc

docs:: ex-doc

ex-doc: app
	$(verbose) rebar3 ex_doc

.PHONY: eqwalize eqwalize-all distclean-elp

# Arch detection.

ifeq ($(ARCH),)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),amd64)
ARCH = x86_64
else ifeq ($(UNAME_M),x86_64)
ARCH = x86_64
else ifeq ($(UNAME_M),arm64)
ARCH = aarch64
else ifeq ($(UNAME_M),aarch64)
ARCH = aarch64
else
$(error Unable to detect architecture. Please open a ticket with the output of uname -s.)
endif

export ARCH
endif

# Configuration.
ELP_VERSION ?= 2026-10-14
ELP_OTP_VERSION ?= 29.1

ELP ?= $(CURDIR)/elp
export ELP

ifeq ($(PLATFORM),darwin)
	ELP_URL ?= https://github.com/WhatsApp/erlang-language-platform/releases/download/${ELP_VERSION}/elp-macos-${ARCH}-apple-darwin-otp-${ELP_OTP_VERSION}.tar.gz
else
	ELP_URL ?= https://github.com/WhatsApp/erlang-language-platform/releases/download/${ELP_VERSION}/elp-linux-${ARCH}-unknown-linux-gnu-otp-${ELP_OTP_VERSION}.tar.gz
endif

ELP_OPTS ?=
ELP_BUILD_DIR ?= $(CURDIR)/_elp_build
ELP_ARCHIVE = elp-$(ELP_VERSION).tar.gz

# Core targets.

help::
	$(verbose) printf "%s\n" "" \
		"elp targets:" \
		"  eqwalize     Run 'elp eqwalize libsodium' on the current project" \
		"  eqwalize-all Run 'elp eqwalize-all' on the current project"

distclean:: distclean-elp

# Plugin-specific targets.

$(ELP):
	$(verbose) mkdir -p $(ELP_BUILD_DIR)
	$(verbose) echo "Downloading ELP and eqwalizer from: "$(ELP_URL)
	$(verbose) $(call core_http_get,$(ELP_BUILD_DIR)/$(ELP_ARCHIVE),$(ELP_URL))
	$(verbose) cd $(ELP_BUILD_DIR) && \
		tar -xzf $(ELP_ARCHIVE)
	$(gen_verbose) cp $(ELP_BUILD_DIR)/elp $(ELP)
	$(verbose) chmod +x $(ELP)
	$(verbose) rm -rf $(ELP_BUILD_DIR)

eqwalize: $(ELP)
	$(verbose) $(ELP) eqwalize $(PROJECT) --bail-on-error

eqwalize-all: $(ELP)
	$(verbose) $(ELP) eqwalize-all --bail-on-error

distclean-elp:
	$(gen_verbose) rm -rf $(ELP)

.PHONY: erlfmt erlfmt-check distclean-erlfmt format

# Configuration.
ERLFMT_VERSION ?= 1.8.0

ERLFMT ?= $(CURDIR)/erlfmt
export ERLFMT

ERLFMT_URL ?= https://github.com/WhatsApp/erlfmt/archive/refs/tags/v$(ERLFMT_VERSION).tar.gz
ERLFMT_OPTS ?=
ERLFMT_BUILD_DIR ?= $(CURDIR)/_erlfmt_build
ERLFMT_CODE_ARCHIVE = $(ERLFMT_VERSION).tar.gz

ERLFMT_REBAR3_VERSION ?= 3.28.0
ERLFMT_REBAR3_URL ?= https://github.com/erlang/rebar3/releases/download/$(ERLFMT_REBAR3_VERSION)/rebar3
ERLFMT_REBAR3 ?= rebar3

# Core targets.

help::
	$(verbose) printf "%s\n" "" \
		"erlfmt targets:" \
		"  erlfmt       Run erlfmt or download the default otherwise" \
		"  erlfmt-check Run erlfmt --check"

distclean:: distclean-erlfmt

# Plugin-specific targets.

$(ERLFMT):
	$(verbose) mkdir -p $(ERLFMT_BUILD_DIR)
ifeq ($(shell command -v $(ERLFMT_REBAR3)),)
	$(verbose) echo "Downloading Rebar3 from: "$(ERLFMT_REBAR3_URL)
	$(verbose) $(call core_http_get,$(ERLFMT_BUILD_DIR)/rebar3,$(ERLFMT_REBAR3_URL))
	$(verbose) chmod +x $(ERLFMT_BUILD_DIR)/rebar3
	$(eval ERLFMT_REBAR3 := $(ERLFMT_BUILD_DIR)/rebar3)
else
	$(verbose) echo "Using Rebar3: "$(ERLFMT_REBAR3)
endif
	$(verbose) echo "Downloading erlfmt from: "$(ERLFMT_URL)
	$(verbose) $(call core_http_get,$(ERLFMT_BUILD_DIR)/$(ERLFMT_CODE_ARCHIVE),$(ERLFMT_URL))
	$(verbose) cd $(ERLFMT_BUILD_DIR) && \
		tar -xzf $(ERLFMT_CODE_ARCHIVE) && \
		cd erlfmt-$(ERLFMT_VERSION) && \
		$(ERLFMT_REBAR3) as release escriptize
	$(gen_verbose) cp $(ERLFMT_BUILD_DIR)/erlfmt-$(ERLFMT_VERSION)/_build/release/bin/erlfmt $(ERLFMT)
	$(verbose) chmod +x $(ERLFMT)
	$(verbose) rm -rf $(ERLFMT_BUILD_DIR)/erlfmt-$(ERLFMT_VERSION)
	$(verbose) rm $(ERLFMT_BUILD_DIR)/$(ERLFMT_CODE_ARCHIVE)
	$(verbose) rm -f $(ERLFMT_BUILD_DIR)/rebar3
	$(verbose) rm -rf $(ERLFMT_BUILD_DIR)

erlfmt: $(ERLFMT)
	$(verbose) $(ERLFMT) --verbose --write --require-pragma --print-width=120 \
		'{src,include,test}/**/*.{hrl,erl,app.src}' \
		'test/**/*.config' \
		'{rebar.config,rebar.config.script}'

erlfmt-check: $(ERLFMT)
	$(verbose) $(ERLFMT) --check --require-pragma --print-width=120 \
		'{src,include,test}/**/*.{hrl,erl,app.src,app.src.script}' \
		'test/**/*.config' \
		'{rebar.config,rebar.config.script}'

distclean-erlfmt:
	$(gen_verbose) rm -rf $(ERLFMT)

format: $(ERLFMT)
	$(verbose) $(MAKE) -C $(CURDIR)/c_src format
	$(verbose) $(MAKE) erlfmt

.PHONY: lint lint-dialyzer lint-eqwalizer lint-format lint-xref

lint:: lint-format lint-eqwalizer lint-xref lint-dialyzer

lint-dialyzer:
	$(verbose) rebar3 as test dialyzer

lint-eqwalizer: eqwalize-all

lint-format: erlfmt-check
	$(verbose) $(MAKE) -C $(CURDIR)/c_src lint-format

lint-xref:
	$(verbose) rebar3 xref
