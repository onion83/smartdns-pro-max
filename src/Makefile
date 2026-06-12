# Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
#
# smartdns is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# smartdns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

BIN=smartdns
SMARTDNS_LIB=libsmartdns.a
SMARTDNS_TEST_LIB=libsmartdns-test.a
# libs without main.o
OBJS=$(filter-out main.o, $(patsubst %.c,%.o,$(wildcard *.c)) $(patsubst %.c,%.o,$(wildcard */*.c)))
# libs without lib/%.o
LINT_OBJS=$(filter-out lib/%.o, $(OBJS))
TEST_OBJS=$(patsubst %.o,%_test.o,$(OBJS))
MAIN_OBJ = main.o

# ============================================================================
# Dependency detection: OpenSSL + libcurl
# Priority: LOCAL_DEPS_PREFIX (/opt) > ../third_party/ > system (if allowed)
# ============================================================================

# --- OpenSSL detection ---
# Search order: LOCAL_DEPS_PREFIX/openssl > ../third_party/openssl/install > system
OPENSSL_PREFIX :=
ifdef LOCAL_DEPS_PREFIX
  ifneq ("$(wildcard $(LOCAL_DEPS_PREFIX)/openssl/include/openssl/ssl.h)","")
    OPENSSL_PREFIX := $(LOCAL_DEPS_PREFIX)/openssl
    $(info OpenSSL: using custom prefix $(OPENSSL_PREFIX))
  endif
endif
ifndef OPENSSL_PREFIX
  ifneq ("$(wildcard ../third_party/openssl/install/include/openssl/ssl.h)","")
    OPENSSL_PREFIX := ../third_party/openssl/install
    $(info OpenSSL: using third_party prefix $(OPENSSL_PREFIX))
  endif
endif
ifndef OPENSSL_PREFIX
  ifeq ($(USE_SYSTEM_LIBS), 1)
    HAS_SYSTEM_OPENSSL := $(shell pkg-config --exists openssl 2>/dev/null && echo 1 || echo 0)
    ifeq ($(HAS_SYSTEM_OPENSSL), 1)
      OPENSSL_PREFIX := /usr
      $(info OpenSSL: using system prefix)
    endif
  endif
endif
ifndef OPENSSL_PREFIX
  $(error OpenSSL not found. Install to $$(LOCAL_DEPS_PREFIX)/openssl or ../third_party/openssl/install, or set USE_SYSTEM_LIBS=1)
endif

# OpenSSL link mode: prefer shared if available (for dynamic builds), fallback to static
OPENSSL_LIBDIR := $(OPENSSL_PREFIX)/lib
ifneq ("$(wildcard $(OPENSSL_LIBDIR)/libssl.so)","")
  # Shared OpenSSL found
  SSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
  SSL_LDFLAGS := -L$(OPENSSL_LIBDIR) -lssl -lcrypto
  SSL_RPATH := -Wl,-rpath,$(OPENSSL_LIBDIR)
  $(info OpenSSL: dynamic linking from $(OPENSSL_LIBDIR))
else ifneq ("$(wildcard $(OPENSSL_LIBDIR)/libssl.a)","")
  # Static OpenSSL found
  SSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
  SSL_LDFLAGS := $(OPENSSL_LIBDIR)/libssl.a $(OPENSSL_LIBDIR)/libcrypto.a
  SSL_RPATH :=
  $(info OpenSSL: static linking from $(OPENSSL_LIBDIR))
else
  $(error OpenSSL libraries not found in $(OPENSSL_LIBDIR))
endif

# --- libcurl detection ---
# Search order: LOCAL_DEPS_PREFIX/curl > ../third_party/curl/install > system
CURL_PREFIX :=
ifdef LOCAL_DEPS_PREFIX
  ifneq ("$(wildcard $(LOCAL_DEPS_PREFIX)/curl/include/curl/curl.h)","")
    CURL_PREFIX := $(LOCAL_DEPS_PREFIX)/curl
    $(info libcurl: using custom prefix $(CURL_PREFIX))
  endif
endif
ifndef CURL_PREFIX
  ifneq ("$(wildcard ../third_party/curl/install/include/curl/curl.h)","")
    CURL_PREFIX := ../third_party/curl/install
    $(info libcurl: using third_party prefix $(CURL_PREFIX))
  endif
endif
ifndef CURL_PREFIX
  ifeq ($(USE_SYSTEM_LIBS), 1)
    HAS_SYSTEM_CURL := $(shell curl-config --libs 2>/dev/null)
    ifdef HAS_SYSTEM_CURL
      CURL_PREFIX := /usr
      $(info libcurl: using system prefix)
    endif
  endif
endif

ifeq ("$(CURL_PREFIX)","")
  CURL_CFLAGS :=
  CURL_LDFLAGS :=
  $(warning libcurl not found, geosite URL download will be disabled)
else
  # libcurl link mode: prefer shared if available, fallback to static
  CURL_LIBDIR := $(CURL_PREFIX)/lib
  ifneq ("$(wildcard $(CURL_LIBDIR)/libcurl.so)","")
    # Shared libcurl found
    CURL_CFLAGS := -DUSE_CURL -I$(CURL_PREFIX)/include
    CURL_LDFLAGS := -L$(CURL_LIBDIR) -lcurl
    CURL_RPATH := -Wl,-rpath,$(CURL_LIBDIR)
    $(info libcurl: dynamic linking from $(CURL_LIBDIR))
  else ifneq ("$(wildcard $(CURL_LIBDIR)/libcurl.a)","")
    # Static libcurl found
    CURL_CFLAGS := -DUSE_CURL -DUSE_CURL_STATIC -I$(CURL_PREFIX)/include
    CURL_LDFLAGS := $(CURL_LIBDIR)/libcurl.a
    CURL_RPATH :=
    $(info libcurl: static linking from $(CURL_LIBDIR))
  else
    $(error libcurl libraries not found in $(CURL_LIBDIR))
  endif
endif

ifeq ($(filter -j,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc)
endif

# cflags
ifndef CFLAGS
 ifdef DEBUG
  CFLAGS = -g -DDEBUG
 else
  CFLAGS = -O2
 endif
 CFLAGS +=-Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables -Wmissing-prototypes -Wshadow -Wextra -Wno-unused-parameter -Wno-implicit-fallthrough
endif

HASH := \#
HAS_UNWIND := $(shell printf '$(HASH)include <unwind.h>\nvoid main() { _Unwind_Backtrace(0, 0);}' | $(CC) -x c - -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(HAS_UNWIND), 1)
override CFLAGS += -DHAVE_UNWIND_BACKTRACE
endif

WITH_ZLIB ?= auto
HAS_ZLIB := $(shell printf '$(HASH)include <zlib.h>\nint main(void) { return zlibVersion()[0] == 0; }' | $(CC) -x c - -lz -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(WITH_ZLIB), yes)
override WITH_ZLIB := 1
endif
ifeq ($(WITH_ZLIB), auto)
 ifeq ($(HAS_ZLIB), 1)
  override CFLAGS += -DWITH_ZLIB
  override LDFLAGS += -lz
 endif
else ifeq ($(WITH_ZLIB), 1)
override CFLAGS += -DWITH_ZLIB
override LDFLAGS += -lz
endif

override CFLAGS +=-Iinclude
override CFLAGS += -DBASE_FILE_NAME=\"$(notdir $<)\"
override CFLAGS += $(EXTRA_CFLAGS)

ifdef VER
 override CFLAGS += -DSMARTDNS_VERSION='"$(VER)"'
endif

# Assemble CFLAGS: add OpenSSL and libcurl includes
override CFLAGS += $(SSL_CFLAGS) $(CURL_CFLAGS)

# Assemble LDFLAGS: add RPATH for dynamic libraries
# RPATH ensures the runtime linker finds shared libs from custom prefixes
# Note: musl libc's dynamic linker ignores RPATH/RUNPATH.
#       For musl targets, shared libs must be in /lib or /usr/lib (or set /etc/ld-musl-*.path).
ifdef SSL_RPATH
  override LDFLAGS += $(SSL_RPATH)
endif
ifdef CURL_RPATH
  override LDFLAGS += $(CURL_RPATH)
endif

HAS_GIT := $(shell command -v git 2> /dev/null)
ifndef NO_GIT_VER
 ifdef HAS_GIT
  IS_GIT_REPO := $(shell git rev-parse --is-inside-work-tree 2>/dev/null)
  ifdef IS_GIT_REPO
   override COMMIT_VERSION = $(shell git describe --tags --always --dirty)
  endif
 endif
endif

ifdef COMMIT_VERSION
 override CFLAGS += -DCOMMIT_VERSION='"$(shell git describe --tags --always --dirty)"'
endif

CXXFLAGS=-O2 -g -Wall -std=c++11 
override CXXFLAGS +=-Iinclude

ifeq ($(STATIC), yes)
STATIC = 1
endif

# Link mode selection
# SSL_LDFLAGS and CURL_LDFLAGS are already set by the detection logic above.
# They may be:
#   - dynamic: -L/path -lssl -lcrypto  (RPATH already added to LDFLAGS)
#   - static:  /path/libssl.a /path/libcrypto.a
# In static/hybrid mode, we force static linking of ssl/curl/zlib.
# In dynamic mode, we use whatever SSL_LDFLAGS/CURL_LDFLAGS provide.

ifdef STATIC
  # Fully static build: all libraries linked statically
 override CFLAGS += -DBUILD_STATIC
 override LDFLAGS += $(SSL_LDFLAGS) $(CURL_LDFLAGS) -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldl -lm -lz -static -rdynamic
else ifdef STATIC_DEPS
  # Hybrid build: static ssl/curl/zlib, dynamic libc+libgcc_s (for dlopen plugin support)
  # Keep libgcc_s DYNAMIC so .so plugins can resolve _Unwind_* symbols from it at runtime
 override CFLAGS += -DBUILD_STATIC_DEPS
  # Force static linking for ssl/curl/zlib even if shared libs are present
  ifneq ("$(wildcard $(OPENSSL_LIBDIR)/libssl.a)","")
    override LDFLAGS += $(OPENSSL_LIBDIR)/libssl.a $(OPENSSL_LIBDIR)/libcrypto.a
  else
    override LDFLAGS += $(SSL_LDFLAGS)
  endif
  # Only add curl if it was found
  ifdef CURL_PREFIX
    ifneq ("$(wildcard $(CURL_LIBDIR)/libcurl.a)","")
      override LDFLAGS += $(CURL_LIBDIR)/libcurl.a
    else
      override LDFLAGS += $(CURL_LDFLAGS)
    endif
  endif
 override LDFLAGS += -Wl,-Bstatic -lz -Wl,-Bdynamic -lpthread -ldl -lm -rdynamic
else
  # Dynamic build: use detected SSL_LDFLAGS and CURL_LDFLAGS as-is
  # RPATH already added to LDFLAGS above
 override LDFLAGS += $(SSL_LDFLAGS) $(CURL_LDFLAGS) -lpthread -ldl -lm -lz -rdynamic
endif

USE_ATOMIC := $(shell printf '$(HASH)include <stdint.h>\nvoid main() { uint64_t value=0;__atomic_add_fetch(&value, 1, __ATOMIC_SEQ_CST);__atomic_load_n(&value,__ATOMIC_SEQ_CST);}' | $(CC) -x c - -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(USE_ATOMIC), 0)
 override CFLAGS += -DUSE_ATOMIC
 override LDFLAGS += -latomic 
endif

override LDFLAGS += $(EXTRA_LDFLAGS)

.PHONY: all clean build-curl

all: $(BIN)

build-curl:
	@echo "Building libcurl static library..."
	../third_party/build_curl.sh

%_test.o: %.c
	$(CC) -DTEST $(CFLAGS) -c $< -o $@

$(BIN) : $(MAIN_OBJ) $(SMARTDNS_LIB)
	$(CC) $^ -o $@ $(LDFLAGS)

$(SMARTDNS_TEST_LIB): $(TEST_OBJS)
	$(AR) rcs $@ $^

$(SMARTDNS_LIB): $(OBJS)
	$(AR) rcs $@ $^

clang-tidy-parallel:
	@echo "Running clang-tidy with $(shell nproc) parallel jobs..."
	@printf '%s\n' $(LINT_OBJS:.o=.c) | xargs -P $(shell nproc) -I {} clang-tidy {} -- $(CFLAGS)

clang-tidy:
	clang-tidy -p=. $(LINT_OBJS:.o=.c) -- $(CFLAGS)

clean:
	$(RM) $(OBJS) $(BIN) $(SMARTDNS_LIB) $(MAIN_OBJ) $(SMARTDNS_TEST_LIB) $(TEST_OBJS)

# lint specific files
# make lint-files FILES="dns.c proxy.c"
lint-files:
	@echo "Specify FILES variable to lint specific files, e.g., make lint-files FILES='src/dns.c src/proxy.c'"
	clang-tidy -p=. $(FILES) -- $(CFLAGS)
