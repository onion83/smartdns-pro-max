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

# libcurl: prefer locally built static lib, fallback to system
LOCAL_CURL_DIR ?= ../third_party/curl/install
LOCAL_CURL_LIB := $(shell ls $(LOCAL_CURL_DIR)/lib/libcurl.a 2>/dev/null)
ifdef LOCAL_CURL_LIB
  CURL_CFLAGS := -DUSE_CURL -I$(LOCAL_CURL_DIR)/include
  CURL_LDFLAGS := $(LOCAL_CURL_LIB)
  $(info Using local libcurl: $(LOCAL_CURL_LIB))
else
  HAS_SYSTEM_CURL := $(shell curl-config --libs 2>/dev/null)
  ifdef HAS_SYSTEM_CURL
    CURL_CFLAGS := -DUSE_CURL $(shell curl-config --cflags 2>/dev/null)
    CURL_LDFLAGS := -lcurl
    $(info Using system libcurl)
  else
    CURL_CFLAGS :=
    CURL_LDFLAGS :=
    $(warning libcurl not found, geosite URL download will be disabled)
  endif
endif

# Static OpenSSL (for fully static builds with musl)
LOCAL_OPENSSL_DIR ?= ../third_party/openssl/install
LOCAL_OPENSSL_LIB := $(shell ls $(LOCAL_OPENSSL_DIR)/lib/libssl.a 2>/dev/null)
ifdef LOCAL_OPENSSL_LIB
  override CFLAGS += -I$(LOCAL_OPENSSL_DIR)/include
  ifdef STATIC
    # In static mode, link against static OpenSSL instead of system -lssl/-lcrypto
    SSL_LDFLAGS := $(LOCAL_OPENSSL_LIB) $(LOCAL_OPENSSL_DIR)/lib/libcrypto.a
    $(info Using local static OpenSSL: $(LOCAL_OPENSSL_LIB))
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

override CFLAGS +=-Iinclude
override CFLAGS += -DBASE_FILE_NAME='"$(notdir $<)"'
override CFLAGS += $(EXTRA_CFLAGS)

ifdef VER
 override CFLAGS += -DSMARTDNS_VERSION='"$(VER)"'
endif

override CFLAGS += $(CURL_CFLAGS)
override LDFLAGS += $(CURL_LDFLAGS)

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

ifdef STATIC
 override CFLAGS += -DBUILD_STATIC
 ifdef SSL_LDFLAGS
  override LDFLAGS += $(SSL_LDFLAGS) -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldl -lm -lz -static -rdynamic
 else
  override LDFLAGS += -lssl -lcrypto -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldl -lm -lz -static -rdynamic
 endif
else
 override LDFLAGS += -lssl -lcrypto -lpthread -ldl -lm -rdynamic
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

