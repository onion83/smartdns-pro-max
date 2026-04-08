/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include "geosite.h"
#include "domain_rule.h"
#include "domain_set.h"
#include "dns_conf_group.h"
#include "smartdns/dns_cache.h"
#include "smartdns/lib/idna.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/eventfd.h>
#endif

#ifdef USE_CURL
#include <curl/curl.h>
#endif


#ifndef SMARTDNS_VERSION
#ifdef COMMIT_VERSION
#define SMARTDNS_VERSION_STR COMMIT_VERSION
#else
#define SMARTDNS_VERSION_STR "unknown"
#endif
#else
#define SMARTDNS_VERSION_STR SMARTDNS_VERSION
#endif

/* Geosite feature build timestamp, returns e.g. "geosite-mod-202604031335" */
const char *geosite_build_version(void)
{
	static char ver[48] = {0};
	if (ver[0] == 0) {
		char s_month[5];
		int month = 0, day = 0, year = 0, hour = 0, min = 0;
		static const char *month_names = "JanFebMarAprMayJunJulAugSepOctNovDec";
		sscanf(__DATE__, "%4s %d %d", s_month, &day, &year);
		month = (strstr(month_names, s_month) - month_names) / 3;
		sscanf(__TIME__, "%d:%d", &hour, &min);
		snprintf(ver, sizeof(ver), "geosite-mod-%.4d%.2d%.2d%.2d%.2d", year, month + 1, day, hour, min);
	}
	return ver;
}

/* Log libcurl and libssl versions with static/dynamic linkage info */
static void _geosite_log_lib_versions(void)
{
#ifdef USE_CURL
	tlog(TLOG_NOTICE, "geosite: %s (%s)", curl_version(),
#ifdef USE_CURL_STATIC
		"static"
#else
		"dynamic"
#endif
	);
#else
	tlog(TLOG_NOTICE, "geosite: libcurl not available");
#endif
}

struct geosite_dat_table geosite_dat_table;
struct geosite_set_table geosite_set_table;

/* Global geosite-updater configuration with defaults */
static struct geosite_updater_config geosite_updater = {
	.default_interval = GEOSITE_DEFAULT_UPDATE_INTERVAL,
	.diff_algo = GEOSITE_DIFF_MTIME,
	.use_etag = 0,
	.user_agent = "smartdns/" SMARTDNS_VERSION_STR,
	.data_dir = "",
	.http_timeout = 300,
	.http_retry = 2,
	.http_retry_interval = 3,
};

const struct geosite_updater_config *geosite_get_updater_config(void)
{
	return &geosite_updater;
}

static LIST_HEAD(geosite_domain_rule_list);

#ifdef __linux__
/* Async download eventfd — signals main thread when download completes */
static int geosite_download_efd = -1;
#endif

#define MAX_LINE_LEN 4096

/* CRC32 lookup table */
static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

static void _crc32_table_init(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t crc = i;
		for (int j = 0; j < 8; j++) {
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320u;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
	crc32_table_initialized = 1;
}

static uint32_t _compute_crc32(const char *filepath)
{
	if (!crc32_table_initialized) {
		_crc32_table_init();
	}

	FILE *fp = fopen(filepath, "rb");
	if (fp == NULL) {
		return 0;
	}

	uint32_t crc = 0xFFFFFFFF;
	unsigned char buf[8192];
	size_t nread;
	while ((nread = fread(buf, 1, sizeof(buf), fp)) > 0) {
		for (size_t i = 0; i < nread; i++) {
			crc = (crc >> 8) ^ crc32_table[(crc ^ buf[i]) & 0xFF];
		}
	}
	fclose(fp);
	return crc ^ 0xFFFFFFFF;
}

/* Compute MD5 hash of a file, returns hex string (32 chars + NUL) */
static int _compute_md5(const char *filepath, char *hash_out, size_t hash_len)
{
	FILE *fp = fopen(filepath, "rb");
	if (fp == NULL) {
		return -1;
	}

	/* MD5 context (RFC 1321) */
	uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
	uint64_t count = 0;
	unsigned char buffer[64];

	/* MD5 transform */
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac) { (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }
#define GG(a, b, c, d, x, s, ac) { (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }
#define HH(a, b, c, d, x, s, ac) { (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }
#define II(a, b, c, d, x, s, ac) { (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }

	static const uint32_t T[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};
	static const int r[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};
	static const int g[64] = {
		0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
		5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
		0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9
	};

	/* Process file in 64-byte blocks */
	size_t buflen = 0;
	size_t nread;
	unsigned char readbuf[8192];
	while ((nread = fread(readbuf, 1, sizeof(readbuf), fp)) > 0) {
		const unsigned char *ptr = readbuf;
		size_t remaining = nread;
		while (remaining > 0) {
			size_t to_copy = 64 - buflen;
			if (to_copy > remaining) {
				to_copy = remaining;
			}
			memcpy(buffer + buflen, ptr, to_copy);
			buflen += to_copy;
			ptr += to_copy;
			remaining -= to_copy;
			count += to_copy;

			if (buflen == 64) {
				uint32_t x[16];
				for (int i = 0; i < 16; i++) {
					x[i] = (uint32_t)buffer[i * 4] | ((uint32_t)buffer[i * 4 + 1] << 8) |
						((uint32_t)buffer[i * 4 + 2] << 16) | ((uint32_t)buffer[i * 4 + 3] << 24);
				}
				uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
				for (int i = 0; i < 64; i++) {
					if (i < 16) { FF(a, b, c, d, x[g[i]], r[i], T[i]); }
					else if (i < 32) { GG(a, b, c, d, x[g[i]], r[i], T[i]); }
					else if (i < 48) { HH(a, b, c, d, x[g[i]], r[i], T[i]); }
					else { II(a, b, c, d, x[g[i]], r[i], T[i]); }
					uint32_t tmp = d; d = c; c = b; b = a; a = tmp;
				}
				state[0] += a; state[1] += b; state[2] += c; state[3] += d;
				buflen = 0;
			}
		}
	}
	fclose(fp);

	/* Padding */
	uint64_t bits = count * 8;
	buffer[buflen++] = 0x80;
	if (buflen > 56) {
		while (buflen < 64) buffer[buflen++] = 0;
		/* Process this padding block */
		uint32_t x[16];
		for (int i = 0; i < 16; i++) {
			x[i] = (uint32_t)buffer[i * 4] | ((uint32_t)buffer[i * 4 + 1] << 8) |
				((uint32_t)buffer[i * 4 + 2] << 16) | ((uint32_t)buffer[i * 4 + 3] << 24);
		}
		uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
		for (int i = 0; i < 64; i++) {
			if (i < 16) { FF(a, b, c, d, x[g[i]], r[i], T[i]); }
			else if (i < 32) { GG(a, b, c, d, x[g[i]], r[i], T[i]); }
			else if (i < 48) { HH(a, b, c, d, x[g[i]], r[i], T[i]); }
			else { II(a, b, c, d, x[g[i]], r[i], T[i]); }
			uint32_t tmp = d; d = c; c = b; b = a; a = tmp;
		}
		state[0] += a; state[1] += b; state[2] += c; state[3] += d;
		buflen = 0;
	}
	while (buflen < 56) buffer[buflen++] = 0;
	for (int i = 0; i < 8; i++) {
		buffer[56 + i] = (unsigned char)(bits >> (i * 8));
	}
	/* Process final block */
	uint32_t x[16];
	for (int i = 0; i < 16; i++) {
		x[i] = (uint32_t)buffer[i * 4] | ((uint32_t)buffer[i * 4 + 1] << 8) |
			((uint32_t)buffer[i * 4 + 2] << 16) | ((uint32_t)buffer[i * 4 + 3] << 24);
	}
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	for (int i = 0; i < 64; i++) {
		if (i < 16) { FF(a, b, c, d, x[g[i]], r[i], T[i]); }
		else if (i < 32) { GG(a, b, c, d, x[g[i]], r[i], T[i]); }
		else if (i < 48) { HH(a, b, c, d, x[g[i]], r[i], T[i]); }
		else { II(a, b, c, d, x[g[i]], r[i], T[i]); }
		uint32_t tmp = d; d = c; c = b; b = a; a = tmp;
	}
	state[0] += a; state[1] += b; state[2] += c; state[3] += d;

#undef F
#undef G
#undef H
#undef I
#undef ROTL
#undef FF
#undef GG
#undef HH
#undef II

	/* Convert to hex string */
	unsigned char digest[16];
	for (int i = 0; i < 4; i++) {
		digest[i * 4] = (unsigned char)(state[i]);
		digest[i * 4 + 1] = (unsigned char)(state[i] >> 8);
		digest[i * 4 + 2] = (unsigned char)(state[i] >> 16);
		digest[i * 4 + 3] = (unsigned char)(state[i] >> 24);
	}

	if (hash_len < 33) {
		return -1;
	}
	for (int i = 0; i < 16; i++) {
		snprintf(hash_out + i * 2, 3, "%02x", digest[i]);
	}
	hash_out[32] = '\0';
	return 0;
}

/* Compute file hash based on configured algorithm, store as hex string in dat->file_hash */
static int _compute_file_hash(const char *filepath, enum geosite_diff_algo algo, char *hash_out, size_t hash_len)
{
	switch (algo) {
	case GEOSITE_DIFF_CRC32: {
		uint32_t crc = _compute_crc32(filepath);
		snprintf(hash_out, hash_len, "%08x", crc);
		return 0;
	}
	case GEOSITE_DIFF_MD5:
		return _compute_md5(filepath, hash_out, hash_len);
	default:
		return -1;
	}
}

/* Extract domain and filename from URL for cache file naming.
 * URL: "https://domain.com/path/to/file.list"
 *   => domain = "domain.com", filename = "file.list"
 *   => cache = "domain.com-file.list" */
static void _extract_url_parts(const char *url, char *domain, size_t domain_len, char *filename, size_t filename_len)
{
	const char *p = url;

	/* Skip scheme */
	if (strncmp(p, "https://", 8) == 0) {
		p += 8;
	} else if (strncmp(p, "http://", 7) == 0) {
		p += 7;
	}

	/* Extract domain (up to first '/' or end) */
	const char *slash = strchr(p, '/');
	if (slash != NULL) {
		size_t dlen = (size_t)(slash - p);
		if (dlen >= domain_len) {
			dlen = domain_len - 1;
		}
		memcpy(domain, p, dlen);
		domain[dlen] = '\0';
	} else {
		safe_strncpy(domain, p, domain_len);
		filename[0] = '\0';
		return;
	}

	/* Extract filename from last '/' in full URL */
	const char *last_slash = strrchr(url, '/');
	if (last_slash != NULL && *(last_slash + 1) != '\0') {
		safe_strncpy(filename, last_slash + 1, filename_len);
	} else {
		safe_strncpy(filename, "index", filename_len);
	}
}

/* Extract set name from "/geosite-set:NAME/" or "/domain-set:NAME/" */
static inline const char *_geosite_extract_set_name(const char *domain)
{
	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		return domain + sizeof("domain-set:") - 1;
	}
	if (strncmp(domain, "geosite-set:", sizeof("geosite-set:") - 1) == 0) {
		return domain + sizeof("geosite-set:") - 1;
	}
	return NULL;
}

/* Forward declaration */
static int _geosite_dat_update(struct geosite_dat *dat);

/* Domain cache management for reload diff */
static void _domain_cache_free(struct geosite_domain_cache *cache)
{
	if (cache->domains) {
		for (int i = 0; i < cache->count; i++) {
			free(cache->domains[i]);
		}
		free(cache->domains);
		cache->domains = NULL;
	}
	cache->count = 0;
}

#define DOMAIN_CACHE_CHUNK_SIZE 256

static int _domain_cache_collect(const char *domain, void *priv)
{
	struct geosite_domain_cache *cache = (struct geosite_domain_cache *)priv;
	if (cache->count >= GEOSITE_MAX_CACHED_DOMAINS) {
		return 0;
	}
	/* Expand in chunks to avoid per-entry realloc overhead */
	if ((cache->count % DOMAIN_CACHE_CHUNK_SIZE) == 0) {
		int new_capacity = cache->count + DOMAIN_CACHE_CHUNK_SIZE;
		if (new_capacity > GEOSITE_MAX_CACHED_DOMAINS) {
			new_capacity = GEOSITE_MAX_CACHED_DOMAINS;
		}
		char **new_ptr = realloc(cache->domains, (size_t)new_capacity * sizeof(char *));
		if (new_ptr == NULL) {
			return -1;
		}
		cache->domains = new_ptr;
	}
	cache->domains[cache->count] = strdup(domain);
	if (cache->domains[cache->count] == NULL) {
		return -1;
	}
	cache->count++;
	return 0;
}

/* Check if a domain exists in a pre-loaded domain cache (O(N) scan, no I/O) */
static int _domain_cache_contains(const struct geosite_domain_cache *cache, const char *domain)
{
	if (cache == NULL || cache->domains == NULL) {
		return 0;
	}
	for (int i = 0; i < cache->count; i++) {
		if (strcmp(cache->domains[i], domain) == 0) {
			return 1;
		}
	}
	return 0;
}

void geosite_dat_table_init(void)
{
	hash_init(geosite_dat_table.dats);
#ifdef USE_CURL
	curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
}

void geosite_set_table_init(void)
{
	hash_init(geosite_set_table.sets);
}

void geosite_dat_table_destroy(void)
{
	struct geosite_dat *dat = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		hlist_del_init(&dat->node);
		_domain_cache_free(&dat->old_domains);
		_domain_cache_free(&dat->new_domains);
		free(dat);
	}

#ifdef USE_CURL
	curl_global_cleanup();
#endif
}

void geosite_set_table_destroy(void)
{
	struct geosite_set *set = NULL;
	struct hlist_node *tmp = NULL;
	struct geosite_dat *dat_ref = NULL;
	struct geosite_dat *tmp_dat = NULL;
	unsigned long i = 0;

	hash_for_each_safe(geosite_set_table.sets, i, tmp, set, node)
	{
		hlist_del_init(&set->node);
		/* Free references in dat_list */
		list_for_each_entry_safe(dat_ref, tmp_dat, &set->dat_list, dat_list)
		{
			list_del(&dat_ref->dat_list);
			geosite_dat_put(dat_ref);
		}
		free(set);
	}
}

void geosite_log_config_summary(void)
{
	int dat_count = 0;
	int set_count = 0;
	int url_count = 0;
	struct geosite_dat *dat = NULL;
	unsigned long i;

	/* Count geosite-dat sources */
	hash_for_each(geosite_dat_table.dats, i, dat, node)
	{
		dat_count++;
		if (dat->is_url) {
			url_count++;
		}
	}

	/* Count geosite-set rules */
	struct geosite_set *set = NULL;
	hash_for_each(geosite_set_table.sets, i, set, node)
	{
		set_count++;
	}

	if (dat_count == 0 && set_count == 0) {
		return;
	}

	tlog(TLOG_NOTICE, "geosite MOD: %s", geosite_build_version());
	_geosite_log_lib_versions();

	tlog(TLOG_NOTICE,
		"geosite: %d dat source(s) (%d local, %d url), %d set rule(s), interval=%d, diff_algo=%s",
		dat_count, dat_count - url_count, url_count, set_count,
		geosite_updater.default_interval,
		geosite_updater.diff_algo == GEOSITE_DIFF_MTIME ? "mtime" : geosite_updater.diff_algo == GEOSITE_DIFF_CRC32 ? "crc32" : "md5");

	/* Warn if update-interval is too small relative to worst-case download time */
	int worst_case = geosite_updater.http_timeout * (geosite_updater.http_retry + 1) +
	                 geosite_updater.http_retry_interval * geosite_updater.http_retry;
	if (geosite_updater.default_interval > 0 && geosite_updater.default_interval < worst_case) {
		tlog(TLOG_WARN,
			"geosite: update-interval (%d) is less than worst-case download time (%d), "
			"consider increasing update-interval to avoid download overlap",
			geosite_updater.default_interval, worst_case);
	}
}

void geosite_save_domain_rule(const char *set_name, int argc, char *argv[])
{
	/* Check for duplicate to avoid saving during replay */
	struct geosite_domain_rule_entry *existing = NULL;
	list_for_each_entry(existing, &geosite_domain_rule_list, list)
	{
		if (strcmp(existing->set_name, set_name) == 0) {
			/* Already saved, skip */
			return;
		}
	}

	struct geosite_domain_rule_entry *entry = zalloc(1, sizeof(*entry));
	if (entry == NULL) {
		tlog(TLOG_ERROR, "geosite: failed to save domain rule for %s", set_name);
		return;
	}

	safe_strncpy(entry->set_name, set_name, DNS_MAX_CNAME_LEN);

	/* Track the current rule group where the rule will be stored.
	 * This is determined by the -g option (if present) or the current group
	 * at the time of parsing. During reload, we use this to ensure rules
	 * are deleted and re-added to the same group. */
	struct dns_conf_group *current_group = _config_current_rule_group();
	if (current_group != NULL) {
		safe_strncpy(entry->rule_group, current_group->group_name, sizeof(entry->rule_group));
	}

	entry->argc = argc;
	entry->argv = zalloc(argc, sizeof(char *));
	if (entry->argv == NULL) {
		free(entry);
		tlog(TLOG_ERROR, "geosite: failed to save domain rule argv for %s", set_name);
		return;
	}
	for (int i = 0; i < argc; i++) {
		entry->argv[i] = strdup(argv[i]);
		if (entry->argv[i] == NULL) {
			for (int j = 0; j < i; j++) {
				free(entry->argv[j]);
			}
			free(entry->argv);
			free(entry);
			tlog(TLOG_ERROR, "geosite: failed to save domain rule argv for %s", set_name);
			return;
		}
	}

	list_add_tail(&entry->list, &geosite_domain_rule_list);
	tlog(TLOG_DEBUG, "geosite: saved domain rule for set '%s' (argc=%d, group=%s)", set_name, argc,
		 entry->rule_group[0] ? entry->rule_group : "(default)");
}

struct geosite_dat *geosite_dat_get(const char *name)
{
	uint32_t key = hash_string(name);
	struct geosite_dat *dat = NULL;

	hash_for_each_possible(geosite_dat_table.dats, dat, node, key)
	{
		if (strcmp(dat->name, name) == 0) {
			atomic_inc(&dat->refcnt);
			return dat;
		}
	}

	return NULL;
}

/* Find geosite_dat by name in hash table without incrementing refcnt.
 * Used internally for field updates (e.g., downloading thread updating flags).
 * Caller must hold appropriate synchronization. */
static struct geosite_dat *_geosite_dat_find_by_name(const char *name)
{
	uint32_t key = hash_string(name);
	struct geosite_dat *dat = NULL;

	hash_for_each_possible(geosite_dat_table.dats, dat, node, key)
	{
		if (strcmp(dat->name, name) == 0) {
			return dat;
		}
	}

	return NULL;
}

void geosite_dat_put(struct geosite_dat *dat)
{
	if (dat == NULL) {
		return;
	}
	if (atomic_dec_and_test(&dat->refcnt)) {
		tlog(TLOG_WARN, "geosite-dat %s: refcnt reached zero (potential reference counting bug)", dat->name);
	}
}

/* Check if a string looks like a URL */
static int _is_url(const char *str)
{
	if (str == NULL) {
		return 0;
	}
	return (strncmp(str, "http://", 7) == 0 || strncmp(str, "https://", 8) == 0);
}

#ifdef USE_CURL
/* libcurl write callback: append data to FILE* */
static size_t _curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	return fwrite(ptr, size, nmemb, (FILE *)userdata);
}

/* libcurl header callback: capture ETag from response headers */
struct _curl_header_data {
	char etag[128];
	int http_code;
};

static size_t _curl_header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
	struct _curl_header_data *hd = (struct _curl_header_data *)userdata;
	size_t total = size * nitems;

	/* Capture HTTP status code */
	if (strncasecmp(buffer, "HTTP/", 5) == 0) {
		char *code_start = buffer + 9; /* skip "HTTP/x.x " */
		if (*code_start) {
			hd->http_code = atoi(code_start);
		}
		return total;
	}

	/* Capture ETag header */
	if (strncasecmp(buffer, "etag:", 5) == 0) {
		const char *val = buffer + 5;
		while (*val == ' ' || *val == '\t') val++;
		size_t vlen = total - (size_t)(val - buffer);
		/* Strip trailing \r\n */
		while (vlen > 0 && (val[vlen - 1] == '\r' || val[vlen - 1] == '\n')) {
			vlen--;
		}
		if (vlen >= sizeof(hd->etag)) {
			vlen = sizeof(hd->etag) - 1;
		}
		memcpy(hd->etag, val, vlen);
		hd->etag[vlen] = '\0';
	}

	return total;
}

/*
 * Download file from URL using libcurl.
 * Returns: 0 = success (file changed), 1 = not modified (304), -1 = error.
 * If etag_out is non-NULL, stores the new ETag on success.
 */
static int _download_file(const char *url, const char *output_path, const char *etag_in, char *etag_out)
{
	CURL *curl = NULL;
	CURLcode res;
	FILE *fp = NULL;
	long http_code = 0;
	char errbuf[CURL_ERROR_SIZE] = {0};
	char dir[PATH_MAX] = {0};
	int ret = -1;
	struct curl_slist *headers = NULL;
	struct _curl_header_data header_data = {.http_code = 0};

	/* Ensure output directory exists */
	strncpy(dir, output_path, sizeof(dir) - 1);
	char *last_slash = strrchr(dir, '/');
	if (last_slash != NULL) {
		*last_slash = '\0';
		if (access(dir, F_OK) != 0) {
			char mkdir_cmd[PATH_MAX + 32];
			snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p '%s'", dir);
			if (system(mkdir_cmd) != 0) {
				/* ignore mkdir failure, curl will report error if dir doesn't exist */
			}
		}
	}

	curl = curl_easy_init();
	if (curl == NULL) {
		tlog(TLOG_ERROR, "geosite: curl_easy_init failed");
		return -1;
	}

	fp = fopen(output_path, "wb");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "geosite: failed to create file %s: %s", output_path, strerror(errno));
		curl_easy_cleanup(curl);
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, _curl_header_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_data);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)geosite_updater.http_timeout > 30 ? 30L : (long)geosite_updater.http_timeout);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)geosite_updater.http_timeout);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, geosite_updater.user_agent);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

	/* If ETag is provided and enabled, add If-None-Match header */
	if (geosite_updater.use_etag && etag_in && etag_in[0] != '\0') {
		char if_none_match[256];
		snprintf(if_none_match, sizeof(if_none_match), "If-None-Match: %s", etag_in);
		headers = curl_slist_append(headers, if_none_match);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	}

	tlog(TLOG_DEBUG, "geosite: downloading %s", url);
	res = curl_easy_perform(curl);

	if (res == CURLE_OK) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 304) {
			/* Not Modified — caller will log with diff-algo info */
			fclose(fp);
			unlink(output_path);
			curl_easy_cleanup(curl);
			if (headers) curl_slist_free_all(headers);
			/* Still update etag_out with the returned ETag if any */
			if (etag_out && header_data.etag[0]) {
				safe_strncpy(etag_out, header_data.etag, 128);
			}
			return 1;
		}
		if (http_code == 200) {
			ret = 0;
		} else {
			tlog(TLOG_ERROR, "geosite: download %s returned HTTP %ld", url, http_code);
		}
	} else {
		tlog(TLOG_ERROR, "geosite: download %s failed: %s", url, errbuf[0] ? errbuf : curl_easy_strerror(res));
	}

	fclose(fp);
	curl_easy_cleanup(curl);
	if (headers) curl_slist_free_all(headers);

	/* Store the new ETag */
	if (ret == 0 && etag_out && header_data.etag[0]) {
		safe_strncpy(etag_out, header_data.etag, 128);
	}

	if (ret != 0) {
		unlink(output_path);
	}

	return ret;
}
#else
/* Download file from URL using wget or curl (fallback) */
static int _download_file(const char *url, const char *output_path, const char *etag_in, char *etag_out)
{
	char cmd[PATH_MAX * 2 + 128];
	int ret;
	(void)etag_in;
	(void)etag_out;

	/* Try wget first, suppress stderr to avoid "not found" pollution */
	if (geosite_updater.user_agent[0]) {
		ret = snprintf(cmd, sizeof(cmd),
			"{ wget -q --timeout=%d --user-agent='%s' -O \"%s\" \"%s\" 2>/dev/null || "
			"curl -sL --connect-timeout %d -m %d -A '%s' -o \"%s\" \"%s\" 2>/dev/null; }",
			geosite_updater.http_timeout, geosite_updater.user_agent, output_path, url,
			geosite_updater.http_timeout > 30 ? 30 : geosite_updater.http_timeout,
			geosite_updater.http_timeout, geosite_updater.user_agent, output_path, url);
	} else {
		ret = snprintf(cmd, sizeof(cmd),
			"{ wget -q --timeout=%d -O \"%s\" \"%s\" 2>/dev/null || "
			"curl -sL --connect-timeout %d -m %d -o \"%s\" \"%s\" 2>/dev/null; }",
			geosite_updater.http_timeout, output_path, url,
			geosite_updater.http_timeout > 30 ? 30 : geosite_updater.http_timeout,
			geosite_updater.http_timeout, output_path, url);
	}
	if (ret < 0 || ret >= (int)sizeof(cmd)) {
		tlog(TLOG_ERROR, "command too long for URL: %s", url);
		return -1;
	}

	tlog(TLOG_DEBUG, "geosite: downloading %s (wget/curl fallback)", url);
	ret = system(cmd);
	if (ret != 0) {
		tlog(TLOG_ERROR, "geosite: download %s failed (wget/curl not available or network error)", url);
		return -1;
	}

	return 0;
}
#endif /* USE_CURL */

/* Check if a domain string (already punycode-encoded) is valid for geosite rules.
 * Allows: alphanumeric, hyphen, dot, wildcard (*), and include (+).
 * Rejects: IP addresses, empty strings, overly long labels, etc. */
static int _is_valid_domain(const char *domain)
{
	if (domain == NULL || domain[0] == '\0') {
		return 0;
	}

	size_t len = strlen(domain);
	if (len > DNS_MAX_CNAME_LEN - 1) {
		return 0;
	}

	/* Reject pure numeric strings that look like IP addresses */
	int has_alpha = 0;
	int has_dot = 0;
	int label_len = 0;

	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)domain[i];

		if (c >= 'a' && c <= 'z') {
			has_alpha = 1;
			label_len++;
			continue;
		}
		if (c >= '0' && c <= '9') {
			label_len++;
			continue;
		}
		if (c == '-') {
			/* Hyphen cannot be at start or end of a label */
			if (label_len == 0 || (i + 1 < len && domain[i + 1] == '.')) {
				return 0;
			}
			label_len++;
			continue;
		}
		if (c == '.') {
			if (label_len == 0) {
				/* Allow leading dot after '+' prefix (e.g., "+.example.com") */
				if (i == 1 && domain[0] == '+') {
					label_len = 0;
					has_dot = 1;
					continue;
				}
				/* Consecutive dots or leading dot after normalization */
				return 0;
			}
			if (label_len > 63) {
				/* Label too long (RFC 1035) */
				return 0;
			}
			has_dot = 1;
			label_len = 0;
			continue;
		}
		if (c == '*') {
			/* Wildcard: must be the only char or followed by a dot (e.g., "*.example.com") */
			if (i == 0 && (len == 1 || domain[1] == '.')) {
				continue;
			}
			return 0;
		}
		if (c == '+') {
			/* Include marker: must be the first char (e.g., "+example.com", "+.example.com") */
			if (i == 0) {
				continue;
			}
			return 0;
		}
		/* Reject any other character (punycode xn-- prefix is allowed since it's alphanumeric + '-') */
		return 0;
	}

	/* Final label length check */
	if (label_len > 63 || label_len == 0) {
		return 0;
	}

	/* Reject if it looks like an IPv4 address (e.g., "1.2.3.4" with no alpha) */
	if (!has_alpha && has_dot) {
		/* Count dots — IPv4 has exactly 3 */
		int dots = 0;
		for (size_t i = 0; i < len; i++) {
			if (domain[i] == '.') {
				dots++;
			}
		}
		if (dots == 3) {
			return 0;
		}
	}

	return 1;
}

/* Parse a geosite list file and call callback for each domain */
static int _parse_geosite_file(const char *file, geosite_domain_cb callback, void *priv)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char value[DNS_MAX_CNAME_LEN];
	int line_no = 0;
	int filed_num = 0;
	int ret = 0;

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "open geosite file %s error, %s", file, strerror(errno));
		return -1;
	}

	line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp)) {
		char *p = line;
		line_no++;

		/* skip UTF-8 BOM */
		if (line_no == 1 && (unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB &&
			(unsigned char)line[2] == 0xBF) {
			p += 3;
		}

		filed_num = sscanf(p, "%255s", value);
		if (filed_num <= 0) {
			continue;
		}

		if (value[0] == '#' || value[0] == '\n' || value[0] == '\0') {
			continue;
		}

		/* Normalize domain */
		char domain[DNS_MAX_CNAME_LEN];
		char *d_ptr = value;

		/* remove leading dots */
		while (*d_ptr == '.') {
			if (*(d_ptr + 1) == '\0') {
				break;
			}
			d_ptr++;
		}

		/* skip empty domain */
		if (*d_ptr == '\0') {
			continue;
		}

		/* Convert to punycode if needed */
		if (utf8_to_punycode(d_ptr, strlen(d_ptr), domain, sizeof(domain)) <= 0) {
			tlog(TLOG_WARN, "process geosite file %s: skip invalid domain at line %d (punycode failed: %s).", file, line_no, d_ptr);
			continue;
		}

		/* Validate domain format */
		if (!_is_valid_domain(domain)) {
			tlog(TLOG_WARN, "process geosite file %s: skip invalid domain '%s' at line %d.", file, domain, line_no);
			continue;
		}

		ret = callback(domain, priv);
		if (ret != 0) {
			tlog(TLOG_WARN, "process geosite file %s failed at line %d.", file, line_no);
			/* Continue processing other lines */
		}
	}

	fclose(fp);
	return 0;
}

#ifdef __linux__
/* eventfd management for async download notifications */
int geosite_get_download_event_fd(void)
{
	return geosite_download_efd;
}

int geosite_download_event_init(void)
{
	if (geosite_download_efd >= 0) {
		return 0;
	}
	geosite_download_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (geosite_download_efd < 0) {
		tlog(TLOG_ERROR, "geosite: create download eventfd failed, %s", strerror(errno));
		return -1;
	}
	return 0;
}

void geosite_download_event_destroy(void)
{
	if (geosite_download_efd >= 0) {
		close(geosite_download_efd);
		geosite_download_efd = -1;
	}
}

/* Notify main thread that download is complete */
static void _geosite_notify_download_complete(void)
{
	if (geosite_download_efd < 0) {
		return;
	}
	uint64_t val = 1;
	int unused __attribute__((unused));
	unused = write(geosite_download_efd, &val, sizeof(val));
}
#endif /* __linux__ */

#ifndef __linux__
/* Stubs for non-Linux platforms (no async download, use sync fallback) */
int geosite_get_download_event_fd(void) { return -1; }
int geosite_download_event_init(void) { return 0; }
void geosite_download_event_destroy(void) {}
#endif
struct geosite_download_arg {
	char name[DNS_MAX_CNAME_LEN];
	char url[DNS_MAX_PATH];
	char file[DNS_MAX_PATH];
	char etag[128];                     /* current ETag for conditional download */
	enum geosite_diff_algo diff_algo;   /* algorithm for content comparison */
	int is_url;
};

/* Download and normalize a single URL geosite-dat.
 *
 * Common core used by both:
 *   - _geosite_download_thread()  [async background]
 *   - geosite_download_url_files_sync()  [synchronous for --check-domain-rule]
 *
 * Parameters:
 *   dat       - geosite_dat to download (must be is_url==1)
 *   out_etag  - [out] new ETag from server response (128 bytes)
 *
 * Returns:
 *    0 = success (file downloaded, normalized, renamed)
 *    1 = not modified (304 Not Modified)
 *   -1 = error (download failed or normalize failed)
 */
static int _geosite_download_one_url(struct geosite_dat *dat, char *out_etag)
{
	int ret = -1;
	char temp_file[DNS_MAX_PATH];
	int domain_count = 0;

	/* Use system temp directory for download staging, not data-dir */
	const char *tmpdir = getenv("TMPDIR");
	if (tmpdir == NULL || tmpdir[0] == '\0') {
		tmpdir = P_tmpdir;
	}
	if (tmpdir == NULL || tmpdir[0] == '\0') {
		tmpdir = "/tmp";
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
	snprintf(temp_file, sizeof(temp_file), "%s/smartdns-geosite.XXXXXX", tmpdir);
	temp_file[sizeof(temp_file) - 8] = '\0';
#pragma GCC diagnostic pop

	int fd = mkstemp(temp_file);
	if (fd < 0) {
		tlog(TLOG_ERROR, "geosite-dat %s: create temp file failed: %s", dat->name, strerror(errno));
		return -1;
	}
	close(fd);

	/* Download with ETag support, retry on failure */
	int retry = 0;
	for (retry = 0; retry <= geosite_updater.http_retry; retry++) {
		ret = _download_file(dat->url, temp_file, dat->etag, out_etag);
		if (ret >= 0 || retry >= geosite_updater.http_retry) {
			break;
		}
		tlog(TLOG_WARN, "geosite-dat %s: download failed, retry %d/%d",
			 dat->name, retry + 1, geosite_updater.http_retry);
		sleep(geosite_updater.http_retry_interval);
	}

	if (ret == 1) {
		unlink(temp_file);
		const char *algo_name = (geosite_updater.diff_algo == GEOSITE_DIFF_CRC32) ? "crc32" :
		                        (geosite_updater.diff_algo == GEOSITE_DIFF_MD5)   ? "md5" : "mtime";
		tlog(TLOG_DEBUG, "geosite-dat %s: content not changed (ETag 304, skipped %s check)",
			 dat->name, algo_name);
		return 1; /* 304 Not Modified */
	}
	if (ret != 0) {
		unlink(temp_file);
		return -1; /* download failed */
	}

	/* Normalize: parse downloaded file and rewrite with validated domains */
	FILE *fp_in = fopen(temp_file, "r");
	if (fp_in == NULL) {
		tlog(TLOG_ERROR, "geosite-dat %s: open temp file failed: %s", dat->name, strerror(errno));
		unlink(temp_file);
		return -1;
	}

	char out_file[DNS_MAX_PATH + 4]; /* extra 4 for ".new" suffix */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
	snprintf(out_file, sizeof(out_file), "%s.new", dat->file);
#pragma GCC diagnostic pop
	out_file[sizeof(out_file) - 5] = '\0';

	FILE *fp_out = fopen(out_file, "w");
	if (fp_out == NULL) {
		tlog(TLOG_ERROR, "geosite-dat %s: create output file failed: %s", dat->name, strerror(errno));
		fclose(fp_in);
		unlink(temp_file);
		return -1;
	}

	char line[MAX_LINE_LEN];
	char value[DNS_MAX_CNAME_LEN];
	int line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp_in)) {
		char *p = line;
		line_no++;
		/* skip UTF-8 BOM */
		if (line_no == 1 && (unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB &&
			(unsigned char)line[2] == 0xBF) {
			p += 3;
		}
		int filed_num = sscanf(p, "%255s", value);
		if (filed_num <= 0) {
			continue;
		}
		if (value[0] == '#' || value[0] == '\n' || value[0] == '\0') {
			fprintf(fp_out, "%s", line);
			continue;
		}
		char domain[DNS_MAX_CNAME_LEN];
		char *d_ptr = value;
		while (*d_ptr == '.') {
			if (*(d_ptr + 1) == '\0') break;
			d_ptr++;
		}
		if (*d_ptr == '\0') {
			fprintf(fp_out, "%s", line);
			continue;
		}
		if (utf8_to_punycode(d_ptr, strlen(d_ptr), domain, sizeof(domain)) <= 0) {
			fprintf(fp_out, "%s", line);
			continue;
		}
		if (!_is_valid_domain(domain)) {
			continue;
		}
		fprintf(fp_out, "%s\n", domain);
		domain_count++;
	}

	fclose(fp_in);
	fclose(fp_out);

	/* Atomic rename */
	ret = rename(out_file, dat->file);
	if (ret != 0) {
		tlog(TLOG_ERROR, "geosite-dat %s: rename failed: %s", dat->name, strerror(errno));
		unlink(out_file);
		unlink(temp_file);
		return -1;
	}

	unlink(temp_file);
	tlog(TLOG_DEBUG, "geosite-dat %s: download complete (%d domains normalized)", dat->name, domain_count);
	return 0; /* success */
}

#ifdef __linux__
/* Background download thread function — wraps _geosite_download_one_url() */
static void *_geosite_download_thread(void *arg)
{
	struct geosite_download_arg *dlarg = (struct geosite_download_arg *)arg;
	int ret = -1;
	char new_etag[128] = {0};

	if (dlarg->is_url) {
		struct geosite_dat *dat = _geosite_dat_find_by_name(dlarg->name);
		if (dat == NULL) {
			tlog(TLOG_ERROR, "geosite-dat %s: not found in table", dlarg->name);
			goto out;
		}

		ret = _geosite_download_one_url(dat, new_etag);

		if (ret == 1) {
			/* 304 Not Modified */
			dat->last_update = time(NULL);
			dat->downloading = 0;
			if (new_etag[0]) {
				safe_strncpy(dat->etag, new_etag, sizeof(dat->etag));
			}
			goto out_skip_notify;
		}

		if (ret != 0) {
			goto out;
		}

		/* Update ETag on success */
		if (new_etag[0]) {
			safe_strncpy(dat->etag, new_etag, sizeof(dat->etag));
		}
	}

out:
	/* Mark dat as needing update so geosite_reload_rules() will finalize state
	 * (update last_update, clear downloading flag, reload rules if content changed) */
	if (dlarg->is_url) {
		struct geosite_dat *dat = _geosite_dat_find_by_name(dlarg->name);
		if (dat) {
			dat->need_update = 1;
		}
	}

	if (ret == 0) {
		tlog(TLOG_INFO, "geosite-dat %s: download successful, content updated", dlarg->name);
	} else {
		tlog(TLOG_ERROR, "geosite-dat %s: download failed", dlarg->name);
	}
	free(arg);
	_geosite_notify_download_complete();
	return NULL;

out_skip_notify:
	/* 304 fast path: downloading already cleared, no need to notify main thread */
	free(arg);
	return NULL;
}
#endif /* __linux__ */

static int _geosite_dat_update(struct geosite_dat *dat)
{
	if (!dat->is_url) {
		/* For local files, detect changes based on configured diff-algo */
		struct stat st;
		if (stat(dat->file, &st) != 0) {
			tlog(TLOG_WARN, "geosite-dat %s: cannot stat file %s", dat->name, dat->file);
			return -1;
		}

		switch (geosite_updater.diff_algo) {
		case GEOSITE_DIFF_MTIME:
			/* Compare mtime (original behavior) */
			if ((unsigned int)st.st_mtime == dat->last_update) {
				return -1;
			}
			tlog(TLOG_DEBUG, "geosite-dat %s: file changed (old_mtime=%u, new_mtime=%u)",
				 dat->name, dat->last_update, (unsigned int)st.st_mtime);
			dat->last_update = st.st_mtime;
			break;

		case GEOSITE_DIFF_CRC32:
		case GEOSITE_DIFF_MD5: {
			/* Compute hash and compare with stored hash */
			char new_hash[33] = {0};
			if (_compute_file_hash(dat->file, geosite_updater.diff_algo, new_hash, sizeof(new_hash)) != 0) {
				tlog(TLOG_WARN, "geosite-dat %s: failed to compute file hash", dat->name);
				return -1;
			}
			if (dat->file_hash[0] != '\0' && strcmp(new_hash, dat->file_hash) == 0) {
				/* Hash unchanged */
				return -1;
			}
			tlog(TLOG_DEBUG, "geosite-dat %s: file changed (old_hash=%s, new_hash=%s)",
				 dat->name, dat->file_hash[0] ? dat->file_hash : "(none)", new_hash);
			safe_strncpy(dat->file_hash, new_hash, sizeof(dat->file_hash));
			break;
		}
		default:
			return -1;
		}

		/*
		 * For local files, the file has already been modified externally.
		 * old_domains was cached at registration time (or after the previous
		 * reload), so it holds the PREVIOUS file content for diff-based rule
		 * removal. Do NOT overwrite old_domains here.
		 */
		return 0;
	}

	/* URL sources: handled by async download in geosite_check_and_download() */
	return -1;
}

/* Synchronously download all URL-based geosite-dat files and check local files.
 * Blocks until all downloads complete and rules are reloaded.
 * Used by --check-domain-rule to ensure latest data before checking.
 *
 * Reuses:
 *   - _geosite_download_one_url()  for URL sources (download+normalize)
 *   - _geosite_dat_update()        for local file change detection (mtime/hash) */
int geosite_download_url_files_sync(void)
{
	struct geosite_dat *dat = NULL;
	unsigned long i = 0;

	hash_for_each(geosite_dat_table.dats, i, dat, node)
	{
		if (dat->is_url) {
			/* URL source: download + normalize */
			tlog(TLOG_INFO, "geosite: sync downloading %s from %s...", dat->name, dat->url);
			char new_etag[128] = {0};
			int dl_ret = _geosite_download_one_url(dat, new_etag);

			if (dl_ret == 1) {
				/* 304 Not Modified */
				dat->last_update = time(NULL);
				if (new_etag[0]) {
					safe_strncpy(dat->etag, new_etag, sizeof(dat->etag));
				}
				continue;
			}

			if (dl_ret != 0) {
				tlog(TLOG_ERROR, "geosite-dat %s: sync download failed after %d retries", dat->name,
					 geosite_updater.http_retry + 1);
				continue;
			}

			/* Download succeeded — update ETag and mark for reload */
			if (new_etag[0]) {
				safe_strncpy(dat->etag, new_etag, sizeof(dat->etag));
			}

			dat->need_update = 1;
			dat->last_update = time(NULL);

			tlog(TLOG_INFO, "geosite-dat %s: sync download complete, file updated", dat->name);
		} else {
			/* Local file: check for changes using configured diff-algo (mtime/crc32/md5) */
			if (_geosite_dat_update(dat) == 0) {
				dat->need_update = 1;
				tlog(TLOG_DEBUG, "geosite-dat %s: local file changed", dat->name);
			}
		}
	}

	/* Reload rules if any files were updated */
	return geosite_reload_rules();
}

/* Check all geosite data sources and trigger async downloads if needed.
 * This function is non-blocking — it only checks mtime/interval and
 * submits download tasks to background threads. */
int geosite_check_and_download(void)
{
	struct geosite_dat *dat = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;
	unsigned int now = time(NULL);

	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (dat->update_interval <= 0) {
			continue;
		}

		/* Skip if a download is already in progress for this dat */
		if (dat->downloading) {
			continue;
		}

		/* Check if update is needed based on interval */
		if (dat->last_update != 0 && (now - dat->last_update) < (unsigned int)dat->update_interval) {
			continue;
		}

		if (dat->is_url) {
#ifdef __linux__
			/* URL source: submit async download task (non-blocking) */
			dat->downloading = 1;

			/* Cache current domains before download (for diff-based reload) */
			_domain_cache_free(&dat->old_domains);
			if (access(dat->file, F_OK) == 0) {
				_parse_geosite_file(dat->file, _domain_cache_collect, &dat->old_domains);
			}

			struct geosite_download_arg *arg = zalloc(1, sizeof(*arg));
			if (arg == NULL) {
				tlog(TLOG_ERROR, "geosite: failed to allocate download arg for %s", dat->name);
				dat->downloading = 0;
				continue;
			}
			safe_strncpy(arg->name, dat->name, DNS_MAX_CNAME_LEN);
			safe_strncpy(arg->url, dat->url, DNS_MAX_PATH);
			safe_strncpy(arg->file, dat->file, DNS_MAX_PATH);
			safe_strncpy(arg->etag, dat->etag, sizeof(arg->etag));
			arg->diff_algo = geosite_updater.diff_algo;
			arg->is_url = 1;

			pthread_t tid;
			int ret = pthread_create(&tid, NULL, _geosite_download_thread, arg);
			if (ret != 0) {
				tlog(TLOG_ERROR, "geosite: failed to create download thread for %s: %s",
					 dat->name, strerror(errno));
				free(arg);
				dat->downloading = 0;
				continue;
			}
			pthread_detach(tid);
			tlog(TLOG_DEBUG, "geosite-dat %s: async download submitted (interval=%d)", dat->name, dat->update_interval);
#else
			/* Fallback: synchronous download on non-Linux platforms */
			tlog(TLOG_DEBUG, "checking geosite-dat %s for update (interval=%d, last=%u, now=%u)",
				dat->name, dat->update_interval, dat->last_update, now);
			if (_geosite_dat_update(dat) == 0) {
				dat->need_update = 1;
			}
#endif
		} else {
			/* Local file: fast mtime check (non-blocking) */
			tlog(TLOG_DEBUG, "checking geosite-dat %s for update (interval=%d, last=%u, now=%u)",
				dat->name, dat->update_interval, dat->last_update, now);
			if (_geosite_dat_update(dat) == 0) {
				dat->need_update = 1;
				/* For local files, reload immediately in the next step */
			} else {
				tlog(TLOG_DEBUG, "geosite-dat %s: file no change", dat->name);
			}
		}
	}

	/* For local files that were updated, do synchronous reload */
	struct geosite_dat *dat2 = NULL;
	struct hlist_node *tmp2 = NULL;
	unsigned long i2 = 0;
	int has_local_update = 0;
	hash_for_each_safe(geosite_dat_table.dats, i2, tmp2, dat2, node)
	{
		if (dat2->need_update && !dat2->is_url) {
			has_local_update = 1;
			break;
		}
	}
	if (has_local_update) {
		geosite_reload_rules();
	}

	return 0;
}

/* Reload geosite rules into ART tree.
 * Called from main thread after receiving download-complete eventfd notification,
 * or after local file mtime change detected by geosite_check_and_download().
 * This function handles the ART tree operations (delete stale + re-add) and
 * is safe to call from the main epoll thread. */
int geosite_reload_rules(void)
{
	struct geosite_dat *dat = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;
	int has_update = 0;

	/* Check if any dat needs update */
	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (dat->need_update) {
			has_update = 1;
			break;
		}
	}
	if (!has_update) {
		return 0;
	}

	/* For URL sources, check if download has completed by verifying file mtime */
	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (dat->need_update && dat->is_url) {
			struct stat st;
			if (stat(dat->file, &st) == 0 && (unsigned int)st.st_mtime != dat->last_update) {
				dat->last_update = st.st_mtime;
				tlog(TLOG_DEBUG, "geosite-dat %s: URL file updated (new_mtime=%u)", dat->name, dat->last_update);
			} else {
				/* File not actually changed, clear flag */
				dat->need_update = 0;
				dat->downloading = 0;
				const char *algo_name = (geosite_updater.diff_algo == GEOSITE_DIFF_CRC32) ? "crc32" :
				                        (geosite_updater.diff_algo == GEOSITE_DIFF_MD5)   ? "md5" : "mtime";
				tlog(TLOG_DEBUG, "geosite-dat %s: URL file no change (%s)", dat->name, algo_name);
			}
		}
	}

	/* Re-check after clearing stale flags */
	has_update = 0;
	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (dat->need_update) {
			has_update = 1;
			break;
		}
	}
	if (!has_update) {
		return 0;
	}

	/* Preload new domain lists for all dat sources that need update.
	 * This allows in-memory diff (old vs new) without file I/O during reload. */
	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (!dat->need_update) {
			continue;
		}
		_domain_cache_free(&dat->new_domains);
		if (access(dat->file, F_OK) == 0) {
			_parse_geosite_file(dat->file, _domain_cache_collect, &dat->new_domains);
		}
	}

	struct geosite_domain_rule_entry *entry = NULL;
	struct geosite_domain_rule_entry *tmp_entry = NULL;
	int total_deleted = 0;
	int total_added = 0;

	/* Collect changed dat names for log message */
	char changed_names[256] = {0};
	int changed_names_len = 0;
	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (!dat->need_update) {
			continue;
		}
		if (changed_names_len > 0 && changed_names_len < (int)sizeof(changed_names) - 3) {
			changed_names_len += snprintf(changed_names + changed_names_len, sizeof(changed_names) - changed_names_len, ", ");
		}
		changed_names_len += snprintf(changed_names + changed_names_len, sizeof(changed_names) - changed_names_len, "%s", dat->name);
	}

	const char *algo_name = (geosite_updater.diff_algo == GEOSITE_DIFF_CRC32) ? "crc32" :
	                        (geosite_updater.diff_algo == GEOSITE_DIFF_MD5)   ? "md5" : "mtime";
	tlog(TLOG_INFO, "geosite: %s changed (%s), reloading domain rules", changed_names, algo_name);
	list_for_each_entry_safe(entry, tmp_entry, &geosite_domain_rule_list, list)
	{
		tlog(TLOG_DEBUG, "geosite: reloading rules for set '%s' (argc=%d, group=%s)",
			 entry->set_name, entry->argc, entry->rule_group[0] ? entry->rule_group : "(default)");

		/*
		 * After config parsing, dns_conf_current_group_info is NULL
		 * (cleaned up by _config_current_group_pop_all in _dns_conf_load_post).
		 * We push a heap-allocated temp group_info so that
		 * _config_current_rule_group() returns the correct target rule.
		 * The temp group_info is properly freed after _config_domain_rules returns.
		 */
		struct dns_conf_group *target_rule = dns_conf_rule.default_conf;
		if (entry->rule_group[0] != '\0') {
			target_rule = _config_rule_group_get(entry->rule_group);
			if (target_rule == NULL) {
				target_rule = dns_conf_rule.default_conf;
				tlog(TLOG_WARN, "geosite: rule group '%s' not found, using default", entry->rule_group);
			}
		}
		struct dns_conf_group_info *tmp_group = _config_push_temp_rule_group(target_rule);
		if (tmp_group == NULL) {
			tlog(TLOG_ERROR, "geosite: failed to push temp rule group for set '%s'", entry->set_name);
			continue;
		}

		const char *set_ref_name = _geosite_extract_set_name(entry->set_name);
		if (set_ref_name == NULL) {
			goto re_add;
		}

		uint32_t set_key = hash_string(set_ref_name);
		struct geosite_set *set = NULL;
		hash_for_each_possible(geosite_set_table.sets, set, node, set_key)
		{
			if (strcmp(set->name, set_ref_name) == 0) {
				break;
			}
		}
		if (set != NULL) {
			struct geosite_dat *dat_ref = NULL;
			list_for_each_entry(dat_ref, &set->dat_list, dat_list)
			{
				struct geosite_dat *dat_entry = geosite_dat_get(dat_ref->name);
				if (dat_entry == NULL || !dat_entry->need_update) {
					if (dat_entry) geosite_dat_put(dat_entry);
					continue;
				}
				geosite_dat_put(dat_entry);

				/* Diff: delete rules for domains that existed in old but not in new */
				for (int d = 0; d < dat_entry->old_domains.count; d++) {
					const char *old_domain = dat_entry->old_domains.domains[d];
					if (_domain_cache_contains(&dat_entry->new_domains, old_domain)) {
						continue;
					}
					tlog(TLOG_DEBUG, "geosite: DELETE rule for domain '%s' (dat %s)",
						 old_domain, dat_entry->name);
					_config_domain_rule_delete(old_domain);
					dns_cache_remove_by_suffix(old_domain, NULL);
					total_deleted++;
				}
			}
		}

	re_add:
		{
			char **argv_copy = calloc(entry->argc, sizeof(char *));
			if (argv_copy != NULL) {
				memcpy(argv_copy, entry->argv, entry->argc * sizeof(char *));
				_config_domain_rules(NULL, entry->argc, argv_copy);
				free(argv_copy);
			} else {
				tlog(TLOG_ERROR, "geosite: failed to allocate argv copy for set '%s'", entry->set_name);
			}
		}

		tlog(TLOG_DEBUG, "geosite: reloaded rules for set '%s'", entry->set_name);

		/* Pop the temp group_info, restoring group stack state */
		_config_pop_temp_rule_group(tmp_group);
	}

	/* Group stack is restored to NULL (post-config-parsing state) */

	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (!dat->need_update) {
			continue;
		}
		dat->need_update = 0;
		dat->downloading = 0;
		/* Swap: new_domains becomes old_domains for next reload cycle */
		_domain_cache_free(&dat->old_domains);
		dat->old_domains = dat->new_domains;
		dat->new_domains.domains = NULL;
		dat->new_domains.count = 0;
		total_added += dat->old_domains.count;
		tlog(TLOG_DEBUG, "geosite: refreshed domain cache for dat '%s' (%d domains)",
			 dat->name, dat->old_domains.count);
	}

	tlog(TLOG_INFO, "geosite: reload complete, %d domains active, %d rules removed",
		 total_added, total_deleted);

	return 0;
}

/* Iterate domains in a geosite-set */
int geosite_set_foreach_domain(const char *set_name, geosite_domain_cb callback, void *priv)
{
	uint32_t key = hash_string(set_name);
	struct geosite_set *set = NULL;
	struct geosite_dat *dat_ref = NULL;
	int ret = 0;

	hash_for_each_possible(geosite_set_table.sets, set, node, key)
	{
		if (strcmp(set->name, set_name) == 0) {
			break;
		}
	}

	if (set == NULL) {
		tlog(TLOG_WARN, "geosite-set %s not found.", set_name);
		return -1;
	}

	list_for_each_entry(dat_ref, &set->dat_list, dat_list)
	{
		struct geosite_dat *dat = geosite_dat_get(dat_ref->name);
		if (dat == NULL) {
			tlog(TLOG_WARN, "geosite-dat %s referenced by %s not found.", dat_ref->name, set_name);
			continue;
		}

		/* Check if file exists */
		if (access(dat->file, F_OK) != 0) {
			tlog(TLOG_WARN, "geosite-dat %s file %s not accessible.", dat->name, dat->file);
			geosite_dat_put(dat);
			continue;
		}

		ret = _parse_geosite_file(dat->file, callback, priv);
		geosite_dat_put(dat);

		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

/* Iterate domains in a single geosite-dat */
int geosite_dat_foreach_domain(const char *dat_name, geosite_domain_cb callback, void *priv)
{
	struct geosite_dat *dat = geosite_dat_get(dat_name);
	if (dat == NULL) {
		tlog(TLOG_WARN, "geosite-dat %s not found.", dat_name);
		return -1;
	}

	if (access(dat->file, F_OK) != 0) {
		tlog(TLOG_WARN, "geosite-dat %s file %s not accessible.", dat->name, dat->file);
		geosite_dat_put(dat);
		return -1;
	}

	int ret = _parse_geosite_file(dat->file, callback, priv);
	geosite_dat_put(dat);

	return ret;
}

/* Config parser for geosite-dat directive */
int _config_geosite_dat(void *data, int argc, char *argv[])
{
	struct geosite_dat *dat = NULL;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char file[DNS_MAX_PATH] = {0};
	int update_interval = geosite_updater.default_interval;
	int opt = 0;

	/* clang-format off */
	static struct option long_options[] = {
		{"name", required_argument, NULL, 'n'},
		{"file", required_argument, NULL, 'f'},
		{"interval", required_argument, NULL, 'i'},
		{NULL, 0, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "geosite-dat: invalid parameter.");
		return -1;
	}

	/* Parse arguments: geosite-dat <name> <file> [interval] */
	/* argv[0] = "geosite-dat", argv[1] = name, argv[2] = file, argv[3] = interval */
	if (argc >= 2) {
		safe_strncpy(name, argv[1], DNS_MAX_CNAME_LEN);
	}
	if (argc >= 3) {
		safe_strncpy(file, argv[2], DNS_MAX_PATH);
	}
	if (argc >= 4) {
		update_interval = atoi(argv[3]);
		if (update_interval < 0) {
			update_interval = geosite_updater.default_interval;
		}
	}

	/* Also parse long options for backward compatibility */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:f:i:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n':
			safe_strncpy(name, optarg, DNS_MAX_CNAME_LEN);
			break;
		case 'f':
			safe_strncpy(file, optarg, DNS_MAX_PATH);
			break;
		case 'i':
			update_interval = atoi(optarg);
			if (update_interval < 0) {
				update_interval = geosite_updater.default_interval;
			}
			break;
		default:
			break;
		}
	}

	if (name[0] == 0 || file[0] == 0) {
		tlog(TLOG_ERROR, "geosite-dat: name and file are required.");
		return -1;
	}

	/* Check if name already exists */
	uint32_t key = hash_string(name);
	struct geosite_dat *existing = NULL;
	hash_for_each_possible(geosite_dat_table.dats, existing, node, key)
	{
		if (strcmp(existing->name, name) == 0) {
			tlog(TLOG_WARN, "geosite-dat %s already exists, skipping.", name);
			return 0;
		}
	}

	dat = zalloc(1, sizeof(*dat));
	if (dat == NULL) {
		tlog(TLOG_ERROR, "geosite-dat: cannot allocate memory.");
		return -1;
	}

	INIT_LIST_HEAD(&dat->dat_list);
	atomic_set(&dat->refcnt, 1);
	safe_strncpy(dat->name, name, DNS_MAX_CNAME_LEN);
	dat->update_interval = update_interval;
	dat->is_url = _is_url(file);
	dat->last_update = 0;
	dat->need_update = 0;
	dat->etag[0] = '\0';
	dat->file_hash[0] = '\0';

	/* Helper: resolve data-dir (user configured or default {cwd}/data) */
	char resolved_data_dir[PATH_MAX] = {0};
	{
		if (geosite_updater.data_dir[0]) {
			safe_strncpy(resolved_data_dir, geosite_updater.data_dir, sizeof(resolved_data_dir));
		} else {
			char cwd[PATH_MAX];
			if (getcwd(cwd, sizeof(cwd)) != NULL) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
				snprintf(resolved_data_dir, sizeof(resolved_data_dir), "%s/data", cwd);
#pragma GCC diagnostic pop
				resolved_data_dir[sizeof(resolved_data_dir) - 2] = '\0';
			} else {
				safe_strncpy(resolved_data_dir, dns_conf_get_data_dir(), sizeof(resolved_data_dir));
			}
		}
	}

	if (!dat->is_url) {
		/* Local file: resolve path based on type (absolute / relative / bare filename) */
		if (file[0] == '/') {
			/* Case 1: Absolute path — use directly */
			safe_strncpy(dat->file, file, DNS_MAX_PATH);
		} else if (file[0] == '.' && (file[1] == '/' || file[1] == '\0' ||
		                              (file[1] == '.' && file[2] == '/'))) {
			/* Case 2: Relative path (./  or  ../) — join with data-dir */
			if (file[1] == '.' && file[2] == '/') {
				/* ../ relative: data-dir parent + rest */
				snprintf(dat->file, DNS_MAX_PATH, "%s/%s", resolved_data_dir, file);
			} else if (file[1] == '/') {
				/* ./ relative: data-dir + rest (skip ./) */
				snprintf(dat->file, DNS_MAX_PATH, "%s/%s", resolved_data_dir, file + 2);
			} else {
				/* just "." */
				safe_strncpy(dat->file, resolved_data_dir, DNS_MAX_PATH);
			}
		} else {
			/* Case 3: Bare filename (no path separator) — data-dir + filename */
			snprintf(dat->file, DNS_MAX_PATH, "%s/%s", resolved_data_dir, file);
		}

		/* Check if file exists */
		if (access(dat->file, F_OK) != 0) {
			tlog(TLOG_ERROR, "geosite-dat %s: file %s not accessible. %s", name, dat->file, strerror(errno));
			free(dat);
			return -1;
		}

		/* Record initial state based on diff-algo */
		if (geosite_updater.diff_algo == GEOSITE_DIFF_MTIME) {
			struct stat st;
			if (stat(dat->file, &st) == 0) {
				dat->last_update = st.st_mtime;
			}
		} else {
			/* Compute initial file hash for crc32/md5 */
			_compute_file_hash(dat->file, geosite_updater.diff_algo, dat->file_hash, sizeof(dat->file_hash));
			dat->last_update = time(NULL);
		}

		/*
		 * Cache initial domain list for local files.
		 * This snapshot captures the domains that will be loaded into ART rules
		 * during the upcoming config parse. When the file is later modified
		 * externally, this cache serves as the "old" domain list for diffing,
		 * allowing us to detect and remove rules for deleted domains.
		 */
		_parse_geosite_file(dat->file, _domain_cache_collect, &dat->old_domains);
	} else {
		/* For URL, construct the local cache file path using data-dir */
		char url_domain[256] = {0};
		char url_filename[256] = {0};
		_extract_url_parts(file, url_domain, sizeof(url_domain), url_filename, sizeof(url_filename));

		char cache_file[DNS_MAX_PATH];
		if (url_filename[0]) {
			snprintf(cache_file, sizeof(cache_file), "%s/%s-%s", resolved_data_dir, url_domain, url_filename);
		} else {
			snprintf(cache_file, sizeof(cache_file), "%s/geosite-%s.list", resolved_data_dir, name);
		}
		safe_strncpy(dat->file, cache_file, DNS_MAX_PATH);

		/* Store the original URL */
		safe_strncpy(dat->url, file, DNS_MAX_PATH);

		/* Ensure data directory exists */
		if (access(resolved_data_dir, F_OK) != 0) {
			mkdir(resolved_data_dir, 0755);
		}

		if (access(dat->file, F_OK) != 0) {
			/* No local cache — skip blocking download, let async updater handle it.
			 * Set last_update=0 so geosite_check_and_download() triggers download immediately. */
			tlog(TLOG_INFO, "geosite-dat %s: no cached file at %s, will download from %s in background",
				name, dat->file, dat->url);
			dat->last_update = 0;
		} else {
			/* Local cache exists — use it immediately (fast startup) */
			dat->last_update = time(NULL);
			if (geosite_updater.diff_algo != GEOSITE_DIFF_MTIME) {
				_compute_file_hash(dat->file, geosite_updater.diff_algo, dat->file_hash, sizeof(dat->file_hash));
			}
			tlog(TLOG_INFO, "geosite-dat %s: cached (%s)", name, dat->file);
		}
	}

	hash_add(geosite_dat_table.dats, &dat->node, key);

	tlog(TLOG_DEBUG, "geosite-dat %s registered: file=%s, interval=%d, is_url=%d",
		dat->name, dat->is_url ? dat->url : dat->file, dat->update_interval, dat->is_url);

	return 0;
}

/* Config parser for geosite-updater directive */
int _config_geosite_updater(void *data, int argc, char *argv[])
{
	int opt = 0;
	int interval = -1;

	/* clang-format off */
	static struct option long_options[] = {
		{"diff-algo", required_argument, NULL, 'a'},
		{"http-use-etag", required_argument, NULL, 'e'},
		{"user-agent", required_argument, NULL, 'u'},
		{"data-dir", required_argument, NULL, 'd'},
		{"http-timeout", required_argument, NULL, 't'},
		{"http-retry", required_argument, NULL, 'r'},
		{"http-retry-intval", required_argument, NULL, 'R'},
		{NULL, 0, NULL, 0}
	};
	/* clang-format on */

	/* First positional argument (if any) is the default interval */
	if (argc >= 2 && argv[1][0] != '-') {
		interval = atoi(argv[1]);
		if (interval < 0) {
			interval = GEOSITE_DEFAULT_UPDATE_INTERVAL;
		}
	}

	/* Parse long options */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "a:e:u:d:t:r:R:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'a':
			/* diff-algo: mtime, crc32, md5 */
			if (strcasecmp(optarg, "mtime") == 0) {
				geosite_updater.diff_algo = GEOSITE_DIFF_MTIME;
			} else if (strcasecmp(optarg, "crc32") == 0) {
				geosite_updater.diff_algo = GEOSITE_DIFF_CRC32;
			} else if (strcasecmp(optarg, "md5") == 0) {
				geosite_updater.diff_algo = GEOSITE_DIFF_MD5;
			} else {
				tlog(TLOG_WARN, "geosite-updater: unknown diff-algo '%s', using mtime", optarg);
				geosite_updater.diff_algo = GEOSITE_DIFF_MTIME;
			}
			break;
		case 'e':
			/* http-use-etag: yes/no */
			if (strcasecmp(optarg, "yes") == 0 || strcasecmp(optarg, "1") == 0 || strcasecmp(optarg, "true") == 0) {
				geosite_updater.use_etag = 1;
			} else {
				geosite_updater.use_etag = 0;
			}
			break;
		case 'u':
			/* user-agent */
			safe_strncpy(geosite_updater.user_agent, optarg, sizeof(geosite_updater.user_agent));
			break;
		case 'd':
			/* data-dir */
			safe_strncpy(geosite_updater.data_dir, optarg, sizeof(geosite_updater.data_dir));
			break;
		case 't':
			/* http-timeout */
			geosite_updater.http_timeout = atoi(optarg);
			if (geosite_updater.http_timeout <= 0) {
				geosite_updater.http_timeout = 300;
			}
			break;
		case 'r':
			/* http-retry */
			geosite_updater.http_retry = atoi(optarg);
			if (geosite_updater.http_retry < 0) {
				geosite_updater.http_retry = 0;
			}
			if (geosite_updater.http_retry > 5) {
				geosite_updater.http_retry = 5;
			}
			break;
		case 'R':
			/* http-retry-intval: seconds between retries */
			geosite_updater.http_retry_interval = atoi(optarg);
			if (geosite_updater.http_retry_interval < 1) {
				geosite_updater.http_retry_interval = 1;
			}
			if (geosite_updater.http_retry_interval > 60) {
				geosite_updater.http_retry_interval = 60;
			}
			break;
		default:
			break;
		}
	}

	/* Apply default interval if specified */
	if (interval >= 0) {
		geosite_updater.default_interval = interval;
	}

	tlog(TLOG_DEBUG,
		"geosite-updater configured: interval=%d, diff_algo=%s, use_etag=%d, "
		"http_timeout=%d, http_retry=%d, http_retry_interval=%d",
		geosite_updater.default_interval,
		geosite_updater.diff_algo == GEOSITE_DIFF_MTIME ? "mtime" : geosite_updater.diff_algo == GEOSITE_DIFF_CRC32 ? "crc32" : "md5",
		geosite_updater.use_etag,
		geosite_updater.http_timeout,
		geosite_updater.http_retry,
		geosite_updater.http_retry_interval);

	return 0;
}

/* Config parser for geosite-set directive */
int _config_geosite_set(void *data, int argc, char *argv[])
{
	struct geosite_set *set = NULL;
	struct geosite_dat *dat_ref = NULL;
	char set_name[DNS_MAX_CNAME_LEN] = {0};
	int i;

	if (argc <= 1) {
		tlog(TLOG_ERROR, "geosite-set: invalid parameter.");
		return -1;
	}

	/* Parse: geosite-set <set_name> <geosite1> <geosite2> ... */
	/* argv[0] = "geosite-set", argv[1] = set_name, argv[2+] = geosite names */
	safe_strncpy(set_name, argv[1], DNS_MAX_CNAME_LEN);

	if (set_name[0] == 0) {
		tlog(TLOG_ERROR, "geosite-set: set name is required.");
		return -1;
	}

	/* Check if set already exists */
	uint32_t key = hash_string(set_name);
	hash_for_each_possible(geosite_set_table.sets, set, node, key)
	{
		if (strcmp(set->name, set_name) == 0) {
			tlog(TLOG_WARN, "geosite-set %s already exists, skipping.", set_name);
			return 0;
		}
	}

	set = zalloc(1, sizeof(*set));
	if (set == NULL) {
		tlog(TLOG_ERROR, "geosite-set: cannot allocate memory.");
		return -1;
	}

	INIT_LIST_HEAD(&set->dat_list);
	INIT_HLIST_NODE(&set->node);
	safe_strncpy(set->name, set_name, DNS_MAX_CNAME_LEN);

	/* Add references to geosite-dat entries (start from argv[2]) */
	for (i = 2; i < argc; i++) {
		struct geosite_dat *dat = geosite_dat_get(argv[i]);
		if (dat == NULL) {
			tlog(TLOG_WARN, "geosite-set %s: geosite-dat %s not found, will be resolved later.",
				set_name, argv[i]);
			/* Store as temporary reference, will be resolved later */
		}

		dat_ref = zalloc(1, sizeof(*dat_ref));
		if (dat_ref == NULL) {
			tlog(TLOG_ERROR, "geosite-set: cannot allocate dat reference.");
			free(set);
			return -1;
		}

		INIT_LIST_HEAD(&dat_ref->dat_list);
		safe_strncpy(dat_ref->name, argv[i], DNS_MAX_CNAME_LEN);
		dat_ref->is_url = 0;
		dat_ref->update_interval = 0;

		if (dat) {
			/* Copy file path if dat exists */
			safe_strncpy(dat_ref->file, dat->file, DNS_MAX_PATH);
			dat_ref->is_url = dat->is_url;
			dat_ref->update_interval = dat->update_interval;
			geosite_dat_put(dat);
		}

		list_add_tail(&dat_ref->dat_list, &set->dat_list);
	}

	hash_add(geosite_set_table.sets, &set->node, key);

	/* Also register to domain_set_name_table for domain-rules usage */
	_config_domain_set_geosite_add(set_name);

	tlog(TLOG_DEBUG, "geosite-set %s registered with %d geosite(s)", set_name, argc - 2);

	return 0;
}
