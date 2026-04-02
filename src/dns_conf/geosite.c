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
#include "smartdns/lib/idna.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_CURL
#include <curl/curl.h>
#endif

#ifndef SMARTDNS_VERION
#ifdef COMMIT_VERION
#define SMARTDNS_VERION_STR COMMIT_VERION
#else
#define SMARTDNS_VERION_STR "unknown"
#endif
#else
#define SMARTDNS_VERION_STR SMARTDNS_VERION
#endif

struct geosite_dat_table geosite_dat_table;
struct geosite_set_table geosite_set_table;

static LIST_HEAD(geosite_domain_rule_list);

#define MAX_LINE_LEN 4096

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

static int _domain_cache_collect(const char *domain, void *priv)
{
	struct geosite_domain_cache *cache = (struct geosite_domain_cache *)priv;
	if (cache->count >= GEOSITE_MAX_CACHED_DOMAINS) {
		return 0;
	}
	cache->domains = realloc(cache->domains, (cache->count + 1) * sizeof(char *));
	if (cache->domains == NULL) {
		return -1;
	}
	cache->domains[cache->count] = strdup(domain);
	if (cache->domains[cache->count] == NULL) {
		return -1;
	}
	cache->count++;
	return 0;
}

static int _domain_cache_contains(const struct geosite_domain_cache *cache, const char *domain)
{
	for (int i = 0; i < cache->count; i++) {
		if (strcmp(cache->domains[i], domain) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Check if a domain exists in a geosite file */
static int _domain_cache_contains_file(const char *file, const char *domain)
{
	FILE *fp = fopen(file, "r");
	if (fp == NULL) {
		return 0;
	}
	char line[MAX_LINE_LEN];
	char value[DNS_MAX_CNAME_LEN];
	char normalized[DNS_MAX_CNAME_LEN];
	while (fgets(line, MAX_LINE_LEN, fp)) {
		char *p = line;
		if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) {
			p += 3;
		}
		if (sscanf(p, "%255s", value) <= 0) {
			continue;
		}
		if (value[0] == '#' || value[0] == '\n' || value[0] == '\0') {
			continue;
		}
		char *d_ptr = value;
		while (*d_ptr == '.' && *(d_ptr + 1) != '\0') {
			d_ptr++;
		}
		if (*d_ptr == '\0') {
			continue;
		}
		if (utf8_to_punycode(d_ptr, strlen(d_ptr), normalized, sizeof(normalized)) <= 0) {
			continue;
		}
		if (strcmp(normalized, domain) == 0) {
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
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
	tlog(TLOG_INFO, "geosite: saved domain rule for set '%s' (argc=%d, group=%s)", set_name, argc,
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

void geosite_dat_put(struct geosite_dat *dat)
{
	if (dat && atomic_dec_and_test(&dat->refcnt)) {
		/* Should not happen during normal operation */
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

/* Download file from URL using libcurl */
static int _download_file(const char *url, const char *output_path)
{
	CURL *curl = NULL;
	CURLcode res;
	FILE *fp = NULL;
	long http_code = 0;
	char errbuf[CURL_ERROR_SIZE] = {0};
	char dir[PATH_MAX] = {0};
	int ret = -1;

	/* Ensure output directory exists */
	strncpy(dir, output_path, sizeof(dir) - 1);
	char *last_slash = strrchr(dir, '/');
	if (last_slash != NULL) {
		*last_slash = '\0';
		if (access(dir, F_OK) != 0) {
			char mkdir_cmd[PATH_MAX + 32];
			snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p '%s'", dir);
			system(mkdir_cmd);
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
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "smartdns/" SMARTDNS_VERION_STR);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

	tlog(TLOG_INFO, "geosite: downloading %s", url);
	res = curl_easy_perform(curl);

	if (res == CURLE_OK) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
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

	if (ret != 0) {
		unlink(output_path);
	}

	return ret;
}
#else
/* Download file from URL using wget or curl (fallback) */
static int _download_file(const char *url, const char *output_path)
{
	char cmd[PATH_MAX * 2 + 64];
	int ret;

	/* Try wget first, suppress stderr to avoid "not found" pollution */
	ret = snprintf(cmd, sizeof(cmd),
		"{ wget -q --timeout=300 -O \"%s\" \"%s\" 2>/dev/null || curl -sL --connect-timeout 10 -m 300 -o \"%s\" \"%s\" 2>/dev/null; }",
		output_path, url, output_path, url);
	if (ret < 0 || ret >= (int)sizeof(cmd)) {
		tlog(TLOG_ERROR, "command too long for URL: %s", url);
		return -1;
	}

	tlog(TLOG_INFO, "geosite: downloading %s", url);
	ret = system(cmd);
	if (ret != 0) {
		tlog(TLOG_ERROR, "geosite: download %s failed (wget/curl not available or network error)", url);
		return -1;
	}

	return 0;
}
#endif /* USE_CURL */

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
			tlog(TLOG_WARN, "process geosite file %s failed at line %d, invalid domain %s.", file, line_no, d_ptr);
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

static int _geosite_dat_update(struct geosite_dat *dat)
{
	char temp_file[DNS_MAX_PATH];
	FILE *fp_in = NULL;
	FILE *fp_out = NULL;
	char line[MAX_LINE_LEN];
	char value[DNS_MAX_CNAME_LEN];
	int filed_num = 0;
	int line_no = 0;
	int ret = 0;

	if (!dat->is_url) {
		/* For local files, check mtime to detect changes */
		struct stat st;
		if (stat(dat->file, &st) != 0) {
			tlog(TLOG_WARN, "geosite-dat %s: cannot stat file %s", dat->name, dat->file);
			return -1;
		}
		if ((unsigned int)st.st_mtime == dat->last_update) {
			/* File not modified since last check */
			return -1;
		}
		tlog(TLOG_INFO, "geosite-dat %s: local file updated (old_mtime=%u, new_mtime=%u)",
			 dat->name, dat->last_update, (unsigned int)st.st_mtime);
		dat->last_update = st.st_mtime;
		/*
		 * For local files, the file has already been modified externally
		 * when mtime changes. old_domains was cached at registration time
		 * (or after the previous reload), so it holds the PREVIOUS file
		 * content. This is exactly what we need for diff-based stale rule
		 * removal — domains in old_domains but not in the new file will
		 * have their rules deleted.
		 * Do NOT overwrite old_domains here.
		 */
		return 0;
	}

	/*
	 * For URL sources, cache current domains before downloading new file.
	 * This allows reload to diff old vs new and remove stale rules.
	 */
	_domain_cache_free(&dat->old_domains);
	if (access(dat->file, F_OK) == 0) {
		_parse_geosite_file(dat->file, _domain_cache_collect, &dat->old_domains);
	}

	/* Create temp file for downloaded content */
	snprintf(temp_file, sizeof(temp_file), "%s.XXXXXX", dat->file);
	int fd = mkstemp(temp_file);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create temp file failed for %s: %s", dat->name, strerror(errno));
		return -1;
	}
	close(fd);

	/* Download to temp file */
	ret = _download_file(dat->url, temp_file);
	if (ret != 0) {
		unlink(temp_file);
		return ret;
	}

	/* Verify the downloaded file is valid (contains domains) */
	fp_in = fopen(temp_file, "r");
	if (fp_in == NULL) {
		tlog(TLOG_ERROR, "open temp file %s failed: %s", temp_file, strerror(errno));
		unlink(temp_file);
		return -1;
	}

	/* Create output file */
	char out_file[DNS_MAX_PATH];
	snprintf(out_file, sizeof(out_file), "%s.new", dat->file);
	fp_out = fopen(out_file, "w");
	if (fp_out == NULL) {
		tlog(TLOG_ERROR, "create output file %s failed: %s", out_file, strerror(errno));
		fclose(fp_in);
		unlink(temp_file);
		return -1;
	}

	/* Parse and rewrite the file (normalize domains) */
	while (fgets(line, MAX_LINE_LEN, fp_in)) {
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
			fprintf(fp_out, "%s", line);
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

		if (*d_ptr == '\0') {
			fprintf(fp_out, "%s", line);
			continue;
		}

		/* Convert to punycode if needed */
		if (utf8_to_punycode(d_ptr, strlen(d_ptr), domain, sizeof(domain)) <= 0) {
			fprintf(fp_out, "%s", line);
			continue;
		}

		/* Write normalized domain */
		fprintf(fp_out, "%s\n", domain);
	}

	fclose(fp_in);
	fclose(fp_out);

	/* Replace original file with new file */
	ret = rename(out_file, dat->file);
	if (ret != 0) {
		tlog(TLOG_ERROR, "rename %s to %s failed: %s", out_file, dat->file, strerror(errno));
		unlink(out_file);
		unlink(temp_file);
		return -1;
	}

	unlink(temp_file);

	/* Update last update time */
	dat->last_update = time(NULL);

	tlog(TLOG_INFO, "geosite-dat %s updated from %s", dat->name, dat->file);

	return 0;
}

/* Check and update all geosite data sources */
int geosite_check_and_update(void)
{
	struct geosite_dat *dat = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;
	unsigned int now = time(NULL);
	int updated = 0;

	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (dat->update_interval <= 0) {
			continue;
		}

		/* Check if update is needed */
		if (dat->last_update == 0 || (now - dat->last_update) >= (unsigned int)dat->update_interval) {
			tlog(TLOG_DEBUG, "checking geosite-dat %s for update (interval=%d, last=%u, now=%u)",
				dat->name, dat->update_interval, dat->last_update, now);
			if (_geosite_dat_update(dat) == 0) {
				dat->need_update = 1;
				updated = 1;
			}
		}
	}

	/* If any dat was updated, reload domain rules that reference geosite-sets */
	if (updated) {
		struct geosite_domain_rule_entry *entry = NULL;
		struct geosite_domain_rule_entry *tmp_entry = NULL;
		struct dns_conf_group_info tmp_group_info;

		/*
		 * Set up a temporary group context. We'll switch to the correct group
		 * (tracked by entry->rule_group) for each entry before delete/add.
		 */
		memset(&tmp_group_info, 0, sizeof(tmp_group_info));
		tmp_group_info.rule = dns_conf_rule.default_conf;

		tlog(TLOG_INFO, "geosite: %d dat(s) updated, reloading domain rules", updated);
		list_for_each_entry_safe(entry, tmp_entry, &geosite_domain_rule_list, list)
		{
			tlog(TLOG_INFO, "geosite: reloading domain rules for set '%s' (argc=%d, group=%s)", entry->set_name, entry->argc,
				 entry->rule_group[0] ? entry->rule_group : "(default)");

			/*
			 * Set the current group to match where the rule was originally added.
			 * This ensures _config_domain_rule_delete removes from the correct group.
			 */
			if (entry->rule_group[0] != '\0') {
				tmp_group_info.group_name = entry->rule_group;
				tmp_group_info.rule = _config_rule_group_get(entry->rule_group);
				if (tmp_group_info.rule == NULL) {
					tmp_group_info.rule = dns_conf_rule.default_conf;
					tlog(TLOG_WARN, "geosite: rule group '%s' not found, using default", entry->rule_group);
				}
			} else {
				tmp_group_info.group_name = NULL;
				tmp_group_info.rule = dns_conf_rule.default_conf;
			}
			_config_set_current_group(&tmp_group_info);

			/*
			 * Remove stale rules for updated geosite-dats.
			 *
			 * Strategy:
			 * - URL sources: old_domains was cached BEFORE download, so we
			 *   diff old vs new and only delete domains no longer in the file.
			 * - Local files: old_domains was cached AFTER external modification,
			 *   so it contains the current (new) content. We delete ALL cached
			 *   domains' rules, then re-add. This correctly handles removals.
			 */
			/* entry->set_name is "/geosite-set:NAME/" — extract NAME */
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
					struct geosite_dat *dat = geosite_dat_get(dat_ref->name);
					if (dat == NULL || !dat->need_update) {
						if (dat) geosite_dat_put(dat);
						continue;
					}
					geosite_dat_put(dat);

					/*
					 * Remove stale rules: old_domains holds domains from the
					 * PREVIOUS file content (cached at registration or after
					 * the last reload). For each cached domain, check if it
					 * still exists in the current file. If not, delete its rule.
					 */
					for (int d = 0; d < dat->old_domains.count; d++) {
						const char *old_domain = dat->old_domains.domains[d];
						int still_exists = 0;
						if (access(dat->file, F_OK) == 0) {
							still_exists = _domain_cache_contains_file(dat->file, old_domain);
						}
						if (still_exists) {
							continue;
						}
						tlog(TLOG_DEBUG, "geosite: removing stale rule for domain '%s' (dat %s)",
							 old_domain, dat->name);
						_config_domain_rule_delete(old_domain);
					}
				}
			}

		re_add:
			/*
			 * Re-add rules with saved argv.
			 * getopt_long_only() permutes argv, so we must pass a copy
			 * to preserve the original order for future reloads.
			 */
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

			tlog(TLOG_INFO, "geosite: reloaded domain rules for set '%s'", entry->set_name);
		}

		/*
		 * After processing all entries, pop back to the base group.
		 * We use a separate pop loop here, outside the entry iteration,
		 * to avoid interfering with the per-entry group context.
		 */
		while (dns_conf_current_group_info != NULL && dns_conf_current_group_info->rule != dns_conf_rule.default_conf) {
			_config_current_group_pop();
		}
		_config_set_current_group(&tmp_group_info);

		/*
		 * After all entries are processed, refresh old_domains cache for
		 * each updated dat. This snapshot captures the current file content
		 * so that the NEXT file modification can be correctly diffed against
		 * the domains whose rules are currently active in the ART tree.
		 */
		hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
		{
			if (!dat->need_update) {
				continue;
			}
			dat->need_update = 0;
			_domain_cache_free(&dat->old_domains);
			if (access(dat->file, F_OK) == 0) {
				_parse_geosite_file(dat->file, _domain_cache_collect, &dat->old_domains);
			}
			tlog(TLOG_INFO, "geosite: refreshed domain cache for dat '%s' (%d domains)",
				 dat->name, dat->old_domains.count);
		}

		/* Restore dns_conf_current_group_info to NULL.
		 * _config_set_current_group(NULL) is a no-op (returns immediately),
		 * so we must clear the pointer directly. */
		dns_conf_current_group_info = NULL;
	}

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
	int update_interval = GEOSITE_DEFAULT_UPDATE_INTERVAL;
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
			update_interval = GEOSITE_DEFAULT_UPDATE_INTERVAL;
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
				update_interval = GEOSITE_DEFAULT_UPDATE_INTERVAL;
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

	if (!dat->is_url) {
		/* Local file */
		conf_get_conf_fullpath(file, dat->file, DNS_MAX_PATH);

		/* Check if file exists */
		if (access(dat->file, F_OK) != 0) {
			tlog(TLOG_ERROR, "geosite-dat %s: file %s not accessible. %s", name, dat->file, strerror(errno));
			free(dat);
			return -1;
		}

		/* Record initial mtime for local files */
		struct stat st;
		if (stat(dat->file, &st) == 0) {
			dat->last_update = st.st_mtime;
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
		/* For URL, construct the local cache file path */
		/* Use data directory or a default location */
		const char *data_dir = dns_conf_get_data_dir();
		char cache_file[DNS_MAX_PATH];
		snprintf(cache_file, sizeof(cache_file), "%s/geosite-%s.list", data_dir, name);
		conf_get_conf_fullpath(cache_file, dat->file, DNS_MAX_PATH);

		/* Store the original URL */
		safe_strncpy(dat->url, argv[2], DNS_MAX_PATH);

		/* Download if local file doesn't exist */
		if (access(dat->file, F_OK) != 0) {
			tlog(TLOG_INFO, "geosite-dat %s: downloading from %s", name, dat->url);
			if (_download_file(dat->url, dat->file) == 0) {
				dat->last_update = time(NULL);
			} else {
				tlog(TLOG_WARN, "geosite-dat %s: initial download failed, will retry later.", name);
			}
		}
	}

	hash_add(geosite_dat_table.dats, &dat->node, key);

	tlog(TLOG_INFO, "geosite-dat %s registered: file=%s, url=%s, interval=%d, is_url=%d",
		dat->name, dat->file, dat->url, dat->update_interval, dat->is_url);

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

	tlog(TLOG_INFO, "geosite-set %s registered with %d geosite(s)", set_name, argc - 2);

	return 0;
}
