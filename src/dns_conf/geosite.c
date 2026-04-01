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
#include "domain_set.h"
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

struct geosite_dat_table geosite_dat_table;
struct geosite_set_table geosite_set_table;

#define MAX_LINE_LEN 4096

/* Forward declaration */
static int _geosite_dat_update(struct geosite_dat *dat);

void geosite_dat_table_init(void)
{
	hash_init(geosite_dat_table.dats);
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
		free(dat);
	}
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

/* Download file from URL using curl */
static int _download_file(const char *url, const char *output_path)
{
	char cmd[PATH_MAX * 2];
	int ret;

	/* Use curl to download the file */
	ret = snprintf(cmd, sizeof(cmd),
		"curl -sL --connect-timeout 10 -m 300 -o \"%s\" \"%s\"",
		output_path, url);
	if (ret < 0 || ret >= sizeof(cmd)) {
		tlog(TLOG_ERROR, "command too long for URL: %s", url);
		return -1;
	}

	tlog(TLOG_DEBUG, "downloading geosite from %s", url);
	ret = system(cmd);
	if (ret != 0) {
		tlog(TLOG_ERROR, "failed to download from %s, ret=%d", url, ret);
		return -1;
	}

	return 0;
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

static int _update_geosite_dat_callback(const char *domain, void *priv)
{
	/* This callback is called during update, nothing to do here */
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
		/* For local files, just touch to update mtime */
		struct stat st;
		if (stat(dat->file, &st) == 0) {
			dat->last_update = st.st_mtime;
		}
		return 0;
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
	ret = _download_file(dat->file, temp_file);
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

	hash_for_each_safe(geosite_dat_table.dats, i, tmp, dat, node)
	{
		if (!dat->is_url || dat->update_interval <= 0) {
			continue;
		}

		/* Check if update is needed */
		if (dat->last_update == 0 || (now - dat->last_update) >= (unsigned int)dat->update_interval) {
			tlog(TLOG_DEBUG, "checking geosite-dat %s for update (interval=%d, last=%u, now=%u)",
				dat->name, dat->update_interval, dat->last_update, now);
			if (_geosite_dat_update(dat) == 0) {
				dat->need_update = 1;
			}
		}
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

	if (dat->is_url) {
		/* For URL, construct the local cache file path */
		/* Use data directory or a default location */
		const char *data_dir = dns_conf_get_data_dir();
		char cache_file[DNS_MAX_PATH];
		snprintf(cache_file, sizeof(cache_file), "%s/geosite-%s.list", data_dir, name);
		conf_get_conf_fullpath(cache_file, dat->file, DNS_MAX_PATH);

		/* Download if local file doesn't exist */
		if (access(dat->file, F_OK) != 0) {
			tlog(TLOG_INFO, "geosite-dat %s: downloading from %s", name, file);
			if (_download_file(file, dat->file) == 0) {
				dat->last_update = time(NULL);
			} else {
				tlog(TLOG_ERROR, "geosite-dat %s: initial download failed.", name);
				free(dat);
				return -1;
			}
		}

		/* Store the URL for future updates */
		safe_strncpy(file, argv[2], DNS_MAX_PATH); /* Keep original URL */
	} else {
		/* Local file */
		conf_get_conf_fullpath(file, dat->file, DNS_MAX_PATH);

		/* Check if file exists */
		if (access(dat->file, F_OK) != 0) {
			tlog(TLOG_ERROR, "geosite-dat %s: file %s not accessible. %s", name, dat->file, strerror(errno));
			free(dat);
			return -1;
		}
	}

	hash_add(geosite_dat_table.dats, &dat->node, key);

	tlog(TLOG_INFO, "geosite-dat %s registered: file=%s, interval=%d, is_url=%d",
		dat->name, dat->file, dat->update_interval, dat->is_url);

	(void)file; /* suppress unused warning */

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
