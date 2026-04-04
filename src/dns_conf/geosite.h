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

#ifndef _DNS_CONF_GEOSITE_H_
#define _DNS_CONF_GEOSITE_H_

#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#define GEOSITE_DEFAULT_UPDATE_INTERVAL 300

/* Maximum cached domains per geosite-dat (for reload diff) */
#define GEOSITE_MAX_CACHED_DOMAINS 65536

/* Diff algorithms for detecting file changes */
enum geosite_diff_algo {
	GEOSITE_DIFF_MTIME = 0,
	GEOSITE_DIFF_CRC32,
	GEOSITE_DIFF_MD5,
};

/* geosite-updater configuration */
struct geosite_updater_config {
	int default_interval;                     /* default update interval (seconds) */
	enum geosite_diff_algo diff_algo;         /* file change detection algorithm */
	int use_etag;                             /* 1 = use HTTP ETag for URL updates */
	char user_agent[256];                     /* HTTP User-Agent for downloads */
	char data_dir[DNS_MAX_PATH];              /* directory for URL-downloaded files */
	int http_timeout;                         /* HTTP download timeout in seconds */
	int http_retry;                           /* HTTP download retry count */
	int http_retry_interval;                  /* seconds to wait between retries (default 3) */
};

/* Cached domain list for reload diff */
struct geosite_domain_cache {
	char **domains;  /* array of domain strings */
	int count;       /* number of cached domains */
};

struct geosite_dat {
	struct hlist_node node;             /* for hash table */
	struct list_head dat_list;          /* for linking in geosite_set */
	char name[DNS_MAX_CNAME_LEN];      /* geosite name, e.g., "google", "tencent" */
	char file[DNS_MAX_PATH];           /* local file path */
	char url[DNS_MAX_PATH];            /* original URL (only if is_url == 1) */
	int update_interval;               /* update interval in seconds, 0 means no update */
	unsigned int last_update;           /* last update timestamp (or mtime for local files) */
	atomic_t refcnt;                   /* reference count */
	int is_url;                        /* 1 if source is a URL */
	int need_update;                   /* flag indicating update is needed */
	int downloading;                   /* 1 if download is in progress */
	char etag[128];                    /* last HTTP ETag for URL sources */
	char file_hash[33];                /* CRC32 (8 hex) or MD5 (32 hex) hash */
	struct geosite_domain_cache old_domains; /* cached domains before last update */
	struct geosite_domain_cache new_domains; /* pre-loaded domains from current file (for reload diff) */
};

/* Saved domain-rules for reload on geosite data update */
struct geosite_domain_rule_entry {
	struct list_head list;
	char set_name[DNS_MAX_CNAME_LEN];  /* domain-set/geosite-set name */
	char rule_group[DNS_MAX_CONF_CNAME_LEN]; /* group where rules should be stored */
	int argc;
	char **argv;                       /* saved argv for _config_domain_rules replay */
};

struct geosite_set {
	struct hlist_node node;
	char name[DNS_MAX_CNAME_LEN];      /* set name, e.g., "test", "block" */
	struct list_head dat_list;          /* list of geosite_dat references */
};

struct geosite_dat_table {
	DECLARE_HASHTABLE(dats, 4);
};

struct geosite_set_table {
	DECLARE_HASHTABLE(sets, 4);
};

extern struct geosite_dat_table geosite_dat_table;
extern struct geosite_set_table geosite_set_table;

/* Initialize/destroy tables */
void geosite_dat_table_init(void);
void geosite_dat_table_destroy(void);
void geosite_set_table_init(void);
void geosite_set_table_destroy(void);

/* Config parser for geosite-dat directive */
int _config_geosite_dat(void *data, int argc, char *argv[]);

/* Config parser for geosite-set directive */
int _config_geosite_set(void *data, int argc, char *argv[]);

/* Config parser for geosite-updater directive */
int _config_geosite_updater(void *data, int argc, char *argv[]);

/* Get the global geosite updater config */
const struct geosite_updater_config *geosite_get_updater_config(void);

/* Domain iteration callback for geosite */
typedef int (*geosite_domain_cb)(const char *domain, void *priv);

/* Iterate domains in a geosite-set */
int geosite_set_foreach_domain(const char *set_name, geosite_domain_cb callback, void *priv);

/* Iterate domains in a single geosite-dat */
int geosite_dat_foreach_domain(const char *dat_name, geosite_domain_cb callback, void *priv);

/* Check and update geosite data if needed (non-blocking, triggers async download) */
int geosite_check_and_download(void);

/* Synchronously download all URL-based geosite-dat files.
 * Blocks until all downloads complete and rules are reloaded.
 * Used by --check-domain-rule to ensure latest data before checking. */
int geosite_download_url_files_sync(void);

/* Reload geosite rules into ART tree (called on main thread after download completes) */
int geosite_reload_rules(void);

/* Get the eventfd for async download notification */
int geosite_get_download_event_fd(void);

/* Initialize async download eventfd */
int geosite_download_event_init(void);

/* Destroy async download eventfd */
void geosite_download_event_destroy(void);

/* Get geosite feature build version string, e.g. "geosite(260403-1322)" */
const char *geosite_build_version(void);

/* Log geosite configuration summary (call after tlog_init) */
void geosite_log_config_summary(void);

/* Get geosite dat by name */
struct geosite_dat *geosite_dat_get(const char *name);

/* Put back geosite dat reference */
void geosite_dat_put(struct geosite_dat *dat);

/* Save domain-rules argv for reload when geosite data changes */
void geosite_save_domain_rule(const char *set_name, int argc, char *argv[]);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif // !_DNS_CONF_GEOSITE_H_
