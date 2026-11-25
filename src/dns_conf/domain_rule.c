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

#include "domain_rule.h"
#include "geosite.h"
#include "address.h"
#include "cname.h"
#include "dns_conf_group.h"
#include "https_record.h"
#include "ipset.h"
#include "nameserver.h"
#include "nftset.h"
#include "server_group.h"
#include "set_file.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"
#include "smartdns/dns_cache.h"
#include "speed_check_mode.h"
#include "txt_record.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static inline uint8_t _get_required_capacity(enum domain_rule type, uint8_t current_capacity)
{
	uint8_t required = type + 1;

	/* Ensure type is within valid range */
	if (type >= DOMAIN_RULE_MAX || type < 0) {
		return 0;
	}

	if (current_capacity == 0) {
		return required;
	}

	/* Expand by 2 slots at a time, but cap at DOMAIN_RULE_MAX */
	uint8_t new_capacity = ((required - current_capacity + 1) / 2) * 2 + current_capacity;

	if (new_capacity > DOMAIN_RULE_MAX) {
		new_capacity = DOMAIN_RULE_MAX;
	}

	return new_capacity;
}

static struct dns_domain_rule *_alloc_domain_rule(uint8_t capacity)
{
	size_t size = sizeof(struct dns_domain_rule) + capacity * sizeof(struct dns_rule *);
	struct dns_domain_rule *rule = malloc(size);

	if (rule == NULL) {
		return NULL;
	}

	memset(rule, 0, size);
	rule->capacity = capacity;
	atomic32_set(&rule->refcnt, 1);

	return rule;
}

/*
 * Check if domain string is a domain-set or geosite-set reference.
 * Returns the set name pointer after the prefix, or NULL if not a set reference.
 */
static inline const char *_domain_get_set_name(const char *domain)
{
	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		return domain + sizeof("domain-set:") - 1;
	}
	if (strncmp(domain, "geosite-set:", sizeof("geosite-set:") - 1) == 0) {
		return domain + sizeof("geosite-set:") - 1;
	}
	return NULL;
}

/*
 * Ensure the domain rule has enough capacity for the given rule type
 * Returns a private copy when growing or detaching a shared leaf.
 * The caller replaces the ART value and releases the old leaf on success.
 */
static struct dns_domain_rule *_ensure_domain_rule_capacity(struct dns_domain_rule *domain_rule, enum domain_rule type)
{
	if (type >= DOMAIN_RULE_MAX || type < 0) {
		tlog(TLOG_ERROR, "Invalid domain rule type %d", type);
		return NULL;
	}

	if (domain_rule == NULL) {
		uint8_t capacity = _get_required_capacity(type, 0);
		return _alloc_domain_rule(capacity);
	}

	/* a shared rule (refcnt > 1) is immutable: copy it before changing it */
	if (type < domain_rule->capacity && atomic32_read(&domain_rule->refcnt) == 1) {
		return domain_rule;
	}

	uint8_t new_capacity = type < domain_rule->capacity ? domain_rule->capacity :
		_get_required_capacity(type, domain_rule->capacity);
	if (new_capacity == 0) {
		return NULL;
	}

	struct dns_domain_rule *new_rule = _alloc_domain_rule(new_capacity);
	if (new_rule == NULL) {
		return NULL;
	}

	for (int i = 0; i < domain_rule->capacity; i++) {
		if (domain_rule->rules[i]) {
			_dns_rule_get(domain_rule->rules[i]);
			new_rule->rules[i] = domain_rule->rules[i];
		}
	}

	return new_rule;
}

/* Large block lists commonly contain the same flags-only value at every leaf.
 * Keep a bounded configuration-lifetime pool; full/colliding buckets simply
 * retain private values. Shared leaves and their flags must never be mutated.
 * Query paths do not consult this pool. Each entry owns one leaf reference.
 */
#define DOMAIN_RULE_POOL_SIZE 1024
#define DOMAIN_RULE_POOL_PROBES 8
static struct dns_domain_rule *domain_rule_pool[DOMAIN_RULE_POOL_SIZE];

static struct dns_domain_rule *_domain_rule_intern_flags(struct dns_domain_rule *rule)
{
	if (rule->capacity != 1 || rule->rules[DOMAIN_RULE_FLAGS] == NULL) {
		return rule;
	}
	struct dns_rule_flags *flags = (struct dns_rule_flags *)rule->rules[DOMAIN_RULE_FLAGS];
	uint32_t hash = flags->flags * 2654435761U ^ flags->is_flag_set * 2246822519U ^
		(unsigned int)flags->head.sub_only * 3266489917U ^ (unsigned int)flags->head.root_only;
	hash ^= hash >> 16;
	hash ^= hash >> 8;
	for (unsigned int i = 0; i < DOMAIN_RULE_POOL_PROBES; i++) {
		struct dns_domain_rule **slot = &domain_rule_pool[(hash + i) & (DOMAIN_RULE_POOL_SIZE - 1)];
		if (*slot == rule) {
			return rule;
		}
		if (*slot == NULL) {
			atomic32_inc(&rule->refcnt);
			*slot = rule;
			return rule;
		}
		struct dns_rule_flags *other = (struct dns_rule_flags *)(*slot)->rules[DOMAIN_RULE_FLAGS];
		if (flags->flags == other->flags && flags->is_flag_set == other->is_flag_set &&
			flags->head.sub_only == other->head.sub_only && flags->head.root_only == other->head.root_only) {
			atomic32_inc(&(*slot)->refcnt);
			return *slot;
		}
	}
	return rule;
}

void _config_domain_rule_pool_clear(void)
{
	for (unsigned int i = 0; i < DOMAIN_RULE_POOL_SIZE; i++) {
		_config_domain_rule_free(domain_rule_pool[i]);
		domain_rule_pool[i] = NULL;
	}
}

struct dns_rule_info {
	int size;
	int (*get_size)(struct dns_rule *rule);
	void (*clone)(struct dns_rule *new_rule, struct dns_rule *old_rule);
	void (*append)(struct dns_rule *curr_rule, struct dns_rule *new_rule);
	void (*destroy)(struct dns_rule *rule);
	unsigned char is_list : 1;
};



static int _rule_address_ipv4_get_size(struct dns_rule *rule)
{
	return sizeof(struct dns_rule_address_IPV4) + ((struct dns_rule_address_IPV4 *)rule)->addr_num * DNS_RR_A_LEN;
}

static int _rule_address_ipv6_get_size(struct dns_rule *rule)
{
	return sizeof(struct dns_rule_address_IPV6) + ((struct dns_rule_address_IPV6 *)rule)->addr_num * DNS_RR_AAAA_LEN;
}

static void _rule_https_clone(struct dns_rule *new_rule, struct dns_rule *old_rule)
{
	struct dns_https_record_rule *new_https = (struct dns_https_record_rule *)new_rule;
	struct dns_https_record_rule *old_https = (struct dns_https_record_rule *)old_rule;
	struct dns_https_record *record;

	INIT_LIST_HEAD(&new_https->record_list);
	if (old_https->record_list.next != NULL && old_https->record_list.prev != NULL) {
		list_for_each_entry(record, &old_https->record_list, list)
		{
			struct dns_https_record *new_record = malloc(sizeof(struct dns_https_record));
			if (new_record) {
				memcpy(new_record, record, sizeof(struct dns_https_record));
				list_add_tail(&new_record->list, &new_https->record_list);
			}
		}
	}
}

static void _rule_srv_clone(struct dns_rule *new_rule, struct dns_rule *old_rule)
{
	struct dns_srv_record_rule *new_srv = (struct dns_srv_record_rule *)new_rule;
	struct dns_srv_record_rule *old_srv = (struct dns_srv_record_rule *)old_rule;
	struct dns_srv_record *record;

	INIT_LIST_HEAD(&new_srv->record_list);
	if (old_srv->record_list.next != NULL && old_srv->record_list.prev != NULL) {
		list_for_each_entry(record, &old_srv->record_list, list)
		{
			struct dns_srv_record *new_record = malloc(sizeof(struct dns_srv_record));
			if (new_record) {
				memcpy(new_record, record, sizeof(struct dns_srv_record));
				list_add_tail(&new_record->list, &new_srv->record_list);
			}
		}
	}
}

static void _rule_txt_clone(struct dns_rule *new_rule, struct dns_rule *old_rule)
{
	struct dns_txt_record_rule *new_txt = (struct dns_txt_record_rule *)new_rule;
	struct dns_txt_record_rule *old_txt = (struct dns_txt_record_rule *)old_rule;
	struct dns_txt_record *record;

	INIT_LIST_HEAD(&new_txt->record_list);
	if (old_txt->record_list.next != NULL && old_txt->record_list.prev != NULL) {
		list_for_each_entry(record, &old_txt->record_list, list)
		{
			struct dns_txt_record *new_record = malloc(sizeof(struct dns_txt_record));
			if (new_record) {
				memcpy(new_record, record, sizeof(struct dns_txt_record));
				list_add_tail(&new_record->list, &new_txt->record_list);
			}
		}
	}
}

static void _rule_nftset_clone(struct dns_rule *new_rule, struct dns_rule *old_rule)
{
	struct dns_nftset_rule *new_nft = (struct dns_nftset_rule *)new_rule;
	struct dns_nftset_rule *old_nft = (struct dns_nftset_rule *)old_rule;
	struct dns_nftset_rule *prev = new_nft;

	new_nft->next = NULL;
	for (old_nft = old_nft->next; old_nft; old_nft = old_nft->next) {
		struct dns_nftset_rule *copy = (struct dns_nftset_rule *)_new_dns_rule(old_rule->rule);
		if (!copy) {
			break;
		}
		copy->familyname = old_nft->familyname;
		copy->nfttablename = old_nft->nfttablename;
		copy->nftsetname = old_nft->nftsetname;
		copy->next = NULL;
		prev->next = copy;
		prev = copy;
	}
}

static void _rule_ipset_clone(struct dns_rule *new_rule, struct dns_rule *old_rule)
{
	struct dns_ipset_rule *new_ipset = (struct dns_ipset_rule *)new_rule;
	struct dns_ipset_rule *old_ipset = (struct dns_ipset_rule *)old_rule;
	struct dns_ipset_rule *prev = new_ipset;

	new_ipset->next = NULL;
	for (old_ipset = old_ipset->next; old_ipset; old_ipset = old_ipset->next) {
		struct dns_ipset_rule *copy = (struct dns_ipset_rule *)_new_dns_rule(old_rule->rule);
		if (!copy) {
			break;
		}
		copy->ipsetname = old_ipset->ipsetname;
		copy->next = NULL;
		prev->next = copy;
		prev = copy;
	}
}

static void _rule_nftset_append(struct dns_rule *curr_rule, struct dns_rule *new_rule)
{
	struct dns_nftset_rule *tail = (struct dns_nftset_rule *)curr_rule;
	struct dns_nftset_rule *new_nft = (struct dns_nftset_rule *)new_rule;
	while (tail->next) {
		tail = tail->next;
	}
	new_nft->next = NULL;
	tail->next = new_nft;
}

static void _rule_ipset_append(struct dns_rule *curr_rule, struct dns_rule *new_rule)
{
	struct dns_ipset_rule *tail = (struct dns_ipset_rule *)curr_rule;
	struct dns_ipset_rule *new_ipset = (struct dns_ipset_rule *)new_rule;
	while (tail->next) {
		tail = tail->next;
	}
	new_ipset->next = NULL;
	tail->next = new_ipset;
}

static void _rule_https_destroy(struct dns_rule *rule)
{
	struct dns_https_record_rule *https_rule = (struct dns_https_record_rule *)rule;
	struct dns_https_record *record, *tmp;
	if (https_rule->record_list.next != NULL && https_rule->record_list.prev != NULL) {
		list_for_each_entry_safe(record, tmp, &https_rule->record_list, list)
		{
			list_del(&record->list);
			free(record);
		}
	}
}

static void _rule_srv_destroy(struct dns_rule *rule)
{
	struct dns_srv_record_rule *srv_rule = (struct dns_srv_record_rule *)rule;
	struct dns_srv_record *record, *tmp;
	if (srv_rule->record_list.next != NULL && srv_rule->record_list.prev != NULL) {
		list_for_each_entry_safe(record, tmp, &srv_rule->record_list, list)
		{
			list_del(&record->list);
			free(record);
		}
	}
}

static void _rule_txt_destroy(struct dns_rule *rule)
{
	struct dns_txt_record_rule *txt_rule = (struct dns_txt_record_rule *)rule;
	struct dns_txt_record *record, *tmp;
	if (txt_rule->record_list.next != NULL && txt_rule->record_list.prev != NULL) {
		list_for_each_entry_safe(record, tmp, &txt_rule->record_list, list)
		{
			list_del(&record->list);
			free(record);
		}
	}
}

static void _rule_nftset_destroy(struct dns_rule *rule)
{
	struct dns_nftset_rule *nft = ((struct dns_nftset_rule *)rule)->next;
	while (nft) {
		struct dns_nftset_rule *tmp_nft = nft->next;
		nft->next = NULL;
		_dns_rule_put(&nft->head);
		nft = tmp_nft;
	}
}

static void _rule_ipset_destroy(struct dns_rule *rule)
{
	struct dns_ipset_rule *ipset = ((struct dns_ipset_rule *)rule)->next;
	while (ipset) {
		struct dns_ipset_rule *tmp_ipset = ipset->next;
		ipset->next = NULL;
		_dns_rule_put(&ipset->head);
		ipset = tmp_ipset;
	}
}

static struct dns_rule_info dns_rule_info_table[DOMAIN_RULE_MAX] = {
	[DOMAIN_RULE_FLAGS] = {sizeof(struct dns_rule_flags), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_ADDRESS_IPV4] = {sizeof(struct dns_rule_address_IPV4), _rule_address_ipv4_get_size, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_ADDRESS_IPV6] = {sizeof(struct dns_rule_address_IPV6), _rule_address_ipv6_get_size, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_NAMESERVER] = {sizeof(struct dns_nameserver_rule), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_CHECKSPEED] = {sizeof(struct dns_domain_check_orders), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_IPSET] = {sizeof(struct dns_ipset_rule), NULL, _rule_ipset_clone, _rule_ipset_append, _rule_ipset_destroy, 1},
	[DOMAIN_RULE_NFTSET_IP] = {sizeof(struct dns_nftset_rule), NULL, _rule_nftset_clone, _rule_nftset_append, _rule_nftset_destroy, 1},
	[DOMAIN_RULE_IPSET_IPV4] = {sizeof(struct dns_ipset_rule), NULL, _rule_ipset_clone, _rule_ipset_append, _rule_ipset_destroy, 1},
	[DOMAIN_RULE_GROUP] = {sizeof(struct dns_group_rule), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_NFTSET_IP6] = {sizeof(struct dns_nftset_rule), NULL, _rule_nftset_clone, _rule_nftset_append, _rule_nftset_destroy, 1},
	[DOMAIN_RULE_IPSET_IPV6] = {sizeof(struct dns_ipset_rule), NULL, _rule_ipset_clone, _rule_ipset_append, _rule_ipset_destroy, 1},

	[DOMAIN_RULE_HTTPS] = {sizeof(struct dns_https_record_rule), NULL, _rule_https_clone, NULL, _rule_https_destroy, 0},
	[DOMAIN_RULE_SRV] = {sizeof(struct dns_srv_record_rule), NULL, _rule_srv_clone, NULL, _rule_srv_destroy, 0},
	[DOMAIN_RULE_RESPONSE_MODE] = {sizeof(struct dns_response_mode_rule), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_CNAME] = {sizeof(struct dns_cname_rule), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_TTL] = {sizeof(struct dns_ttl_rule), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_NAME] = {sizeof(struct dns_name_rule), NULL, NULL, NULL, NULL, 0},
	[DOMAIN_RULE_TXT] = {sizeof(struct dns_txt_record_rule), NULL, _rule_txt_clone, NULL, _rule_txt_destroy, 0},
};

/* Auto-name counter for unnamed domain rules, starts at 10000 */
static int _domain_rule_auto_name_counter = 10000;

void _domain_rule_auto_name_reset(void)
{
	_domain_rule_auto_name_counter = 10000;
}

struct _check_name_unique_ctx {
	const char *target_name;
	int found_duplicate;
};

static int _check_name_unique_cb(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct _check_name_unique_ctx *ctx = (struct _check_name_unique_ctx *)data;
	struct dns_domain_rule *domain_rule = (struct dns_domain_rule *)value;

	if (DOMAIN_RULE_NAME < domain_rule->capacity && domain_rule->rules[DOMAIN_RULE_NAME] != NULL) {
		struct dns_name_rule *name_rule = (struct dns_name_rule *)domain_rule->rules[DOMAIN_RULE_NAME];
		if (name_rule->name != NULL && strcmp(name_rule->name, ctx->target_name) == 0) {
			ctx->found_duplicate = 1;
			return -1; /* stop iteration */
		}
	}
	return 0; /* continue */
}

static int _check_domain_rule_name_unique(const char *name)
{
	struct dns_conf_group *rg = _config_current_rule_group();
	if (rg == NULL || name == NULL) {
		return 0;
	}

	struct _check_name_unique_ctx ctx = {.target_name = name, .found_duplicate = 0};
	art_iter(&rg->domain_rule.tree, _check_name_unique_cb, &ctx);
	return ctx.found_duplicate ? -1 : 0;
}

static int _conf_domain_rule_name(const char *domain, const char *name, char is_auto)
{
	struct dns_name_rule *name_rule = NULL;

	if (name == NULL || strlen(name) == 0) {
		return -1;
	}

	/* Check uniqueness */
	if (!is_auto && _check_domain_rule_name_unique(name) != 0) {
		tlog(TLOG_ERROR, "domain-rules '%s': name '%s' is already used, must be unique", domain, name);
		return -1;
	}

	name_rule = _new_dns_rule(DOMAIN_RULE_NAME);
	if (name_rule == NULL) {
		tlog(TLOG_ERROR, "allocate memory for domain name rule failed.");
		return -1;
	}

	name_rule->name = strdup(name);
	if (name_rule->name == NULL) {
		_dns_rule_put(&name_rule->head);
		tlog(TLOG_ERROR, "strdup for domain name failed.");
		return -1;
	}
	name_rule->is_auto = is_auto;

	if (_config_domain_rule_add(domain, DOMAIN_RULE_NAME, name_rule) != 0) {
		_dns_rule_put(&name_rule->head);
		return -1;
	}

	return 0;
}

static const char *_get_domain_rule_auto_name(void)
{
	static char auto_name[32];
	snprintf(auto_name, sizeof(auto_name), "drn-%d", _domain_rule_auto_name_counter++);
	return auto_name;
}

void *_new_dns_rule_ext(enum domain_rule domain_rule, int ext_size)
{
	struct dns_rule *rule;
	int size = 0;

	if (domain_rule >= DOMAIN_RULE_MAX) {
		return NULL;
	}

	size = dns_rule_info_table[domain_rule].size + ext_size;
	if (size <= 0) {
		return NULL;
	}

	rule = zalloc(1, size);
	if (!rule) {
		return NULL;
	}
	rule->rule = domain_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

void *_new_dns_rule(enum domain_rule domain_rule)
{
	return _new_dns_rule_ext(domain_rule, 0);
}

static struct dns_rule *_dns_rule_clone(struct dns_rule *rule)
{
	int size = 0;
	struct dns_rule *new_rule;

	if (rule == NULL || rule->rule >= DOMAIN_RULE_MAX) {
		return NULL;
	}

	if (dns_rule_info_table[rule->rule].get_size) {
		size = dns_rule_info_table[rule->rule].get_size(rule);
	} else {
		size = dns_rule_info_table[rule->rule].size;
	}

	if (size <= 0) {
		return NULL;
	}

	new_rule = zalloc(1, size);
	if (!new_rule) {
		return NULL;
	}

	memcpy(new_rule, rule, size);
	atomic_set(&new_rule->refcnt, 1);

	if (dns_rule_info_table[rule->rule].clone) {
		dns_rule_info_table[rule->rule].clone(new_rule, rule);
	}

	return new_rule;
}

void _dns_rule_get(struct dns_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static void _dns_rule_free(struct dns_rule *rule)
{
	if (dns_rule_info_table[rule->rule].destroy) {
		dns_rule_info_table[rule->rule].destroy(rule);
	}
	free(rule);
}


void _dns_rule_put(struct dns_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt)) {
		_dns_rule_free(rule);
	}
}

static struct dns_domain_set_name_list *_config_get_domain_set_name_list(const char *name)
{
	uint32_t key = 0;
	struct dns_domain_set_name_list *set_name_list = NULL;

	key = hash_string(name);
	hash_for_each_possible(dns_domain_set_name_table.names, set_name_list, node, key)
	{
		if (strcmp(set_name_list->name, name) == 0) {
			return set_name_list;
		}
	}

	return NULL;
}

static int _config_domain_rule_set_each(const char *domain_set, set_rule_add_func callback, void *priv)
{
	struct dns_domain_set_name_list *set_name_list = NULL;
	struct dns_domain_set_name *set_name_item = NULL;

	set_name_list = _config_get_domain_set_name_list(domain_set);
	if (set_name_list == NULL) {
		tlog(TLOG_WARN, "domain set %s not found.", domain_set);
		return -1;
	}

	list_for_each_entry(set_name_item, &set_name_list->set_name_list, list)
	{
		switch (set_name_item->type) {
		case DNS_DOMAIN_SET_LIST:
			if (_config_set_rule_each_from_list(set_name_item->file, callback, priv) != 0) {
				return -1;
			}
			break;
		case DNS_DOMAIN_SET_GEOSITE:
			/* For geosite type, use the file field as the geosite-set name */
			if (geosite_set_foreach_domain(set_name_item->file, callback, priv) != 0) {
				tlog(TLOG_WARN, "geosite-set %s domain iteration failed.", set_name_item->file);
			}
			break;
		default:
			tlog(TLOG_WARN, "domain set %s type %d not support.", set_name_list->name, set_name_item->type);
			break;
		}
	}

	return 0;
}

static int _config_domain_rule_add_callback(const char *domain, void *priv)
{
	struct dns_set_rule_add_callback_args *args = (struct dns_set_rule_add_callback_args *)priv;
	return _config_domain_rule_add(domain, args->type, args->rule);
}

static int _config_setup_domain_key(const char *domain, char *domain_key, int domain_key_max_len, int *domain_key_len,
									int *root_rule_only, int *sub_rule_only)
{
	int tmp_root_rule_only = 0;
	int tmp_sub_rule_only = 0;
	int domain_len = 0;

	int len = strlen(domain);
	domain_len = len;
	if (!domain_key || !domain_key_len || domain_key_max_len <= 0 || len + 3 > domain_key_max_len) {
		tlog(TLOG_ERROR, "invalid parameters or domain too long: %s (max %d)", domain, domain_key_max_len - 3);
		return -1;
	}

	while (len > 0 && domain[len - 1] == '.') {
		len--;
	}

	/* prefix '+': same as default suffix match (domain + all subdomains) */
	if (domain[0] == '+' && domain_len > 1 && domain[1] == '.') {
		domain += 2;
		len -= 2;
		domain_len = len;
	}

	reverse_string(domain_key + 1, domain, len, 1);
	if (domain[0] == '*' && domain_len > 1) {
		/* prefix wildcard */
		len--;
		if (domain[1] == '.') {
			tmp_sub_rule_only = 1;
		} else if ((domain[1] == '-') && (domain[2] == '.')) {
			len--;
			tmp_sub_rule_only = 1;
			tmp_root_rule_only = 1;
		}
	} else if (domain[0] == '-' && domain_len > 1) {
		/* root match only */
		len--;
		if (domain[1] == '.') {
			tmp_root_rule_only = 1;
		}
	} else if (len > 0) {
		/* suffix match */
		if (len + 2 < domain_key_max_len) {
			domain_key[len + 1] = '.';
			len++;
		}
	}

	/* add dot to the front when sub rule only */
	domain_key[0] = '.';
	if (tmp_sub_rule_only == 1 && tmp_root_rule_only == 0) {
		domain_key[len + 1] = '\0';
	} else if (tmp_root_rule_only == 1 && tmp_sub_rule_only == 0) {
		if (domain_key[len] == '.') {
			len--;
		}
		domain_key[len + 1] = '\0';
	} else {
		domain_key[len + 1] = '\0';
	}

	*domain_key_len = len + 1;
	if (root_rule_only) {
		*root_rule_only = tmp_root_rule_only;
	}

	if (sub_rule_only) {
		*sub_rule_only = tmp_sub_rule_only;
	}

	return 0;
}

static __attribute__((unused)) struct dns_domain_rule *_config_domain_rule_get(const char *domain)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, NULL, NULL) != 0) {
		return NULL;
	}

	return art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
}

int _config_domain_rule_free(struct dns_domain_rule *domain_rule)
{
	int i = 0;

	if (domain_rule == NULL) {
		return 0;
	}
	if (!atomic32_dec_and_test(&domain_rule->refcnt)) {
		return 0;
	}

	/* Iterate only through allocated capacity, not DOMAIN_RULE_MAX */
	for (i = 0; i < domain_rule->capacity; i++) {
		if (domain_rule->rules[i] == NULL) {
			continue;
		}

		_dns_rule_put(domain_rule->rules[i]);
		domain_rule->rules[i] = NULL;
	}

	free(domain_rule);
	return 0;
}

int _config_domain_iter_free(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct dns_domain_rule *domain_rule = value;
	return _config_domain_rule_free(domain_rule);
}

static int _config_domain_rule_delete_callback(const char *domain, void *priv)
{
	return _config_domain_rule_delete(domain);
}

int _config_domain_rule_delete(const char *domain)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;

	const char *del_set_ref = _domain_get_set_name(domain);
	if (del_set_ref != NULL) {
		return _config_domain_rule_set_each(del_set_ref, _config_domain_rule_delete_callback, NULL);
	}
	/* Reverse string, for suffix match */

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, NULL, NULL) != 0) {
		goto errout;
	}

	/* delete existing rules */
	void *rule = art_delete(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (rule) {
		_config_domain_rule_free(rule);
	}

	return 0;
errout:
	tlog(TLOG_ERROR, "delete domain %s rule failed", domain);
	return -1;
}

static int _config_domain_rule_flag_callback(const char *domain, void *priv)
{
	struct dns_set_rule_flags_callback_args *args = (struct dns_set_rule_flags_callback_args *)priv;
	return _config_domain_rule_flag_set(domain, args->flags, args->is_clear_flag);
}

int _config_domain_rule_flag_set(const char *domain, unsigned int flag, unsigned int is_clear)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;
	struct dns_rule_flags *rule_flags = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		struct dns_set_rule_flags_callback_args args;
		args.flags = flag;
		args.is_clear_flag = is_clear;
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_flag_callback,
											&args);
	}

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		goto errout;
	}

	/* Get existing domain rule */
	domain_rule = art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (domain_rule && domain_rule->rules[DOMAIN_RULE_FLAGS]) {
		rule_flags = (struct dns_rule_flags *)domain_rule->rules[DOMAIN_RULE_FLAGS];
		unsigned int wanted_flags = is_clear ? rule_flags->flags & ~flag : rule_flags->flags | flag;
		if (wanted_flags == rule_flags->flags && (rule_flags->is_flag_set | flag) == rule_flags->is_flag_set &&
			rule_flags->head.sub_only == sub_rule_only && rule_flags->head.root_only == root_rule_only) {
			return 0;
		}
	}
	old_domain_rule = domain_rule;
	domain_rule = _ensure_domain_rule_capacity(domain_rule, DOMAIN_RULE_FLAGS);
	if (domain_rule == NULL) {
		goto errout;
	}
	if (domain_rule != old_domain_rule) {
		add_domain_rule = domain_rule;
	}

	/* add new rule to domain */
	if (domain_rule->rules[DOMAIN_RULE_FLAGS] == NULL) {
		rule_flags = _new_dns_rule(DOMAIN_RULE_FLAGS);
		if (rule_flags == NULL) {
			goto errout;
		}
		rule_flags->flags = 0;
		domain_rule->rules[DOMAIN_RULE_FLAGS] = (struct dns_rule *)rule_flags;
	}

	rule_flags = (struct dns_rule_flags *)domain_rule->rules[DOMAIN_RULE_FLAGS];
	if (atomic_read(&rule_flags->head.refcnt) > 1) {
		struct dns_rule_flags *new_flags = (struct dns_rule_flags *)_dns_rule_clone(&rule_flags->head);
		if (new_flags == NULL) {
			goto errout;
		}
		_dns_rule_put(&rule_flags->head);
		domain_rule->rules[DOMAIN_RULE_FLAGS] = (struct dns_rule *)new_flags;
		rule_flags = new_flags;
	}
	rule_flags->head.sub_only = sub_rule_only;
	rule_flags->head.root_only = root_rule_only;
	if (is_clear == false) {
		rule_flags->flags |= flag;
	} else {
		rule_flags->flags &= ~flag;
	}
	rule_flags->is_flag_set |= flag;
	struct dns_domain_rule *shared_rule = _domain_rule_intern_flags(domain_rule);
	if (shared_rule != domain_rule) {
		/* An unpublished copy owns its own reference. An existing ART leaf
		 * is released below only after replacement, never twice. */
		_config_domain_rule_free(add_domain_rule);
		add_domain_rule = shared_rule;
	}

	/* update domain rule */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len,
									 add_domain_rule);
		if (old_domain_rule) {
			_config_domain_rule_free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		_config_domain_rule_free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add domain %s rule failed", domain);
	return -1;
}

int _config_domain_rule_remove(const char *domain, enum domain_rule type)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (type < 0 || type >= DOMAIN_RULE_MAX) {
		tlog(TLOG_ERROR, "invalid domain rule type %d", type);
		return -1;
	}

	const char *rem_set_ref = _domain_get_set_name(domain);
	if (rem_set_ref != NULL) {
		return _config_domain_rule_set_each(rem_set_ref, _config_domain_rule_delete_callback, NULL);
	}

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		tlog(TLOG_ERROR, "setup domain key failed for %s", domain);
		return -1;
	}

	struct dns_domain_rule *domain_rule =
		art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		tlog(TLOG_ERROR, "domain %s not found", domain);
		return -1;
	}

	if (type >= domain_rule->capacity || domain_rule->rules[type] == NULL) {
		return 0;
	}
	struct dns_domain_rule *private_rule = _ensure_domain_rule_capacity(domain_rule, type);
	if (private_rule == NULL) {
		return -1;
	}
	if (private_rule != domain_rule) {
		art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len, private_rule);
		_config_domain_rule_free(domain_rule);
		domain_rule = private_rule;
	}

	_dns_rule_put(domain_rule->rules[type]);
	domain_rule->rules[type] = NULL;

	return 0;
}

int _config_domain_rule_add(const char *domain, enum domain_rule type, void *rule)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	const char *set_name = _domain_get_set_name(domain);
	if (set_name != NULL) {
		struct dns_set_rule_add_callback_args args;
		args.type = type;
		args.rule = rule;
		return _config_domain_rule_set_each(set_name, _config_domain_rule_add_callback, &args);
	}

	/* Reverse string, for suffix match */
	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		goto errout;
	}

	struct dns_conf_group *rg = _config_current_rule_group();

	if (rg == NULL) {
		tlog(TLOG_ERROR, "BUG: _config_current_rule_group() returned NULL for domain %s type %d", domain, type);
		goto errout;
	}

	/* Get existing domain rule */
	domain_rule = art_search(&rg->domain_rule.tree, (unsigned char *)domain_key, len);

	struct dns_domain_rule *old_ptr = domain_rule;

	/* Ensure capacity for the new rule type */
	domain_rule = _ensure_domain_rule_capacity(domain_rule, type);
	if (domain_rule == NULL) {
		tlog(TLOG_ERROR, "failed to allocate capacity for domain %s rule type %d", domain, type);
		goto errout;
	}

	/* Publish new/private/grown values only after applying the rule. */
	if (domain_rule != old_ptr) {
		add_domain_rule = domain_rule;
	}

	/* add new rule to domain */
	struct dns_rule *prule = (struct dns_rule *)rule;
	int is_cloned = 0;
	if (atomic_read(&prule->refcnt) > 1 &&
		(prule->sub_only != sub_rule_only || prule->root_only != root_rule_only ||
		 dns_rule_info_table[prule->rule].is_list)) {
		struct dns_rule *new_rule = _dns_rule_clone(prule);
		if (new_rule == NULL) {
			goto errout;
		}
		prule = new_rule;
		rule = (void *)new_rule;
		is_cloned = 1;
	}

	if (domain_rule->rules[type]) {
		if (dns_rule_info_table[type].append) {
			dns_rule_info_table[type].append(domain_rule->rules[type], prule);
			if (!is_cloned) {
				_dns_rule_get(prule);
			}
			if (add_domain_rule) {
				old_domain_rule = art_insert(&_config_current_rule_group()->domain_rule.tree,
							     (unsigned char *)domain_key, len, add_domain_rule);
				if (old_domain_rule) {
					_config_domain_rule_free(old_domain_rule);
				}
			}
			return 0;
		}

		_dns_rule_put(domain_rule->rules[type]);
		domain_rule->rules[type] = NULL;
	}

	domain_rule->rules[type] = prule;
	prule->sub_only = sub_rule_only;
	prule->root_only = root_rule_only;
	if (!is_cloned) {
		_dns_rule_get(prule);
	}

	/* update domain rule - only for new allocations */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len,
									 add_domain_rule);
		if (old_domain_rule) {
			_config_domain_rule_free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		_config_domain_rule_free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add domain %s rule failed", domain);
	return -1;
}

static int _conf_domain_rule_rr_ttl(const char *domain, int ttl, int ttl_min, int ttl_max)
{
	struct dns_ttl_rule *rr_ttl = NULL;

	if (ttl < 0 || ttl_min < 0 || ttl_max < 0) {
		tlog(TLOG_ERROR, "invalid ttl value.");
		goto errout;
	}

	rr_ttl = _new_dns_rule(DOMAIN_RULE_TTL);
	if (rr_ttl == NULL) {
		goto errout;
	}

	rr_ttl->ttl = ttl;
	rr_ttl->ttl_min = ttl_min;
	rr_ttl->ttl_max = ttl_max;

	if (_config_domain_rule_add(domain, DOMAIN_RULE_TTL, rr_ttl) != 0) {
		goto errout;
	}

	_dns_rule_put(&rr_ttl->head);

	return 0;
errout:
	if (rr_ttl != NULL) {
		_dns_rule_put(&rr_ttl->head);
	}

	return -1;
}

static int _conf_domain_rule_no_serve_expired(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_SERVE_EXPIRED, 0);
}

static int _conf_domain_rule_delete(const char *domain)
{
	return _config_domain_rule_delete(domain);
}

static int _conf_domain_rule_no_cache(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_CACHE, 0);
}

static int _conf_domain_rule_enable_cache(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_ENABLE_CACHE, 0);
}

static int _conf_domain_rule_no_ipalias(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_IPALIAS, 0);
}

static int _conf_domain_rule_no_ignore_ip(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_IGNORE_IP, 0);
}

int _conf_domain_rule_response_mode(char *domain, const char *mode)
{
	enum response_mode_type response_mode_type = DNS_RESPONSE_MODE_FIRST_PING_IP;
	struct dns_response_mode_rule *response_mode = NULL;

	for (int i = 0; response_mode_list()[i].name != NULL; i++) {
		if (strcmp(mode, response_mode_list()[i].name) == 0) {
			response_mode_type = response_mode_list()[i].id;
			break;
		}
	}

	response_mode = _new_dns_rule(DOMAIN_RULE_RESPONSE_MODE);
	if (response_mode == NULL) {
		goto errout;
	}
	response_mode->mode = response_mode_type;

	if (_config_domain_rule_add(domain, DOMAIN_RULE_RESPONSE_MODE, response_mode) != 0) {
		goto errout;
	}

	_dns_rule_put(&response_mode->head);
	return 0;
errout:
	if (response_mode) {
		_dns_rule_put(&response_mode->head);
	}

	return 0;
}

int _conf_domain_rule_speed_check(char *domain, const char *mode)
{
	struct dns_domain_check_orders *check_orders = NULL;

	check_orders = _new_dns_rule(DOMAIN_RULE_CHECKSPEED);
	if (check_orders == NULL) {
		goto errout;
	}

	if (_config_speed_check_mode_parser(check_orders, mode) != 0) {
		goto errout;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_CHECKSPEED, check_orders) != 0) {
		goto errout;
	}

	_dns_rule_put(&check_orders->head);
	return 0;
errout:
	if (check_orders) {
		_dns_rule_put(&check_orders->head);
	}
	return 0;
}

int _conf_domain_rule_group(const char *domain, const char *group_name)
{
	struct dns_group_rule *group_rule = NULL;
	const char *group = NULL;

	if (strncmp(group_name, "-", sizeof("-")) != 0) {
		group = _dns_conf_get_group_name(group_name);
		if (group == NULL) {
			goto errout;
		}

		group_rule = _new_dns_rule(DOMAIN_RULE_GROUP);
		if (group_rule == NULL) {
			goto errout;
		}

		group_rule->group_name = group;
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_GROUP_IGNORE, 0) != 0) {
			goto errout;
		}

		return 0;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_GROUP, group_rule) != 0) {
		goto errout;
	}

	_dns_rule_put(&group_rule->head);

	return 0;
errout:
	if (group_rule) {
		_dns_rule_put(&group_rule->head);
	}

	tlog(TLOG_ERROR, "add group %s, %s failed", domain, group_name);
	return 0;
}

static int _conf_domain_rule_dualstack_selection(char *domain, const char *yesno)
{
	if (strncmp(yesno, "yes", sizeof("yes")) == 0 || strncmp(yesno, "Yes", sizeof("Yes")) == 0) {
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_DUALSTACK_SELECT, 0) != 0) {
			goto errout;
		}
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_DUALSTACK_SELECT, 1) != 0) {
			goto errout;
		}
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "set dualstack for %s failed. ", domain);
	return 1;
}

int _config_domain_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];
	int rr_ttl = 0;
	int rr_ttl_min = 0;
	int rr_ttl_max = 0;
	const char *group = NULL;
	char group_name[DNS_MAX_CONF_CNAME_LEN];
	int has_explicit_name = 0;



	/* clang-format off */
	static struct option long_options[] = {
		{"speed-check-mode", required_argument, NULL, 'c'},
		{"response-mode", required_argument, NULL, 'r'},
		{"address", required_argument, NULL, 'a'},
		{"https-record", required_argument, NULL, 'h'},
		{"txt-record", required_argument, NULL, 'T'},
		{"ipset", required_argument, NULL, 'p'},
		{"nftset", required_argument, NULL, 't'},
		{"nameserver", required_argument, NULL, 'n'},
		{"name", required_argument, NULL, 'N'},
		{"group", required_argument, NULL, 'g'},
		{"dualstack-ip-selection", required_argument, NULL, 'd'},
		{"cname", required_argument, NULL, 'A'},
		{"rr-ttl", required_argument, NULL, 251},
		{"rr-ttl-min", required_argument, NULL, 252},
		{"rr-ttl-max", required_argument, NULL, 253},
		{"no-serve-expired", no_argument, NULL, 254},
		{"delete", no_argument, NULL, 255},
		{"no-cache", no_argument, NULL, 256},
		{"no-ip-alias", no_argument, NULL, 257},
		{"enable-cache", no_argument, NULL, 258},
		{"no-ignore-ip", no_argument, NULL, 259},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	/* Check for domain-set: or geosite-set: prefix before calling _get_domain */
	const char *set_ref = _domain_get_set_name(value);
	if (set_ref != NULL) {
		safe_strncpy(domain, value, DNS_MAX_CONF_CNAME_LEN);
		struct dns_domain_set_name_list *name = _config_get_domain_set_name_list(set_ref);
		if (name == NULL) {
			tlog(TLOG_ERROR, "domain set '%s' not found.", set_ref);
			goto errout;
		}
		/* Save for reload on geosite data update */
		geosite_save_domain_rule(value, argc, argv);
	} else {
		if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
			tlog(TLOG_ERROR, "failed to parse domain '%s'", argv[1]);
			goto errout;
		}
		/* Check if _get_domain extracted a domain-set/geosite-set reference (e.g., /geosite-set:name/) */
		set_ref = _domain_get_set_name(domain);
		if (set_ref != NULL) {
			struct dns_domain_set_name_list *name = _config_get_domain_set_name_list(set_ref);
			if (name == NULL) {
				tlog(TLOG_ERROR, "domain set '%s' not found.", set_ref);
				goto errout;
			}
			/* Save for reload on geosite data update */
			geosite_save_domain_rule(domain, argc, argv);
		}
	}

	for (int i = 2; i < argc - 1; i++) {
		if (strncmp(argv[i], "-g", sizeof("-g")) == 0 || strncmp(argv[i], "--group", sizeof("--group")) == 0 ||
			strncmp(argv[i], "-group", sizeof("-group")) == 0) {
			safe_strncpy(group_name, argv[i + 1], DNS_MAX_CONF_CNAME_LEN);
			group = group_name;
			break;
		}
	}

	if (group != NULL) {
		_config_current_group_push(group, NULL);
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "c:a:p:t:n:N:d:A:r:g:h:T:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'c': {
			const char *check_mode = optarg;
			if (check_mode == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_speed_check(domain, check_mode) != 0) {
				tlog(TLOG_ERROR, "add check-speed-rule rule failed.");
				goto errout;
			}

			break;
		}
		case 'r': {
			const char *response_mode = optarg;
			if (response_mode == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_response_mode(domain, response_mode) != 0) {
				tlog(TLOG_ERROR, "add response-mode rule failed.");
				goto errout;
			}

			break;
		}
		case 'a': {
			const char *address = optarg;
			if (address == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_address(domain, address) != 0) {
				tlog(TLOG_ERROR, "add address rule failed.");
				goto errout;
			}

			break;
		}
		case 'h': {
			const char *https_record = optarg;
			if (https_record == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_https_record(domain, https_record) != 0) {
				tlog(TLOG_ERROR, "add https-record rule failed.");
				goto errout;
			}

			break;
		}
		case 'T': {
			const char *txt_record = optarg;
			if (txt_record == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_txt_record(domain, txt_record) != 0) {
				tlog(TLOG_ERROR, "add txt-record rule failed.");
				goto errout;
			}

			break;
		}
		case 'p': {
			const char *ipsetname = optarg;
			if (ipsetname == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_ipset(domain, ipsetname) != 0) {
				tlog(TLOG_ERROR, "add ipset rule failed.");
				goto errout;
			}

			break;
		}
		case 'n': {
			const char *nameserver_group = optarg;
			if (nameserver_group == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_nameserver(domain, nameserver_group) != 0) {
				tlog(TLOG_ERROR, "add nameserver rule failed.");
				goto errout;
			}

			break;
		}
		case 'N': {
			if (optarg == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_name(domain, optarg, 0) != 0) {
				goto errout;
			}
			has_explicit_name = 1;

			break;
		}
		case 'A': {
			const char *cname = optarg;

			if (_conf_domain_rule_cname(domain, cname) != 0) {
				tlog(TLOG_ERROR, "add cname rule failed.");
				goto errout;
			}

			break;
		}
		case 'd': {
			const char *yesno = optarg;
			if (_conf_domain_rule_dualstack_selection(domain, yesno) != 0) {
				tlog(TLOG_ERROR, "set dualstack selection rule failed.");
				goto errout;
			}

			break;
		}
		case 't': {
			const char *nftsetname = optarg;
			if (nftsetname == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_nftset(domain, nftsetname) != 0) {
				tlog(TLOG_ERROR, "add nftset rule failed.");
				goto errout;
			}

			break;
		}
		case 'g': {
			break;
		}
		case 251: {
			rr_ttl = atoi(optarg);
			break;
		}
		case 252: {
			rr_ttl_min = atoi(optarg);
			break;
		}
		case 253: {
			rr_ttl_max = atoi(optarg);
			break;
		}
		case 254: {
			if (_conf_domain_rule_no_serve_expired(domain) != 0) {
				tlog(TLOG_ERROR, "set no-serve-expired rule failed.");
				goto errout;
			}

			break;
		}
		case 255: {
			if (_conf_domain_rule_delete(domain) != 0) {
				tlog(TLOG_ERROR, "delete domain rule failed.");
				goto errout;
			}

			return 0;
		}
		case 256: {
			if (_conf_domain_rule_no_cache(domain) != 0) {
				tlog(TLOG_ERROR, "set no-cache rule failed.");
				goto errout;
			}

			break;
		}
		case 257: {
			if (_conf_domain_rule_no_ipalias(domain) != 0) {
				tlog(TLOG_ERROR, "set no-ipalias rule failed.");
				goto errout;
			}

			break;
		}
		case 258: {
			if (_conf_domain_rule_enable_cache(domain) != 0) {
				tlog(TLOG_ERROR, "set enable-cache rule failed.");
				goto errout;
			}

			break;
		}
		case 259: {
			if (_conf_domain_rule_no_ignore_ip(domain) != 0) {
				tlog(TLOG_ERROR, "set no-ignore-ip rule failed.");
				goto errout;
			}

			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown domain-rules option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	if (rr_ttl > 0 || rr_ttl_min > 0 || rr_ttl_max > 0) {
		if (_conf_domain_rule_rr_ttl(domain, rr_ttl, rr_ttl_min, rr_ttl_max) != 0) {
			tlog(TLOG_ERROR, "set rr-ttl rule failed.");
			goto errout;
		}
	}

	if (group != NULL) {
		_config_current_group_pop();
	}

	/* Auto-generate name if not explicitly set */
	if (!has_explicit_name) {
		const char *auto_name = _get_domain_rule_auto_name();
		_conf_domain_rule_name(domain, auto_name, 1);
	}

	return 0;
errout:
	if (group != NULL) {
		_config_current_group_pop();
	}
	return -1;
}

void *dns_conf_get_domain_rule(const char *domain, enum domain_rule type)
{
	struct dns_domain_rule *domain_rule = NULL;
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		return NULL;
	}

	domain_rule = art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		return NULL;
	}

	if (type >= DOMAIN_RULE_MAX || type >= domain_rule->capacity) {
		return NULL;
	}

	return domain_rule->rules[type];
}

static void _fill_dns_server_list(const char *group_name, struct domain_rule_check_result *result)
{
	result->server_num = 0;
	memset(result->servers, 0, sizeof(result->servers));

	if (group_name == NULL || group_name[0] == '\0') {
		return;
	}

	safe_strncpy(result->group_name, group_name, DNS_GROUP_NAME_LEN);

	/* Try named groups via hash table */
	uint32_t gkey = hash_string(group_name);
	struct dns_server_groups *gsg = NULL;
	int found = 0;

	hash_for_each_possible(dns_group_table.group, gsg, node, gkey)
	{
		if (strcmp(gsg->group_name, group_name) == 0) {
			found = 1;
			for (int i = 0; i < gsg->server_num && i < DNS_MAX_CHECK_SERVERS; i++) {
				struct dns_servers *s = gsg->servers[i];
				char prefix[16];
				if (s->type == DNS_SERVER_UDP)
					strncpy(prefix, "udp://", sizeof(prefix));
				else if (s->type == DNS_SERVER_TCP)
					strncpy(prefix, "tcp://", sizeof(prefix));
				else if (s->type == DNS_SERVER_TLS)
					strncpy(prefix, "tls://", sizeof(prefix));
				else if (s->type == DNS_SERVER_HTTPS)
					strncpy(prefix, "https://", sizeof(prefix));
				else if (s->type == DNS_SERVER_QUIC)
					strncpy(prefix, "quic://", sizeof(prefix));
				else if (s->type == DNS_SERVER_HTTP3)
					strncpy(prefix, "h3://", sizeof(prefix));
				else
					prefix[0] = '\0';

				if (s->port > 0 && s->port != DEFAULT_DNS_PORT)
					snprintf(result->servers[i], DNS_SERVER_INFO_STR_LEN, "%s%s:%d", prefix, s->server, s->port);
				else
					snprintf(result->servers[i], DNS_SERVER_INFO_STR_LEN, "%s%s", prefix, s->server);
				if (s->fallback) {
					size_t srv_len = strlen(result->servers[i]);
					if (srv_len < DNS_SERVER_INFO_STR_LEN - 1) {
						result->servers[i][srv_len] = '*';
						result->servers[i][srv_len + 1] = '\0';
					}
				}
				result->server_num++;
			}
			break;
		}
	}

	/* Fallback: default group uses dns_conf.servers[] */
	if (!found && strcmp(group_name, "default") == 0) {
		for (int i = 0; i < dns_conf.server_num && result->server_num < DNS_MAX_CHECK_SERVERS; i++) {
			struct dns_servers *s = &dns_conf.servers[i];
			if (s->server_flag & SERVER_FLAG_EXCLUDE_DEFAULT)
				continue;

			char prefix[16];
			if (s->type == DNS_SERVER_UDP)
				strncpy(prefix, "udp://", sizeof(prefix));
			else if (s->type == DNS_SERVER_TCP)
				strncpy(prefix, "tcp://", sizeof(prefix));
			else if (s->type == DNS_SERVER_TLS)
				strncpy(prefix, "tls://", sizeof(prefix));
			else if (s->type == DNS_SERVER_HTTPS)
				strncpy(prefix, "https://", sizeof(prefix));
			else if (s->type == DNS_SERVER_QUIC)
				strncpy(prefix, "quic://", sizeof(prefix));
			else if (s->type == DNS_SERVER_HTTP3)
				strncpy(prefix, "h3://", sizeof(prefix));
			else
				prefix[0] = '\0';

			char server_str[DNS_SERVER_INFO_STR_LEN];
			if (s->port > 0 && s->port != DEFAULT_DNS_PORT)
				snprintf(server_str, sizeof(server_str), "%s%s:%d", prefix, s->server, s->port);
			else
				snprintf(server_str, sizeof(server_str), "%s%s", prefix, s->server);
			if (s->fallback)
				strncat(server_str, "*", sizeof(server_str) - strlen(server_str) - 1);

			safe_strncpy(result->servers[result->server_num], server_str, DNS_SERVER_INFO_STR_LEN);
			result->server_num++;
		}
	}
}

int dns_conf_check_domain_rule(const char *domain, struct domain_rule_check_result *result)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_conf_group *conf_group = NULL;
	char check_domain[DNS_MAX_CONF_CNAME_LEN];
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	const char *p = NULL;

	if (domain == NULL || result == NULL) {
		return -1;
	}

	memset(result, 0, sizeof(*result));
	safe_strncpy(result->domain, domain, DNS_MAX_CNAME_LEN);
	safe_strncpy(result->rule_name, "PASS", DOMAIN_RULE_NAME_MAX_LEN);
	safe_strncpy(result->group_name, "default", DNS_GROUP_NAME_LEN);
	result->action = DOMAIN_ACTION_NONE;
	result->response_mode = dns_conf.default_response_mode;

	/* Use default rule group for check-domain-rule command */
	conf_group = dns_server_get_default_rule_group();
	if (conf_group == NULL) {
		_fill_dns_server_list("default", result);
		return 0;
	}

	/* Try exact match and each parent suffix: www.qq.com -> qq.com */
	safe_strncpy(check_domain, domain, sizeof(check_domain));

	for (p = check_domain; p && *p;) {
		if (_config_setup_domain_key(p, domain_key, sizeof(domain_key), &len, NULL, NULL) != 0) {
			break;
		}

		domain_rule = art_search(&conf_group->domain_rule.tree, (unsigned char *)domain_key, len);
		if (domain_rule != NULL) {
			safe_strncpy(result->matched_pattern, p, DNS_MAX_CNAME_LEN);

			/* Extract rule name */
			if (DOMAIN_RULE_NAME < domain_rule->capacity && domain_rule->rules[DOMAIN_RULE_NAME] != NULL) {
				struct dns_name_rule *name_rule = (struct dns_name_rule *)domain_rule->rules[DOMAIN_RULE_NAME];
				if (name_rule->name != NULL) {
					safe_strncpy(result->rule_name, name_rule->name, DOMAIN_RULE_NAME_MAX_LEN);
				}
			}

			/* Get response mode from rule */
			if (DOMAIN_RULE_RESPONSE_MODE < domain_rule->capacity && domain_rule->rules[DOMAIN_RULE_RESPONSE_MODE] != NULL) {
				struct dns_response_mode_rule *rm = (struct dns_response_mode_rule *)domain_rule->rules[DOMAIN_RULE_RESPONSE_MODE];
				result->response_mode = rm->mode;
			}

			/* Determine action: ADDRESS takes priority */
			if (DOMAIN_RULE_ADDRESS_IPV4 < domain_rule->capacity && domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] != NULL) {
				result->action = DOMAIN_ACTION_ADDRESS;
				return 0;
			}
			if (DOMAIN_RULE_ADDRESS_IPV6 < domain_rule->capacity && domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] != NULL) {
				result->action = DOMAIN_ACTION_ADDRESS;
				return 0;
			}

			/* Check NAMESERVER / GROUP for NAMESERVER action */
			const char *group = NULL;
			if (DOMAIN_RULE_GROUP < domain_rule->capacity && domain_rule->rules[DOMAIN_RULE_GROUP] != NULL) {
				struct dns_group_rule *gr = (struct dns_group_rule *)domain_rule->rules[DOMAIN_RULE_GROUP];
				if (gr->group_name != NULL) {
					group = gr->group_name;
				}
			}
			if (group == NULL && DOMAIN_RULE_NAMESERVER < domain_rule->capacity &&
				domain_rule->rules[DOMAIN_RULE_NAMESERVER] != NULL) {
				struct dns_nameserver_rule *nr =
					(struct dns_nameserver_rule *)domain_rule->rules[DOMAIN_RULE_NAMESERVER];
				if (nr->group_name != NULL) {
					group = nr->group_name;
				}
			}

			if (group != NULL) {
				result->action = DOMAIN_ACTION_NAMESERVER;
				_fill_dns_server_list(group, result);
				return 0;
			}

			/* Matched a rule but no action (e.g., flags-only rule), continue to parent */
		}

		/* Move to next parent domain */
		p = strchr(p, '.');
		if (p == NULL || *(++p) == '\0') {
			break;
		}
	}

	/* No match: fill default servers */
	_fill_dns_server_list("default", result);
	return 0;
}

const char *dns_conf_check_domain_group(const char *domain)
{
	static struct domain_rule_check_result _result;
	if (dns_conf_check_domain_rule(domain, &_result) != 0) {
		return "default";
	}
	return _result.group_name[0] ? _result.group_name : "default";
}

/* ---- Domain resolution chain implementation ---- */

#define RESOLVE_DNS_TIMEOUT_MS 3000

/* Parse "udp://1.2.3.4:53", "udp://[::1]:53", or "udp://[::1]" into (ip, port). */
static void _parse_server_addr(const char *server_str, char *ip, int ip_len, int *port)
{
	const char *p = strstr(server_str, "://");
	p = p ? p + 3 : server_str;

	*port = 53; /* default port */

	/* Check for IPv6 address in brackets: [::1]:53 or [::1] */
	if (*p == '[') {
		const char *end_bracket = strchr(p, ']');
		if (end_bracket != NULL) {
			/* Extract IPv6 address */
			int len = (int)(end_bracket - p - 1);
			if (len > 0 && len < ip_len) {
				safe_strncpy(ip, p + 1, len + 1);
				ip[len] = '\0';
			}
			/* Check for port after ] */
			if (end_bracket[1] == ':') {
				*port = atoi(end_bracket + 2);
			}
			return;
		}
	}

	/* Check for IPv6 address without brackets (no port or with port) */
	/* IPv6 addresses contain multiple colons */
	char buf[DNS_MAX_IPLEN];
	safe_strncpy(buf, p, sizeof(buf));

	/* Strip trailing '*' (fallback server marker added by
	 * dns_conf_get_check_servers) before parsing the address. */
	size_t buf_len = strlen(buf);
	while (buf_len > 0 && buf[buf_len - 1] == '*') {
		buf[--buf_len] = '\0';
	}

	/* Count colons to detect IPv6 */
	int colon_count = 0;
	const char *q = buf;
	while (*q) {
		if (*q == ':')
			colon_count++;
		q++;
	}

	if (colon_count >= 2) {
		/* This is an IPv6 address */
		/* Bare IPv6 addresses often end with a numeric-only group (e.g.
		 * ...:68), so do not treat the trailing number as a port blindly.
		 * Only accept it as a port when the remaining prefix is a valid
		 * IPv6 address (e.g. "[::1]:53" without brackets, "240e::1:5353"). */
		char *last_colon = strrchr(buf, ':');
		if (last_colon != NULL) {
			char *after_colon = last_colon + 1;
			if (after_colon[0] != '\0') {
				int is_num = 1;
				for (char *c = after_colon; *c; c++) {
					if (*c < '0' || *c > '9') {
						is_num = 0;
						break;
					}
				}
				if (is_num && strlen(after_colon) <= 5) {
					char addr_buf[DNS_MAX_IPLEN];
					struct in6_addr probe;

					safe_strncpy(addr_buf, buf, (size_t)(last_colon - buf) + 1);
					if (inet_pton(AF_INET6, addr_buf, &probe) == 1) {
						*last_colon = '\0';
						*port = atoi(after_colon);
					}
				}
			}
		}
		safe_strncpy(ip, buf, ip_len);
	} else {
		/* IPv4 address */
		char *colon = strrchr(buf, ':');
		if (colon) {
			*colon = '\0';
			*port = atoi(colon + 1);
		}
		safe_strncpy(ip, buf, ip_len);
	}
}

/* Send a UDP DNS query, return response length or -1. Supports IPv4 and IPv6. */
static int _resolve_udp_query(const char *server_ip, int server_port, const char *domain, int qtype,
							  unsigned char *response, int response_len, unsigned int *ping_ms)
{
	/* Detect if server_ip is IPv6 or IPv4 */
	struct sockaddr_storage addr;
	socklen_t addr_len = 0;
	int af = AF_INET;
	int sockfd = -1;

	memset(&addr, 0, sizeof(addr));

	/* Try to parse as IPv6 first */
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
	if (inet_pton(AF_INET6, server_ip, &addr6->sin6_addr) == 1) {
		af = AF_INET6;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(server_port);
		addr_len = sizeof(struct sockaddr_in6);
	} else {
		/* Parse as IPv4 */
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
		if (inet_pton(AF_INET, server_ip, &addr4->sin_addr) != 1) {
			return -1;
		}
		af = AF_INET;
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(server_port);
		addr_len = sizeof(struct sockaddr_in);
	}

	sockfd = socket(af, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return -1;
	}

	struct timeval tv = {.tv_sec = RESOLVE_DNS_TIMEOUT_MS / 1000,
						.tv_usec = (RESOLVE_DNS_TIMEOUT_MS % 1000) * 1000};
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* Build query */
	unsigned char pkt_buf[DNS_IN_PACKSIZE + sizeof(struct dns_packet) + 64];
	struct dns_packet *packet = (struct dns_packet *)pkt_buf;
	memset(pkt_buf, 0, sizeof(pkt_buf));
	struct dns_head head = {.id = (unsigned short)(random() & 0xFFFF), .rd = 1, .qdcount = 1};
	dns_packet_init(packet, sizeof(pkt_buf), &head);
	dns_add_domain(packet, domain, qtype, DNS_C_IN);

	unsigned char wire[DNS_IN_PACKSIZE];
	int wire_len = dns_encode(wire, sizeof(wire), packet);
	if (wire_len < 0) {
		close(sockfd);
		return -1;
	}

	unsigned long start = get_tick_count();
	if (sendto(sockfd, wire, wire_len, 0, (struct sockaddr *)&addr, addr_len) < 0) {
		close(sockfd);
		return -1;
	}

	struct pollfd pfd = {.fd = sockfd, .events = POLLIN};
	if (poll(&pfd, 1, RESOLVE_DNS_TIMEOUT_MS) <= 0) {
		close(sockfd);
		return -1;
	}

	socklen_t alen = sizeof(addr);
	int rlen = recvfrom(sockfd, response, response_len, 0, (struct sockaddr *)&addr, &alen);
	*ping_ms = get_tick_count() - start;
	close(sockfd);
	return rlen;
}

/* Parse DNS response into a query result struct. */
/* Append a piece of record data text to the result, comma-separated. */
/* Append formatted text to a growable buffer, keeping it NUL-terminated. */
static void _resolve_buf_append(char *buf, int buf_size, const char *fmt, ...)
{
	int len = (int)strlen(buf);
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf + len, buf_size - len, fmt, ap);
	va_end(ap);
}

static void _resolve_append_rdata(struct dns_server_query_result *qr, const char *text)
{
	if (text == NULL || text[0] == '\0') {
		return;
	}
	if (qr->rdata[0] != '\0') {
		strlcat(qr->rdata, ", ", sizeof(qr->rdata));
	}
	strlcat(qr->rdata, text, sizeof(qr->rdata));
}

/* Read a (possibly compressed) domain name from a wire-format DNS packet.
 * On success advances *pos past the name (only when no compression pointer
 * was followed) and returns the length of the name written. */
static int _resolve_wire_read_name(const unsigned char *pkt, int pkt_len, int *pos, char *name, int name_size)
{
	int cur = *pos;
	int jumped = 0;
	int next = -1;
	int len = 0;
	int jumps = 0;

	name[0] = '\0';
	while (cur < pkt_len && jumps < 128) {
		unsigned char c = pkt[cur];
		if (c == 0) {
			cur++;
			/* advance past the whole name: either just the non-compressed
			 * labels, or the first two bytes of the compression pointer */
			*pos = jumped ? next : cur;
			return len;
		}
		if ((c & 0xC0) == 0xC0) {
			if (cur + 1 >= pkt_len) {
				return -1;
			}
			int ptr = ((c & 0x3F) << 8) | pkt[cur + 1];
			if (!jumped) {
				next = cur + 2;
			}
			jumped = 1;
			jumps++;
			if (ptr >= pkt_len || ptr < 12) {
				return -1;
			}
			cur = ptr;
			continue;
		}
		if ((c & 0xC0) != 0 || cur + 1 + c > pkt_len) {
			return -1;
		}
		if (len + c + 2 >= name_size) {
			return -1;
		}
		if (len > 0) {
			name[len++] = '.';
		}
		memcpy(name + len, pkt + cur + 1, c);
		len += c;
		name[len] = '\0';
		cur += 1 + c;
	}
	return -1;
}

/* Parse the answer section of a raw wire DNS packet for non-IP record types,
 * filling qr->rdata with a human readable representation of the records. */
static void _resolve_parse_wire_answers(const unsigned char *data, int data_len, int qtype,
										struct dns_server_query_result *qr)
{
	int pos = 12;
	char name[DNS_MAX_CNAME_LEN];

	if (data_len < 12) {
		return;
	}

	int qdcount = (data[4] << 8) | data[5];
	int ancount = (data[6] << 8) | data[7];

	/* skip question section */
	for (int i = 0; i < qdcount && pos < data_len; i++) {
		if (_resolve_wire_read_name(data, data_len, &pos, name, sizeof(name)) < 0) {
			return;
		}
		pos += 4;
	}

	for (int i = 0; i < ancount && pos + 10 <= data_len; i++) {
		if (_resolve_wire_read_name(data, data_len, &pos, name, sizeof(name)) < 0) {
			return;
		}
		if (pos + 10 > data_len) {
			return;
		}
		int rtype = (data[pos] << 8) | data[pos + 1];
		int ttl = (int)(((unsigned)data[pos + 4] << 24) | ((unsigned)data[pos + 5] << 16) |
						((unsigned)data[pos + 6] << 8) | (unsigned)data[pos + 7]);
		int rdlen = (data[pos + 8] << 8) | data[pos + 9];
		int rdpos = pos + 10;
		pos = rdpos + rdlen;
		if (rdpos + rdlen > data_len) {
			return;
		}

		if (rtype == qtype) {
			qr->ttl = (unsigned int)ttl;
			switch (rtype) {
			case DNS_T_A:
			case DNS_T_AAAA:
				/* handled by the rrs path above */
				break;
			case DNS_T_NS:
			case DNS_T_PTR:
			case DNS_T_CNAME: {
				int npos = rdpos;
				char target[DNS_MAX_CNAME_LEN];
				if (_resolve_wire_read_name(data, data_len, &npos, target, sizeof(target)) >= 0) {
					_resolve_append_rdata(qr, target);
				}
				break;
			}
			case DNS_T_MX: {
				if (rdlen < 3) {
					break;
				}
				unsigned short preference = ((unsigned short)data[rdpos] << 8) | (unsigned short)data[rdpos + 1];
				int npos = rdpos + 2;
				char target[DNS_MAX_CNAME_LEN];
				if (_resolve_wire_read_name(data, data_len, &npos, target, sizeof(target)) >= 0) {
					char mx_buf[DNS_MAX_CNAME_LEN * 2];
					snprintf(mx_buf, sizeof(mx_buf), "%u %s", preference, target);
					_resolve_append_rdata(qr, mx_buf);
				}
				break;
			}
			case DNS_T_SRV: {
				if (rdlen < 7) {
					break;
				}
				unsigned short priority = ((unsigned short)data[rdpos] << 8) | (unsigned short)data[rdpos + 1];
				unsigned short weight = ((unsigned short)data[rdpos + 2] << 8) | (unsigned short)data[rdpos + 3];
				unsigned short port = ((unsigned short)data[rdpos + 4] << 8) | (unsigned short)data[rdpos + 5];
				int npos = rdpos + 6;
				char target[DNS_MAX_CNAME_LEN];
				if (_resolve_wire_read_name(data, data_len, &npos, target, sizeof(target)) >= 0) {
					char srv_buf[DNS_MAX_CNAME_LEN * 2];
					snprintf(srv_buf, sizeof(srv_buf), "%u %u %u %s", priority, weight, port, target);
					_resolve_append_rdata(qr, srv_buf);
				}
				break;
			}
			case DNS_T_TXT: {
				int tpos = rdpos;
				char text[DNS_MAX_CNAME_LEN];
				while (tpos < rdpos + rdlen) {
					int tlen = data[tpos];
					tpos++;
					if (tlen <= 0 || tpos + tlen > rdpos + rdlen) {
						break;
					}
					int copy_len = (tlen < (int)sizeof(text) - 1) ? tlen : (int)sizeof(text) - 1;
					memcpy(text, data + tpos, copy_len);
					text[copy_len] = '\0';
					_resolve_append_rdata(qr, text);
					tpos += tlen;
				}
				break;
			}
			case DNS_T_SOA: {
				int spos = rdpos;
				char mname[DNS_MAX_CNAME_LEN];
				char rname[DNS_MAX_CNAME_LEN];
				if (_resolve_wire_read_name(data, data_len, &spos, mname, sizeof(mname)) < 0) {
					break;
				}
				if (_resolve_wire_read_name(data, data_len, &spos, rname, sizeof(rname)) < 0) {
					break;
				}
				if (spos + 20 > rdpos + rdlen) {
					break;
				}
				char soa_buf[DNS_MAX_CNAME_LEN * 3];
				snprintf(soa_buf, sizeof(soa_buf), "%s %s", mname, rname);
				_resolve_append_rdata(qr, soa_buf);
				break;
			}
			case DNS_T_HTTPS: {
				if (rdlen < 3) {
					break;
				}
				unsigned short priority = ((unsigned short)data[rdpos] << 8) | (unsigned short)data[rdpos + 1];
				int npos = rdpos + 2;
				char target[DNS_MAX_CNAME_LEN];
				if (_resolve_wire_read_name(data, data_len, &npos, target, sizeof(target)) < 0) {
					break;
				}
				/* the root name "." encodes as an empty string */
				if (target[0] == '\0') {
					safe_strncpy(target, ".", sizeof(target));
				}
				char https_buf[DNS_MAX_QUERY_RESULT_IPS_STR];
				snprintf(https_buf, sizeof(https_buf), "%u %s", priority, target);

				/* SvcParams: [key(2)][len(2)][value]... */
				int ppos = npos;
				int pend = rdpos + rdlen;
				while (ppos + 4 <= pend) {
					unsigned short key = ((unsigned short)data[ppos] << 8) | (unsigned short)data[ppos + 1];
					unsigned short plen = ((unsigned short)data[ppos + 2] << 8) | (unsigned short)data[ppos + 3];
					ppos += 4;
					if (ppos + plen > pend) {
						break;
					}
					const unsigned char *pv = data + ppos;
					switch (key) {
					case 0: { /* mandatory: list of keys */
						_resolve_buf_append(https_buf, sizeof(https_buf), " mandatory=");
						for (int k = 0; k + 2 <= plen; k += 2) {
							_resolve_buf_append(https_buf, sizeof(https_buf), "%s%u", k > 0 ? "," : "",
												((unsigned short)pv[k] << 8) | (unsigned short)pv[k + 1]);
						}
						break;
					}
					case 1: { /* alpn: sequence of length-prefixed protocol names */
						_resolve_buf_append(https_buf, sizeof(https_buf), " alpn=");
						for (int k = 0; k < plen;) {
							int alen = pv[k];
							if (alen <= 0 || k + 1 + alen > plen) {
								break;
							}
							_resolve_buf_append(https_buf, sizeof(https_buf), "%.*s%s", alen, (const char *)pv + k + 1,
												k + 1 + alen < plen ? "," : "");
							k += 1 + alen;
						}
						break;
					}
					case 2: /* no-default-alpn */
						_resolve_buf_append(https_buf, sizeof(https_buf), " no-default-alpn");
						break;
					case 3: { /* port */
						unsigned short port = (plen >= 2) ? (((unsigned short)pv[0] << 8) | (unsigned short)pv[1]) : 0;
						_resolve_buf_append(https_buf, sizeof(https_buf), " port=%u", port);
						break;
					}
					case 4: { /* ipv4hint */
						_resolve_buf_append(https_buf, sizeof(https_buf), " ipv4hint=");
						for (int k = 0; k + 4 <= plen; k += 4) {
							char ip_str[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, pv + k, ip_str, sizeof(ip_str));
							_resolve_buf_append(https_buf, sizeof(https_buf), "%s%s", k > 0 ? "," : "", ip_str);
						}
						break;
					}
					case 5: { /* ech: opaque, show truncated hex */
						_resolve_buf_append(https_buf, sizeof(https_buf), " ech=");
						int hex_len = plen < 16 ? plen : 16;
						for (int k = 0; k < hex_len; k++) {
							_resolve_buf_append(https_buf, sizeof(https_buf), "%02x", pv[k]);
						}
						if (plen > 16) {
							_resolve_buf_append(https_buf, sizeof(https_buf), "...(%u bytes)", plen);
						}
						break;
					}
					case 6: { /* ipv6hint */
						_resolve_buf_append(https_buf, sizeof(https_buf), " ipv6hint=");
						for (int k = 0; k + 16 <= plen; k += 16) {
							char ip_str[INET6_ADDRSTRLEN];
							inet_ntop(AF_INET6, pv + k, ip_str, sizeof(ip_str));
							_resolve_buf_append(https_buf, sizeof(https_buf), "%s%s", k > 0 ? "," : "", ip_str);
						}
						break;
					}
					case 7: /* dohpath: URI template string */
						_resolve_buf_append(https_buf, sizeof(https_buf), " dohpath=%.*s", plen, (const char *)pv);
						break;
					default: /* unknown key: show as keyN */
						_resolve_buf_append(https_buf, sizeof(https_buf), " key%u", key);
						break;
					}
					ppos += plen;
				}
				_resolve_append_rdata(qr, https_buf);
				break;
			}
			default:
				break;
			}
		} else if (rtype == DNS_T_CNAME && qr->cname[0] == '\0') {
			int cpos = rdpos;
			char target[DNS_MAX_CNAME_LEN];
			if (_resolve_wire_read_name(data, data_len, &cpos, target, sizeof(target)) >= 0) {
				safe_strncpy(qr->cname, target, sizeof(qr->cname));
			}
		}
	}
}

static void _resolve_parse_response(unsigned char *data, int data_len, int qtype, struct dns_server_query_result *qr)
{
	unsigned char buf[DNS_IN_PACKSIZE + sizeof(struct dns_packet) + 64];
	struct dns_packet *packet = (struct dns_packet *)buf;
	memset(buf, 0, sizeof(buf));

	if (dns_decode(packet, sizeof(buf), data, data_len) < 0) {
		qr->rcode = -1;
		return;
	}

	qr->rcode = packet->head.rcode;
	qr->ips[0] = '\0';
	qr->cname[0] = '\0';
	qr->ip_count = 0;
	qr->ttl = 0;

	int ancount = 0;
	struct dns_rrs *rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &ancount);
	while (rrs) {
		char rr_domain[DNS_MAX_CNAME_LEN];
		int rr_ttl = 0;

		switch (rrs->type) {
		case DNS_T_A: {
			unsigned char addr[DNS_RR_A_LEN];
			if (dns_get_A(rrs, rr_domain, sizeof(rr_domain), &rr_ttl, addr) == 0) {
				char ip_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
				if (qr->ip_count > 0)
					strlcat(qr->ips, ", ", sizeof(qr->ips));
				strlcat(qr->ips, ip_str, sizeof(qr->ips));
				qr->ip_count++;
				qr->ttl = rr_ttl;
			}
			break;
		}
		case DNS_T_AAAA: {
			unsigned char addr[DNS_RR_AAAA_LEN];
			if (dns_get_AAAA(rrs, rr_domain, sizeof(rr_domain), &rr_ttl, addr) == 0) {
				char ip_str[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
				if (qr->ip_count > 0)
					strlcat(qr->ips, ", ", sizeof(qr->ips));
				strlcat(qr->ips, ip_str, sizeof(qr->ips));
				qr->ip_count++;
				qr->ttl = rr_ttl;
			}
			break;
		}
		case DNS_T_CNAME: {
			char cname[DNS_MAX_CNAME_LEN];
			if (dns_get_CNAME(rrs, rr_domain, sizeof(rr_domain), &rr_ttl, cname, sizeof(cname)) == 0) {
				safe_strncpy(qr->cname, cname, sizeof(qr->cname));
			}
			break;
		}
		default:
			break;
		}
		rrs = dns_get_rrs_next(packet, rrs);
	}

	/* Other record types (NS/MX/SRV/TXT/SOA/PTR/HTTPS) are stored as opaque
	 * wire rdata by the smartdns decoder and cannot be read through the rrs
	 * API. Parse the raw wire packet answer section directly instead. */
	if (qtype != DNS_T_A && qtype != DNS_T_AAAA) {
		_resolve_parse_wire_answers(data, data_len, qtype, qr);
	}
}

/* Populate chain->query_results[] by querying UDP servers. When
 * query_all_servers is non-zero, all servers (including fallback) are
 * queried in one pass and the result is not written to the cache. */
static void _resolve_query_servers(const char *domain, struct domain_rule_resolve_chain *chain, int query_all_servers,
								   int qtype)
{
	chain->query_result_num = 0;
	chain->final_rcode = -1;
	chain->final_ips[0] = '\0';
	chain->final_cname[0] = '\0';
	chain->final_from[0] = '\0';
	chain->final_ttl = 0;
	chain->final_ping_ms = 0;

	/* Query servers in two phases, consistent with dns_client behavior:
	 * fallback servers (marked with a trailing '*') are only queried when
	 * all non-fallback servers fail to answer. */
	int primary_server_idx[DNS_MAX_CHECK_SERVERS];
	int primary_server_num = 0;
	int fallback_server_idx[DNS_MAX_CHECK_SERVERS];
	int fallback_server_num = 0;

	/* Raw response packets of successful results, used for cache insert */
	unsigned char *resp_data[DNS_MAX_CHECK_SERVERS] = {0};
	int resp_len[DNS_MAX_CHECK_SERVERS] = {0};

	for (int i = 0; i < chain->server_num && i < DNS_MAX_CHECK_SERVERS; i++) {
		if (query_all_servers) {
			primary_server_idx[primary_server_num++] = i;
			continue;
		}
		size_t srv_len = strlen(chain->servers[i]);
		if (srv_len > 0 && chain->servers[i][srv_len - 1] == '*') {
			fallback_server_idx[fallback_server_num++] = i;
		} else {
			primary_server_idx[primary_server_num++] = i;
		}
	}

	for (int pass = 0; pass < (query_all_servers ? 1 : 2) && chain->query_result_num < DNS_MAX_CHECK_SERVERS; pass++) {
		int *server_list = (pass == 0) ? primary_server_idx : fallback_server_idx;
		int server_list_num = (pass == 0) ? primary_server_num : fallback_server_num;

		for (int j = 0; j < server_list_num && chain->query_result_num < DNS_MAX_CHECK_SERVERS; j++) {
			int i = server_list[j];

			/* Only query UDP servers */
			if (strncmp(chain->servers[i], "udp://", 6) != 0) {
				continue;
			}

			char ip[DNS_MAX_IPLEN];
			int port = 53;
			_parse_server_addr(chain->servers[i], ip, sizeof(ip), &port);

			struct dns_server_query_result *qr = &chain->query_results[chain->query_result_num];
			safe_strncpy(qr->server, chain->servers[i], sizeof(qr->server));

			unsigned char response[DNS_IN_PACKSIZE];
			int rlen = _resolve_udp_query(ip, port, domain, qtype, response, sizeof(response), &qr->ping_ms);
			if (rlen > 0) {
				_resolve_parse_response(response, rlen, qtype, qr);
				/* Keep the raw response packet so the winning result can be
				 * inserted into the shared DNS cache afterwards. */
				if (qr->rcode == 0 && resp_data[chain->query_result_num] == NULL) {
					resp_data[chain->query_result_num] = malloc(rlen);
					if (resp_data[chain->query_result_num] != NULL) {
						memcpy(resp_data[chain->query_result_num], response, rlen);
						resp_len[chain->query_result_num] = rlen;
					}
				}
			} else {
				qr->rcode = -1;
			}
			chain->query_result_num++;
		}

		/* Stop before the fallback pass if any primary server answered */
		if (pass == 0) {
			int has_success = 0;
			for (int i = 0; i < chain->query_result_num; i++) {
				if (chain->query_results[i].rcode == 0) {
					has_success = 1;
					break;
				}
			}
			if (has_success) {
				break;
			}
		}
	}

	/* Select final result based on response_mode */
	int best_idx = -1;
	if (qtype != DNS_T_A && qtype != DNS_T_AAAA) {
		/* Non-IP record types: speed check and response_mode do not apply,
		 * take the first successful answer (empty NOERROR = NODATA). */
		for (int i = 0; i < chain->query_result_num; i++) {
			struct dns_server_query_result *qr = &chain->query_results[i];
			if (qr->rcode == 0 && (qr->rdata[0] != '\0' || qr->cname[0] != '\0')) {
				best_idx = i;
				break;
			}
		}
		if (best_idx < 0) {
			/* No records but NOERROR: report the empty answer as NODATA */
			for (int i = 0; i < chain->query_result_num; i++) {
				if (chain->query_results[i].rcode == 0) {
					best_idx = i;
					break;
				}
			}
		}
	} else if (chain->response_mode == DNS_RESPONSE_MODE_FASTEST_RESPONSE ||
			   chain->response_mode == DNS_RESPONSE_MODE_FASTEST_IP) {
		/* FASTEST_RESPONSE: select server with smallest ping_ms */
		/* FASTEST_IP: simplified - same as FASTEST_RESPONSE for now */
		for (int i = 0; i < chain->query_result_num; i++) {
			struct dns_server_query_result *qr = &chain->query_results[i];
			if (qr->rcode == 0 && qr->ip_count > 0 &&
				(best_idx < 0 || qr->ping_ms < chain->query_results[best_idx].ping_ms)) {
				best_idx = i;
			}
		}

		/* No IPs found, try CNAME */
		if (best_idx < 0) {
			for (int i = 0; i < chain->query_result_num; i++) {
				struct dns_server_query_result *qr = &chain->query_results[i];
				if (qr->rcode == 0 && qr->cname[0] != '\0' &&
					(best_idx < 0 || qr->ping_ms < chain->query_results[best_idx].ping_ms)) {
					best_idx = i;
				}
			}
		}
	} else {
		/* FIRST_PING_IP: prefer first server with IPs, then CNAME */
		for (int i = 0; i < chain->query_result_num; i++) {
			struct dns_server_query_result *qr = &chain->query_results[i];
			if (qr->rcode == 0 && qr->ip_count > 0) {
				best_idx = i;
				break;
			}
		}
		if (best_idx < 0) {
			for (int i = 0; i < chain->query_result_num; i++) {
				struct dns_server_query_result *qr = &chain->query_results[i];
				if (qr->rcode == 0 && qr->cname[0] != '\0') {
					best_idx = i;
					break;
				}
			}
		}
	}

	if (best_idx >= 0) {
		struct dns_server_query_result *qr = &chain->query_results[best_idx];
		chain->final_rcode = 0;
		safe_strncpy(chain->final_from, qr->server, sizeof(chain->final_from));
		chain->final_ping_ms = qr->ping_ms;
		chain->final_ttl = qr->ttl;
		if (qr->ip_count > 0) {
			safe_strncpy(chain->final_ips, qr->ips, sizeof(chain->final_ips));
		} else {
			safe_strncpy(chain->final_cname, qr->cname, sizeof(chain->final_cname));
		}
		safe_strncpy(chain->final_data, qr->rdata, sizeof(chain->final_data));
	} else {
		/* No success, return first error rcode */
		for (int i = 0; i < chain->query_result_num; i++) {
			struct dns_server_query_result *qr = &chain->query_results[i];
			if (qr->rcode != 0 && qr->rcode != -1) {
				chain->final_rcode = qr->rcode;
				safe_strncpy(chain->final_from, qr->server, sizeof(chain->final_from));
				break;
			}
		}
	}

	/* Insert the winning answer into the shared DNS cache so that checker
	 * queries populate the cache like normal requests do. Only A/AAAA/HTTPS
	 * are cached, same as the dns_server pipeline. The cache module may be
	 * uninitialized (CLI check mode); dns_cache_insert() handles that safely
	 * (no-op). Skipped in query_all_servers mode (read-only). */
	if (!query_all_servers && (qtype == DNS_T_A || qtype == DNS_T_AAAA || qtype == DNS_T_HTTPS) && best_idx >= 0 &&
		chain->final_rcode == 0 && chain->final_ttl > 0 && resp_data[best_idx] != NULL) {
		struct dns_cache_key cache_key;
		memset(&cache_key, 0, sizeof(cache_key));
		cache_key.domain = domain;
		cache_key.qtype = qtype;
		cache_key.dns_group_name = (strcmp(chain->group_name, "default") == 0) ? "" : chain->group_name;
		cache_key.query_flag = 0;

		/* cache speed is in 0.1ms units, final_ping_ms is in ms */
		struct dns_cache_data *cache_data = dns_cache_new_data_packet(resp_data[best_idx], resp_len[best_idx]);
		if (cache_data != NULL) {
			dns_cache_insert(&cache_key, 0, (int)chain->final_ttl, (int)(chain->final_ping_ms * 10),
							 (int)chain->final_ttl, cache_data);
		}
	}

	for (int i = 0; i < DNS_MAX_CHECK_SERVERS; i++) {
		free(resp_data[i]);
	}
}

/* Fill chain cache fields from a cache entry. Decodes the cached DNS packet
 * to extract IPs and CNAME for display. */
static void _resolve_fill_cache_info(struct domain_rule_resolve_chain *chain, struct dns_cache *dns_cache)
{
	struct dns_server_query_result qr;
	struct dns_cache_packet *cache_packet = NULL;

	chain->cache_hit = 1;
	chain->cache_ttl = dns_cache_get_ttl(dns_cache);
	chain->cache_speed = (int)dns_cache->info.speed;
	chain->cache_rcode = dns_cache->info.rcode;
	safe_strncpy(chain->cache_from_group, dns_cache->info.dns_group_name, sizeof(chain->cache_from_group));

	memset(&qr, 0, sizeof(qr));
	cache_packet = (struct dns_cache_packet *)dns_cache_get_data(dns_cache);
	if (cache_packet != NULL) {
		_resolve_parse_response(cache_packet->data, cache_packet->head.size, chain->query_qtype, &qr);
		dns_cache_data_put((struct dns_cache_data *)cache_packet);
	}

	safe_strncpy(chain->cache_ips, qr.ips, sizeof(chain->cache_ips));
	safe_strncpy(chain->cache_cname, qr.cname, sizeof(chain->cache_cname));
}

/* Look up the DNS cache for the domain (informational only, does not affect
 * the query path). Cache entries are keyed by group name; default-group
 * requests are stored with an empty group name, so try both. */
static void _resolve_check_cache(const char *domain, struct domain_rule_resolve_chain *chain)
{
	struct dns_cache_key cache_key;
	struct dns_cache *dns_cache = NULL;
	const char *groups[2];
	int group_num = 0;

	if (chain->action != DOMAIN_ACTION_NAMESERVER && chain->action != DOMAIN_ACTION_NONE) {
		return;
	}

	/* Only IP/HTTPS record types are cached, same as the dns_server pipeline. */
	if (chain->query_qtype != DNS_T_A && chain->query_qtype != DNS_T_AAAA && chain->query_qtype != DNS_T_HTTPS) {
		return;
	}

	if (chain->group_name[0] != '\0') {
		groups[group_num++] = chain->group_name;
	}
	groups[group_num++] = "";

	for (int gi = 0; gi < group_num && dns_cache == NULL; gi++) {
		memset(&cache_key, 0, sizeof(cache_key));
		cache_key.domain = domain;
		cache_key.qtype = chain->query_qtype;
		cache_key.dns_group_name = groups[gi];
		cache_key.query_flag = 0;

		dns_cache = dns_cache_lookup(&cache_key);
		if (dns_cache != NULL) {
			_resolve_fill_cache_info(chain, dns_cache);
		}
	}

	if (dns_cache != NULL) {
		dns_cache_release(dns_cache);
	}
}

int dns_conf_resolve_domain(const char *domain, struct domain_rule_resolve_chain *chain)
{
	return dns_conf_resolve_domain_ex(domain, chain, 0, 0, DNS_T_A);
}

int dns_conf_resolve_domain_ex(const char *domain, struct domain_rule_resolve_chain *chain, int clear_cache,
							   int query_all_servers, int qtype)
{
	if (domain == NULL || chain == NULL) {
		return -1;
	}

	memset(chain, 0, sizeof(*chain));

	/* Validate the requested record type, fall back to A for unknown values. */
	switch (qtype) {
	case DNS_T_A:
	case DNS_T_AAAA:
	case DNS_T_CNAME:
	case DNS_T_NS:
	case DNS_T_MX:
	case DNS_T_SRV:
	case DNS_T_TXT:
	case DNS_T_SOA:
	case DNS_T_PTR:
	case DNS_T_HTTPS:
		break;
	default:
		qtype = DNS_T_A;
		break;
	}
	chain->query_qtype = qtype;

	/* Delete cached entries of this domain (all qtypes/groups) when
	 * requested, then fall through to a fresh live query. */
	if (clear_cache) {
		int removed_count = 0;
		dns_cache_remove_by_suffix(domain, &removed_count);
		tlog(TLOG_INFO, "check-domain-rule: cleared %d cache entries for %s", removed_count, domain);
	}

	/* Phase 1+2: rule matching (reuse existing function) */
	struct domain_rule_check_result rule_result;
	if (dns_conf_check_domain_rule(domain, &rule_result) != 0) {
		safe_strncpy(chain->domain, domain, DNS_MAX_CNAME_LEN);
		safe_strncpy(chain->rule_name, "PASS", DOMAIN_RULE_NAME_MAX_LEN);
		chain->action = DOMAIN_ACTION_NONE;
		return -1;
	}

	/* Copy rule match results into chain */
	safe_strncpy(chain->domain, rule_result.domain, DNS_MAX_CNAME_LEN);
	safe_strncpy(chain->rule_name, rule_result.rule_name, DOMAIN_RULE_NAME_MAX_LEN);
	safe_strncpy(chain->matched_pattern, rule_result.matched_pattern, DNS_MAX_CNAME_LEN);
	chain->action = rule_result.action;
	safe_strncpy(chain->group_name, rule_result.group_name, DNS_GROUP_NAME_LEN);
	chain->server_num = rule_result.server_num;
	memcpy(chain->servers, rule_result.servers, sizeof(chain->servers));
	chain->response_mode = rule_result.response_mode;

	/* FIRST_PING_IP requires ping-based speed check to pick the answer */
	chain->speed_check_enabled = (chain->response_mode == DNS_RESPONSE_MODE_FIRST_PING_IP);

	/* Phase 3: cache lookup — a valid cached answer is served directly,
	 * same as dns_server cache behavior, no upstream query is made.
	 * Cache info is still collected for display when query_all_servers. */
	_resolve_check_cache(domain, chain);

	if (!query_all_servers && chain->cache_hit && chain->cache_ttl > 0 &&
		(chain->cache_rcode != 0 || chain->cache_ips[0] != '\0' || chain->cache_cname[0] != '\0')) {
		chain->final_rcode = chain->cache_rcode;
		safe_strncpy(chain->final_ips, chain->cache_ips, sizeof(chain->final_ips));
		safe_strncpy(chain->final_cname, chain->cache_cname, sizeof(chain->final_cname));
		safe_strncpy(chain->final_from, "cache", sizeof(chain->final_from));
		chain->final_ttl = (unsigned int)chain->cache_ttl;
		/* cache_speed is in 0.1ms units and may be negative when the speed
		 * check failed; final_ping_ms is unsigned, clamp invalid values to 0. */
		chain->final_ping_ms = (chain->cache_speed > 0) ? (unsigned int)(chain->cache_speed / 10) : 0;
		return 0;
	}

	/* Phase 4: query servers and select final result (only for NAMESERVER/NONE) */
	if (chain->action == DOMAIN_ACTION_NAMESERVER || chain->action == DOMAIN_ACTION_NONE) {
		_resolve_query_servers(domain, chain, query_all_servers, qtype);
	}

	return 0;
}

