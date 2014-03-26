/*
 * ndpi_cache.c
 *
 * Copyright (C) 2013 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

static u_int8_t traceLRU = 0;

#ifndef __KERNEL__
#ifdef __GNUC__
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif
#endif

/* ************************************************************************ */

static u_int32_t get_now(void) {
#ifndef __KERNEL__
  return((u_int32_t)time(NULL));
#else
  return(jiffies);
#endif
}

/* ************************************************************************ */

static u_int32_t compute_timeout(u_int32_t t) {
#ifndef __KERNEL__
  return(t);
#else
  return(t*HZ);
#endif
}

/* ************************************************************************ */

int ndpi_init_lru_cache(struct ndpi_LruCache *cache, u_int32_t max_size) {
  if(unlikely(traceLRU))
    printf("%s(max_size=%u)", __FUNCTION__, max_size);

  cache->max_cache_node_len = 4;
  cache->hash_size = max_size/cache->max_cache_node_len;

#ifdef FULL_STATS
  cache->mem_size += cache->hash_size*sizeof(struct ndpi_LruCacheEntry*);
#endif
  if((cache->hash = (struct ndpi_LruCacheEntry**)ndpi_calloc(cache->hash_size, sizeof(struct ndpi_LruCacheEntry*))) == NULL) {
    printf("ERROR: Not enough memory?");
    return(-1);
  }

#ifdef FULL_STATS
  cache->mem_size += cache->hash_size*sizeof(u_int32_t);
#endif
  if((cache->current_hash_size = (u_int32_t*)ndpi_calloc(cache->hash_size, sizeof(u_int32_t))) == NULL) {
    printf("ERROR: Not enough memory?");
    return(-1);
  }

  return(0);
}

/* ************************************ */

static void free_lru_cache_entry(struct ndpi_LruCache *cache, struct ndpi_LruCacheEntry *entry) {
  if(entry->numeric_node) {
    ; /* Nothing to do */
  } else {
#ifdef FULL_STATS
    cache->mem_size -= strlen(entry->u.str.key);
    cache->mem_size -= strlen(entry->u.str.value);
#endif
    ndpi_free(entry->u.str.key);
    ndpi_free(entry->u.str.value);
  }
}

/* ************************************ */

void ndpi_free_lru_cache(struct ndpi_LruCache *cache) {
  int i;

  if(unlikely(traceLRU)) printf("%s()", __FUNCTION__);

  for(i=0; i<(int)cache->hash_size; i++) {
    struct ndpi_LruCacheEntry *head = cache->hash[i];

    while(head != NULL) {
      struct ndpi_LruCacheEntry *next = head->next;

      free_lru_cache_entry(cache, head);
      ndpi_free(head);
#ifdef FULL_STATS
      cache->mem_size -= sizeof(struct ndpi_LruCacheEntry);
#endif
      head = next;
    }
  }

  ndpi_free(cache->hash);
#ifdef FULL_STATS
  cache->mem_size -= cache->hash_size*sizeof(struct ndpi_LruCacheEntry*);
#endif
  ndpi_free(cache->current_hash_size);
#ifdef FULL_STATS
  cache->mem_size -= cache->hash_size*sizeof(u_int32_t);
#endif
}

/* ************************************ */

static u_int32_t lru_hash_string(char *a) {
  u_int32_t h = 0, i;

  for(i=0; a[i] != 0; i++) h += ((u_int32_t)a[i])*(i+1);
  return(h);
}

/* ************************************ */

#ifdef _NOT_USED_
static u_int32_t lru_node_key_hash(struct ndpi_LruCacheEntry *a) {
  if(a->numeric_node)
    return((u_int32_t)a->u.num.key);
  else
    return(lru_hash_string(a->u.str.key));
}
#endif

/* ************************************ */

#ifdef _NOT_USED_
/*
  Return codes
  0  Items are the same
  -1 a < b
  1  a > b
*/
static int lru_node_key_entry_compare(struct ndpi_LruCacheEntry *a, 
				      struct ndpi_LruCacheEntry *b) {
  if(a->numeric_node) {
    if(a->u.num.key == b->u.num.key)
      return(0);
    else if(a->u.num.key < b->u.num.key)
      return(-1);
    else
      return(1);
  } else
    return(strcmp(a->u.str.key, b->u.str.key));
}
#endif

/* ********************************************* */

struct ndpi_LruCacheEntry* lru_allocCacheNumericNode(struct ndpi_LruCache *cache, u_int64_t key, u_int64_t value) {
  struct ndpi_LruCacheEntry *node = (struct ndpi_LruCacheEntry*)ndpi_calloc(1, sizeof(struct ndpi_LruCacheEntry));

  if(unlikely(traceLRU))
    printf("%s(key=%lu, value=%u)", __FUNCTION__, 
	   (long unsigned int)key, (unsigned int)value);

  if(node == NULL)
    printf("ERROR: Not enough memory?");
  else {
    node->numeric_node = 1;
    node->u.num.key = key, node->u.num.value = value;
  }

#ifdef FULL_STATS
  cache->mem_size += sizeof(struct ndpi_LruCacheEntry);
  //printf("%s(key=%lu, value=%u) [memory: %u]", __FUNCTION__, key, value, cache->mem_size);
#endif

  return(node);
}

/* ************************************ */

struct ndpi_LruCacheEntry* lru_allocCacheStringNode(struct ndpi_LruCache *cache, char *key, char *value, u_int32_t timeout) {
  struct ndpi_LruCacheEntry *node = (struct ndpi_LruCacheEntry*)ndpi_calloc(1, sizeof(struct ndpi_LruCacheEntry));

  if(unlikely(traceLRU))
    printf("%s(key=%s, value=%s)", __FUNCTION__, key, value);

  if(node == NULL)
    printf("ERROR: Not enough memory?");
  else {
    node->numeric_node = 0;
    node->u.str.key = ndpi_strdup(key), node->u.str.value = ndpi_strdup(value);
    node->u.str.expire_time = (timeout == 0) ? 0 : (compute_timeout(timeout) + get_now());

#ifdef FULL_STATS
    cache->mem_size += sizeof(struct ndpi_LruCacheEntry) + strlen(key) + strlen(value);
    //printf("%s(key=%s, value=%s) [memory: %u]", __FUNCTION__, key, value, cache->mem_size);
#endif
  }

  return(node);
}

/* ************************************ */

static void trim_subhash(struct ndpi_LruCache *cache, u_int32_t hash_id) {
  if(unlikely(traceLRU))
    printf("%s()", __FUNCTION__);

  if(cache->current_hash_size[hash_id] >= cache->max_cache_node_len) {
    struct ndpi_LruCacheEntry *head = cache->hash[hash_id], *prev = NULL;

    /* Find the last entry and remove it */
    while(head->next != NULL) {
      prev = head;
      head = head->next;
    }

    if(prev) {
      prev->next = head->next;
      free_lru_cache_entry(cache, head);
      ndpi_free(head);
#ifdef FULL_STATS
      cache->mem_size -= sizeof(struct ndpi_LruCacheEntry);
#endif
      cache->current_hash_size[hash_id]--;
    } else
      printf("ERROR: Internal error in %s()", __FUNCTION__);
  }
}

/* ************************************ */

#ifdef _NOT_USED_
static void validate_unit_len(struct ndpi_LruCache *cache, u_int32_t hash_id) {
  struct ndpi_LruCacheEntry *head = cache->hash[hash_id];
  u_int num = 0;

  while(head != NULL) {
    head = head->next, num++;
  }

  if(num != cache->current_hash_size[hash_id])
    printf("ERROR: Invalid length [expected: %u][read: %u][hash_id: %u]",
	       cache->current_hash_size[hash_id], num, hash_id);
}
#endif

/* ************************************ */

int ndpi_add_to_lru_cache_num(struct ndpi_LruCache *cache,
			      u_int64_t key, u_int64_t value) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_id = key % cache->hash_size;
    struct ndpi_LruCacheEntry *node;
    u_int8_t node_already_existing = 0;
    int rc = 0;

    if(unlikely(traceLRU))
      printf("%s(key=%lu, value=%u)", __FUNCTION__, (long unsigned int)key, (unsigned int)value);

    // validate_unit_len(cache, hash_id);
    cache->num_cache_add++;

    /* [1] Add to hash */
    if(cache->hash[hash_id] == NULL) {
      if((node = lru_allocCacheNumericNode(cache, key, value)) == NULL) {
	rc = -1;
	goto ret_add_to_lru_cache;
      }

      cache->hash[hash_id] = node;
      cache->current_hash_size[hash_id]++;
    } else {
      /* Check if the element exists */
      struct ndpi_LruCacheEntry *head = cache->hash[hash_id];

      while(head != NULL) {
	if(head->u.num.key == key) {
	  /* Duplicated key found */
	  node = head;
	  node->u.num.value = value; /* Overwrite old value */
	  node_already_existing = 1;
	  break;
	} else
	  head = head->next;
      }

      if(!node_already_existing) {
	if((node = lru_allocCacheNumericNode(cache, key, value)) == NULL) {
	  rc = -2;
	  goto ret_add_to_lru_cache;
	}

	node->next = cache->hash[hash_id];
	cache->hash[hash_id] = node;
	cache->current_hash_size[hash_id]++;
      }
    }

    trim_subhash(cache, hash_id);

    // validate_unit_len(cache, hash_id);

  ret_add_to_lru_cache:
    return(rc);
  }
}

/* ************************************ */

int ndpi_add_to_lru_cache_str_timeout(struct ndpi_LruCache *cache,
				     char *key, char *value,
				     u_int32_t timeout) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_val =  lru_hash_string(key);
    u_int32_t hash_id = hash_val % cache->hash_size;
    struct ndpi_LruCacheEntry *node;
    u_int8_t node_already_existing = 0;
    int rc = 0;

    if(unlikely(traceLRU))
      printf("%s(key=%s, value=%s)", __FUNCTION__, key, value);

    // validate_unit_len(cache, hash_id);
    cache->num_cache_add++;

    /* [1] Add to hash */
    if(cache->hash[hash_id] == NULL) {
      if((node = lru_allocCacheStringNode(cache, key, value, timeout)) == NULL) {
	rc = -1;
	goto ret_add_to_lru_cache;
      }

      cache->hash[hash_id] = node;
      cache->current_hash_size[hash_id]++;
    } else {
      /* Check if the element exists */
      struct ndpi_LruCacheEntry *head = cache->hash[hash_id];

      while(head != NULL) {
	if(strcmp(head->u.str.key, key) == 0) {
	  /* Duplicated key found */
	  node = head;
	  if(node->u.str.value) {
#ifdef FULL_STATS
	    cache->mem_size -= strlen(node->u.str.value);
#endif
	    ndpi_free(node->u.str.value);
	  }

	  node->u.str.value = ndpi_strdup(value); /* Overwrite old value */
#ifdef FULL_STATS
	  cache->mem_size += strlen(value);
#endif

	  node->u.str.expire_time = (timeout == 0) ? 0 : (compute_timeout(timeout) + get_now());
	  node_already_existing = 1;
	  break;
	} else
	  head = head->next;
      }

      if(!node_already_existing) {
	if((node = lru_allocCacheStringNode(cache, key, value, timeout)) == NULL) {
	  rc = -2;
	  goto ret_add_to_lru_cache;
	}

	node->next = cache->hash[hash_id];
	cache->hash[hash_id] = node;
	cache->current_hash_size[hash_id]++;
      }
    }

    trim_subhash(cache, hash_id);

    // validate_unit_len(cache, hash_id);

  ret_add_to_lru_cache:
    return(rc);
  }
}

/* ************************************ */

int ndpi_add_to_lru_cache_str(struct ndpi_LruCache *cache, char *key, char *value) {
  ndpi_add_to_lru_cache_str_timeout(cache, key, value, 0);
  return(0);
}

/* ************************************ */

u_int32_t ndpi_find_lru_cache_num(struct ndpi_LruCache *cache, u_int64_t key) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_id = key % cache->hash_size;
    struct ndpi_LruCacheEntry *head, *prev = NULL;
    u_int32_t ret_val = NDPI_PROTOCOL_UNKNOWN;

    if(unlikely(traceLRU))
      printf("%s(%lu)", __FUNCTION__, (long unsigned int)key);

    head = cache->hash[hash_id];
    // validate_unit_len(cache, hash_id);
    cache->num_cache_find++;

    while(head != NULL) {
      if(head->u.num.key == key) {
	ret_val = head->u.num.value;

	/* We now need to move it in front */
	if(prev != NULL) {
	  /* We're not the first element yet */
	  prev->next = head->next;
	  head->next = cache->hash[hash_id];
	  cache->hash[hash_id] = head;
	}
	break;
      } else {
	prev = head;
	head = head->next;
      }
    }

    if(ret_val == NDPI_PROTOCOL_UNKNOWN) cache->num_cache_misses++;

    return(ret_val);
  }
}

/* ************************************ */

char*ndpi_find_lru_cache_str(struct ndpi_LruCache *cache, char *key) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_val =  lru_hash_string(key);
    u_int32_t hash_id = hash_val % cache->hash_size;
    struct ndpi_LruCacheEntry *head, *prev = NULL;
    char *ret_val = NULL;
    time_t now = get_now();

    if(unlikely(traceLRU))
      printf("%s(%s)", __FUNCTION__, key);

    // validate_unit_len(cache, hash_id);
    cache->num_cache_find++;
    head = cache->hash[hash_id];
        
    while(head != NULL) {
      if(strcmp(head->u.str.key, key) == 0) {
	if(head->u.str.expire_time < now) {
	  /* The node has expired */
	  if(prev == NULL)
	    cache->hash[hash_id] = head->next;
	  else
	    prev->next = head->next;

	  free_lru_cache_entry(cache, head);
	  ndpi_free(head);
#ifdef FULL_STATS
	  cache->mem_size -= sizeof(struct ndpi_LruCacheEntry);
#endif
	  ret_val = NULL;
	  cache->current_hash_size[hash_id]--;
	} else
	  ret_val = head->u.str.value;
	break;
      } else {
	prev = head;
	head = head->next;
      }
    }

    if(ret_val == NULL) cache->num_cache_misses++;
    // validate_unit_len(cache, hash_id);

    return(ret_val);
  }
}

/* ************************************ */

#ifdef _NOT_USED_
static void dumpndpi_LruCacheStat(struct ndpi_LruCache *cache,
				  char* cacheName, u_int timeDifference) {
  u_int32_t tot_cache_add = 0, tot_cache_find = 0;
  u_int32_t tot_mem = 0, grand_total_mem = 0;
  u_int32_t num_cache_add = 0, num_cache_find = 0;
  u_int32_t num_cache_misses = 0, grand_total = 0;
  float a, f, m;
  int j, tot;

  tot_cache_add += cache->num_cache_add;
  num_cache_add += cache->num_cache_add - cache->last_num_cache_add;
  cache->last_num_cache_add = cache->num_cache_add;

  tot_cache_find += cache->num_cache_find;
  num_cache_find += cache->num_cache_find - cache->last_num_cache_find;
  cache->last_num_cache_find = cache->num_cache_find;

  num_cache_misses += cache->num_cache_misses - cache->last_num_cache_misses;
  cache->last_num_cache_misses = cache->num_cache_misses;

  for(tot=0, tot_mem=0, j=0; j<(int)cache->hash_size; j++)
    tot += cache->current_hash_size[j], tot_mem += (cache->mem_size+sizeof(struct ndpi_LruCache));

  grand_total += tot;
  grand_total_mem += tot_mem;

#ifdef FULL_STATS
  if(tot > 0)
    printf("LRUCacheUnit %s [current_hash_size: %u][max_cache_node_len: %u][mem_size: %.1f MB/%.1f MB]",
	       cacheName, tot, cache->max_cache_node_len, (float)tot_mem/(float)(1024*1024), (float)grand_total_mem/(float)(1024*1024));
#endif

  a = (timeDifference > 0) ? ((float)num_cache_add)/(float)timeDifference : 0;
  f = (timeDifference > 0) ? ((float)num_cache_find)/(float)timeDifference : 0;
  m = (num_cache_add > 0) ? ((float)(num_cache_misses*100))/((float)num_cache_find) : 0;

  if(tot_cache_find || tot_cache_add)
    printf("LRUCache %s [find: %u operations/%.1f find/sec]"
	       "[cache miss %u/%.1f %%][add: %u operations/%.1f add/sec][tot: %u][mem_size: %.1f MB]",
	       cacheName, tot_cache_find, f, num_cache_misses, m, tot_cache_add, a, grand_total,
	       (float)grand_total_mem/(float)(1024*1024));
}
#endif

