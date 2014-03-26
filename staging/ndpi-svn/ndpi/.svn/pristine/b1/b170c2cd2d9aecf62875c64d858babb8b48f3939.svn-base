/* ndpi_credis.h -- a C client library for Redis, public API.
 *
 * Copyright (c) 2009-2010, Jonas Romfelt <jonas at romfelt dot se>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Ndpi_Credis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __NDPI_NDPI_CREDIS_H
#define __NDPI_NDPI_CREDIS_H

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Functions list below is modelled after the Redis Command Reference (except
 * for the ndpi_credis_connect() and ndpi_credis_close() functions), use this reference 
 * for further descriptions of each command:
 *
 *    http://code.google.com/p/redis/wiki/CommandReference
 *
 * Comments are only available when it is not obvious how Ndpi_Credis implements 
 * the Redis command. In general, functions return 0 on success or a negative
 * value on error. Refer to NDPI_NDPI_CREDIS_ERR_* codes. The return code -1 is 
 * typically used when for instance a key is not found. 
 *
 * IMPORTANT! Memory buffers are allocated, used and managed by ndpi_credis 
 * internally. Subsequent calls to ndpi_credis functions _will_ destroy the data 
 * to which returned values reference to. If for instance the returned value 
 * by a call to ndpi_credis_get() is to be used later in the program, a strdup() 
 * is highly recommended. However, each `REDIS' handle has its own state and 
 * manages its own memory buffers independently. That means that one of two 
 * handles can be destroyed while the other keeps its connection and data.
 * 
 * EXAMPLE
 * 
 * Connect to a Redis server and set value of key `fruit' to `banana': 
 *
 *    NDPI_REDIS rh = ndpi_credis_connect("localhost", 6789, 2000);
 *    ndpi_credis_set(rh, "fruit", "banana");
 *    ndpi_credis_close(rh);
 *
 * TODO
 *
 *  - Add support for missing Redis commands marked as TODO below
 *  - Currently only support for zero-terminated strings, not for storing 
 *    abritary binary data as bulk data. Basically an API issue since it is 
 *    partially supported internally.
 *  - Test 
 */

/* handle to a Redis server connection */
typedef struct _cr_redis* NDPI_REDIS;

#define NDPI_CREDIS_OK 0
#define NDPI_CREDIS_ERR -90
#define NDPI_CREDIS_ERR_NOMEM -91
#define NDPI_CREDIS_ERR_RESOLVE -92
#define NDPI_CREDIS_ERR_CONNECT -93
#define NDPI_CREDIS_ERR_SEND -94
#define NDPI_CREDIS_ERR_RECV -95
#define NDPI_CREDIS_ERR_TIMEOUT -96
#define NDPI_CREDIS_ERR_PROTOCOL -97

#define NDPI_CREDIS_TYPE_NONE 1
#define NDPI_CREDIS_TYPE_STRING 2
#define NDPI_CREDIS_TYPE_LIST 3
#define NDPI_CREDIS_TYPE_SET 4

#define NDPI_CREDIS_SERVER_MASTER 1
#define NDPI_CREDIS_SERVER_SLAVE 2

typedef enum _ndpi_cr_aggregate {
  NDPI_NONE,
  NDPI_SUM, 
  NDPI_MIN,
  NDPI_MAX
} NDPI_REDIS_AGGREGATE;

#define NDPI_CREDIS_VERSION_STRING_SIZE 32
#define NDPI_CREDIS_MULTIPLEXING_API_SIZE 16
#define NDPI_CREDIS_USED_MEMORY_HUMAN_SIZE 32

typedef struct _ndpi_cr_info {
  char redis_version[NDPI_CREDIS_VERSION_STRING_SIZE];
  int arch_bits;
  char multiplexing_api[NDPI_CREDIS_MULTIPLEXING_API_SIZE];
  long process_id;
  long uptime_in_seconds;
  long uptime_in_days;
  int connected_clients;
  int connected_slaves;
  int blocked_clients;
  unsigned long used_memory;
  char used_memory_human[NDPI_CREDIS_USED_MEMORY_HUMAN_SIZE];
  long long changes_since_last_save;
  int bgsave_in_progress;
  long last_save_time;
  int bgrewriteaof_in_progress;
  long long total_connections_received;
  long long total_commands_processed;
  long long expired_keys;
  unsigned long hash_max_zipmap_entries;
  unsigned long hash_max_zipmap_value;
  long pubsub_channels;
  unsigned int pubsub_patterns;
  int vm_enabled;
  int role;
} NDPI_REDIS_INFO;


/*
 * Connection handling
 */

/* `host' is the host to connect to, either as an host name or a IP address, 
 * if set to NULL connection is made to "localhost". `port' is the TCP port 
 * that Redis is listening to, set to 0 will use default port (6379). 
 * `timeout' is the time in milliseconds to use as timeout, when connecting 
 * to a Redis server and waiting for reply, it can be changed after a
 * connection has been made using ndpi_credis_settimeout() */
NDPI_REDIS ndpi_credis_connect(const char *host, int port, int timeout);

/* set Redis server reply `timeout' in millisecs */ 
void ndpi_credis_settimeout(NDPI_REDIS rhnd, int timeout);

void ndpi_credis_close(NDPI_REDIS rhnd);

void ndpi_credis_quit(NDPI_REDIS rhnd);

int ndpi_credis_auth(NDPI_REDIS rhnd, const char *password);

int ndpi_credis_ping(NDPI_REDIS rhnd);

/* if a function call returns error it is _possible_ that the Redis server
 * replied with an error message. It is returned by this function. */
char* ndpi_credis_errorreply(NDPI_REDIS rhnd);

/* 
 * Commands operating on all the kind of values
 */

/* returns -1 if the key doesn't exists and 0 if it does */
int ndpi_credis_exists(NDPI_REDIS rhnd, const char *key);

/* returns -1 if the key doesn't exists and 0 if it was removed 
 * TODO add support to (Redis >= 1.1) remove multiple keys 
 */
int ndpi_credis_del(NDPI_REDIS rhnd, const char *key);

/* returns type, refer to NDPI_CREDIS_TYPE_* defines */
int ndpi_credis_type(NDPI_REDIS rhnd, const char *key);

/* returns number of keys returned in vector `keyv' */
int ndpi_credis_keys(NDPI_REDIS rhnd, const char *pattern, char ***keyv);

int ndpi_credis_randomkey(NDPI_REDIS rhnd, char **key);

int ndpi_credis_rename(NDPI_REDIS rhnd, const char *key, const char *new_key_name);

/* returns -1 if the key already exists */
int ndpi_credis_renamenx(NDPI_REDIS rhnd, const char *key, const char *new_key_name);

/* returns size of db */
int ndpi_credis_dbsize(NDPI_REDIS rhnd);

/* returns -1 if the timeout was not set; either due to key already has 
   an associated timeout or key does not exist */
int ndpi_credis_expire(NDPI_REDIS rhnd, const char *key, int secs);

/* returns time to live seconds or -1 if key does not exists or does not 
 * have expire set */
int ndpi_credis_ttl(NDPI_REDIS rhnd, const char *key);

int ndpi_credis_select(NDPI_REDIS rhnd, int index);

/* returns -1 if the key was not moved; already present at target 
 * or not found on current db */
int ndpi_credis_move(NDPI_REDIS rhnd, const char *key, int index);

int ndpi_credis_flushdb(NDPI_REDIS rhnd);

int ndpi_credis_flushall(NDPI_REDIS rhnd);


/* 
 * Commands operating on string values 
 */

int ndpi_credis_set(NDPI_REDIS rhnd, const char *key, const char *val);

/* returns -1 if the key doesn't exists */
int ndpi_credis_get(NDPI_REDIS rhnd, const char *key, char **val);

/* returns -1 if the key doesn't exists */
int ndpi_credis_getset(NDPI_REDIS rhnd, const char *key, const char *set_val, char **get_val);

/* returns number of values returned in vector `valv'. `keyc' is the number of
 * keys stored in `keyv'. */
int ndpi_credis_mget(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***valv);

/* returns -1 if the key already exists and hence not set */
int ndpi_credis_setnx(NDPI_REDIS rhnd, const char *key, const char *val);

/* TODO
 * SETEX key time value Set+Expire combo command
 * MSET key1 value1 key2 value2 ... keyN valueN set a multiple keys to multiple values in a single atomic operation
 * MSETNX key1 value1 key2 value2 ... keyN valueN set a multiple keys to multiple values in a single atomic operation if none of
 */

/* if `new_val' is not NULL it will return the value after the increment was performed */
int ndpi_credis_incr(NDPI_REDIS rhnd, const char *key, int *new_val);

/* if `new_val' is not NULL it will return the value after the increment was performed */
int ndpi_credis_incrby(NDPI_REDIS rhnd, const char *key, int incr_val, int *new_val);

/* if `new_val' is not NULL it will return the value after the decrement was performed */
int ndpi_credis_decr(NDPI_REDIS rhnd, const char *key, int *new_val);

/* if `new_val' is not NULL it will return the value after the decrement was performed */
int ndpi_credis_decrby(NDPI_REDIS rhnd, const char *key, int decr_val, int *new_val);

/* returns new length of string after `val' has been appended */
int ndpi_credis_append(NDPI_REDIS rhnd, const char *key, const char *val);

int ndpi_credis_substr(NDPI_REDIS rhnd, const char *key, int start, int end, char **substr);


/*
 * Commands operating on lists 
 */

int ndpi_credis_rpush(NDPI_REDIS rhnd, const char *key, const char *element);
int ndpi_credis_rpushx(NDPI_REDIS rhnd, const char *key, const char *element); /* ntop */

int ndpi_credis_lpush(NDPI_REDIS rhnd, const char *key, const char *element);

/* returns length of list */
int ndpi_credis_llen(NDPI_REDIS rhnd, const char *key);

/* returns number of elements returned in vector `elementv' */
int ndpi_credis_lrange(NDPI_REDIS rhnd, const char *key, int start, int range, char ***elementv);

int ndpi_credis_ltrim(NDPI_REDIS rhnd, const char *key, int start, int end);

/* returns -1 if the key doesn't exists */
int ndpi_credis_lindex(NDPI_REDIS rhnd, const char *key, int index, char **element);

int ndpi_credis_lset(NDPI_REDIS rhnd, const char *key, int index, const char *element);

/* returns number of elements removed */
int ndpi_credis_lrem(NDPI_REDIS rhnd, const char *key, int count, const char *element);

/* returns -1 if the key doesn't exists */
int ndpi_credis_lpop(NDPI_REDIS rhnd, const char *key, char **val);

/* returns -1 if the key doesn't exists */
int ndpi_credis_rpop(NDPI_REDIS rhnd, const char *key, char **val);

/* TODO 
 * BLPOP key1 key2 ... keyN timeout Blocking LPOP
 * BRPOP key1 key2 ... keyN timeout Blocking RPOP
 * RPOPLPUSH srckey dstkey Return and remove (atomically) the last element of the source List stored at _srckey_ and push the same element to the destination List stored at _dstkey_ 
 */


/*
 * Commands operating on sets 
 */

/* returns -1 if the given member was already a member of the set */
int ndpi_credis_sadd(NDPI_REDIS rhnd, const char *key, const char *member);

/* returns -1 if the given member is not a member of the set */
int ndpi_credis_srem(NDPI_REDIS rhnd, const char *key, const char *member);

/* returns -1 if the given key doesn't exists else value is returned in `member' */
int ndpi_credis_spop(NDPI_REDIS rhnd, const char *key, char **member);

/* returns -1 if the member doesn't exists in the source set */
int ndpi_credis_smove(NDPI_REDIS rhnd, const char *sourcekey, const char *destkey, 
                 const char *member);

/* returns cardinality (number of members) or 0 if the given key doesn't exists */
int ndpi_credis_scard(NDPI_REDIS rhnd, const char *key);

/* returns -1 if the key doesn't exists and 0 if it does */
int ndpi_credis_sismember(NDPI_REDIS rhnd, const char *key, const char *member);

/* returns number of members returned in vector `members'. `keyc' is the number of
 * keys stored in `keyv'. */
int ndpi_credis_sinter(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***members);

/* `keyc' is the number of keys stored in `keyv' */
int ndpi_credis_sinterstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv);

/* returns number of members returned in vector `members'. `keyc' is the number of
 * keys stored in `keyv'. */
int ndpi_credis_sunion(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***members);

/* `keyc' is the number of keys stored in `keyv' */
int ndpi_credis_sunionstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv);

/* returns number of members returned in vector `members'. `keyc' is the number of
 * keys stored in `keyv'. */
int ndpi_credis_sdiff(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***members);

/* `keyc' is the number of keys stored in `keyv' */
int ndpi_credis_sdiffstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv);

/* returns number of members returned in vector `members' */
int ndpi_credis_smembers(NDPI_REDIS rhnd, const char *key, char ***members);

/* TODO Redis >= 1.1
 * SRANDMEMBER key Return a random member of the Set value at key
 */


/* 
 * Commands operating on sorted sets
 */

/* returns -1 if member was already a member of the sorted set and only score was updated, 
 * 0 is returned if the new element was added */
int ndpi_credis_zadd(NDPI_REDIS rhnd, const char *key, double score, const char *member);

/* returns -1 if the member was not a member of the sorted set */
int ndpi_credis_zrem(NDPI_REDIS rhnd, const char *key, const char *member);

/* returns -1 if the member was not a member of the sorted set, the score of the member after
 * the increment by `incr_score' is returned by `new_score' */
int ndpi_credis_zincrby(NDPI_REDIS rhnd, const char *key, double incr_score, const char *member, double *new_score);

/* returns the rank of the given member or -1 if the member was not a member of the sorted set */
int ndpi_credis_zrank(NDPI_REDIS rhnd, const char *key, const char *member);

/* returns the reverse rank of the given member or -1 if the member was not a member of the sorted set */
int ndpi_credis_zrevrank(NDPI_REDIS rhnd, const char *key, const char *member);

/* returns number of elements returned in vector `elementv' 
 * TODO add support for WITHSCORES */
int ndpi_credis_zrange(NDPI_REDIS rhnd, const char *key, int start, int end, char ***elementv);

/* returns number of elements returned in vector `elementv' 
 * TODO add support for WITHSCORES */
int ndpi_credis_zrevrange(NDPI_REDIS rhnd, const char *key, int start, int end, char ***elementv);

/* returns cardinality or -1 if `key' does not exist */
int ndpi_credis_zcard(NDPI_REDIS rhnd, const char *key);

/* returns -1 if the `key' does not exist or the `member' is not in the sorted set,
 * score is returned in `score' */
int ndpi_credis_zscore(NDPI_REDIS rhnd, const char *key, const char *member, double *score);

/* returns number of elements removed or -1 if key does not exist */
int ndpi_credis_zremrangebyscore(NDPI_REDIS rhnd, const char *key, double min, double max);

/* returns number of elements removed or -1 if key does not exist */
int ndpi_credis_zremrangebyrank(NDPI_REDIS rhnd, const char *key, int start, int end);

/* TODO
 * ZRANGEBYSCORE key min max Return all the elements with score >= min and score <= max (a range query) from the sorted set
 */

/* `keyc' is the number of keys stored in `keyv'. `weightv' is optional, if not 
 * NULL, `keyc' is also the number of weights stored in `weightv'. */
int ndpi_credis_zinterstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv, 
                       const int *weightv, NDPI_REDIS_AGGREGATE aggregate);

/* `keyc' is the number of keys stored in `keyv'. `weightv' is optional, if not 
 * NULL, `keyc' is also the number of weights stored in `weightv'. */
int ndpi_credis_zunionstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv, 
                       const int *weightv, NDPI_REDIS_AGGREGATE aggregate);

/* 
 * Commands operating on hashes
 */

/* TODO
 * HSET key field value Set the hash field to the specified value. Creates the hash if needed.
 * HGET key field Retrieve the value of the specified hash field.
 * HMSET key field1 value1 ... fieldN valueN Set the hash fields to their respective values.
 * HINCRBY key field integer Increment the integer value of the hash at _key_ on _field_ with _integer_.
 * HEXISTS key field Test for existence of a specified field in a hash
 * HDEL key field Remove the specified field from a hash
 * HLEN key Return the number of items in a hash.
 * HKEYS key Return all the fields in a hash.
 * HVALS key Return all the values in a hash.
 * HGETALL key Return all the fields and associated values in a hash.
 */


/*
 * Sorting 
 */

/* returns number of elements returned in vector `elementv' */
int ndpi_credis_sort(NDPI_REDIS rhnd, const char *query, char ***elementv);


/*
 * Transactions
 */

/* TODO
 * MULTI/EXEC/DISCARD Redis atomic transactions
 */


/*
 * Publish/Subscribe
 */

/* TODO
 * SUBSCRIBE/UNSUBSCRIBE/PUBLISH Redis Public/Subscribe messaging paradigm implementation
 */


/* 
 * Persistence control commands 
 */

int ndpi_credis_save(NDPI_REDIS rhnd);

int ndpi_credis_bgsave(NDPI_REDIS rhnd);

/* returns UNIX time stamp of last successfull save to disk */
int ndpi_credis_lastsave(NDPI_REDIS rhnd);

int ndpi_credis_shutdown(NDPI_REDIS rhnd);

int ndpi_credis_bgrewriteaof(NDPI_REDIS rhnd);


/*
 * Remote server control commands 
 */

/* Because the information returned by the Redis changes with virtually every 
 * major release, ndpi_credis tries to parse for as many fields as it is aware of, 
 * staying backwards (and forwards) compatible with older (and newer) versions 
 * of Redis. 
 * Information fields not supported by the Redis server connected to, are set
 * to zero. */
int ndpi_credis_info(NDPI_REDIS rhnd, NDPI_REDIS_INFO *info);

int ndpi_credis_monitor(NDPI_REDIS rhnd);

/* setting host to NULL and/or port to 0 will turn off replication */
int ndpi_credis_slaveof(NDPI_REDIS rhnd, const char *host, int port);

/* TODO
 * CONFIG Configure a Redis server at runtime
 */


#ifdef __cplusplus
}
#endif

#endif /* __NDPI_CREDIS_H */
