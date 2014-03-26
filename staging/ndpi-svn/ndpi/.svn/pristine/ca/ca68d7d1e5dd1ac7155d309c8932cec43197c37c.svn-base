/* ndpi_credis.c -- a C client library for Redis
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

#ifdef WIN32

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _CRT_SECURE_NO_DEPRECATE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#else 
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ndpi_credis.h"

#ifdef WIN32
void close(int fd) {
  closesocket(fd);
}
#endif

#define CR_ERROR '-'
#define CR_INLINE '+'
#define CR_BULK '$'
#define CR_MULTIBULK '*'
#define CR_INT ':'

#define CR_BUFFER_SIZE 4096
#define CR_BUFFER_WATERMARK ((CR_BUFFER_SIZE)/10+1)
#define CR_MULTIBULK_SIZE 256

#define _STRINGIF(arg) #arg
#define STRINGIFY(arg) _STRINGIF(arg)

#define CR_VERSION_STRING_SIZE_STR STRINGIFY(NDPI_CNDPI_REDIS_VERSION_STRING_SIZE)
#define CR_MULTIPLEXING_API_SIZE_STR STRINGIFY(NDPI_CNDPI_REDIS_MULTIPLEXING_API_SIZE)
#define CR_USED_MEMORY_HUMAN_SIZE_STR STRINGIFY(NDPI_CNDPI_REDIS_USED_MEMORY_HUMAN_SIZE)

#undef CREDIS_DEBUG

#ifdef CREDIS_DEBUG
/* add -DCREDIS_DEBUG to CPPFLAGS in Makefile for debug outputs */
#define DEBUG_PRINT(...)                                 \
  do {                                             \
    printf("%s() @ %d: ", __FUNCTION__, __LINE__); \
    printf(__VA_ARGS__);                           \
    printf("\n");                                  \
  } while (0)
#else
#define DEBUG_PRINT(...)
#endif


/* format warnings are GNU C specific */
#if !__GNUC__
#define __attribute__(x)
#endif

typedef struct _cr_buffer {
  char *data;
  int idx;
  int len;
  int size;
} cr_buffer;

typedef struct _cr_multibulk { 
  char **bulks; 
  int *idxs;
  int size;
  int len; 
} cr_multibulk;

typedef struct _cr_reply {
  int integer;
  char *line;
  char *bulk;
  cr_multibulk multibulk;
} cr_reply;

typedef struct _cr_redis {
  struct {
    int major;
    int minor;
    int patch;
  } version;
  int fd;
  char *ip;
  int port;
  int timeout;
  cr_buffer buf;
  cr_reply reply;
  int error;
} cr_redis;


/* Returns pointer to the '\r' of the first occurence of "\r\n", or NULL
 * if not found */
static char * cr_findnl(char *buf, int len) {
  while (--len >= 0) {
    if (*(buf++) == '\r')
      if (*buf == '\n')
        return --buf;
  }
  return NULL;
}

/* Allocate at least `size' bytes more buffer memory, keeping content of
 * previously allocated memory untouched.
 * Returns:
 *   0  on success
 *  -1  on error, i.e. more memory not available */
static int cr_moremem(cr_buffer *buf, int size)
{
  char *ptr;
  int total, n;

  n = size / CR_BUFFER_SIZE + 1;
  total = buf->size + n * CR_BUFFER_SIZE;

  DEBUG_PRINT("allocate %d x CR_BUFFER_SIZE, total %d bytes", n, total);

  ptr = (char*)realloc(buf->data, total);
  if (ptr == NULL)
    return -1;

  buf->data = ptr;
  buf->size = total;
  return 0;
}

/* Allocate at least `size' more multibulk storage, keeping content of 
 * previously allocated memory untouched.
 * Returns:
 *   0  on success
 *  -1  on error, i.e. more memory not available */
static int cr_morebulk(cr_multibulk *mb, int size) 
{
  char **cptr;
  int *iptr;
  int total, n;

  n = (size / CR_MULTIBULK_SIZE + 1) * CR_MULTIBULK_SIZE;
  total = mb->size + n;

  DEBUG_PRINT("allocate %d x CR_MULTIBULK_SIZE, total %d (%lu bytes)", 
        n, total, total * ((sizeof(char *)+sizeof(int))));
  cptr = (char**)realloc(mb->bulks, total * sizeof(char *));
  iptr = (int*)realloc(mb->idxs, total * sizeof(int));

  if (cptr == NULL || iptr == NULL)
    return NDPI_CREDIS_ERR_NOMEM;

  mb->bulks = cptr;
  mb->idxs = iptr;
  mb->size = total;
  return 0;
}

/* Splits string `str' on character `token' builds a multi-bulk array from 
 * the items. This function will modify the contents of what `str' points
 * to.
 * Returns:
 *   0  on success
 *  <0  on error, i.e. more memory not available */
static int cr_splitstrtromultibulk(NDPI_REDIS rhnd, char *str, const char token)
{
  int i = 0;

  if (str != NULL) {
    rhnd->reply.multibulk.bulks[i++] = str;
    while ((str = strchr(str, token))) {
      *str++ = '\0';
      if (i >= rhnd->reply.multibulk.size)
        if (cr_morebulk(&(rhnd->reply.multibulk), 1))
          return NDPI_CREDIS_ERR_NOMEM;
      
      rhnd->reply.multibulk.bulks[i++] = str;
    }
  }
  rhnd->reply.multibulk.len = i;  
  return 0;
}

/* Appends a printf style formatted to the end of buffer `buf'. If available
 * memory in buffer is not enough to hold `str' more memory is allocated to 
 * the buffer. 
 * Returns:
 *   0  on success
 *  <0  on error, i.e. more memory not available */
static int cr_appendstrf(cr_buffer *buf, const char *format, ...)
{
  int rc, avail;
  va_list ap;

  avail = buf->size - buf->len;

  va_start(ap, format);
  rc = vsnprintf(buf->data + buf->len, avail, format, ap);
  va_end(ap);

  if (rc < 0)
    return -1;

  if (rc >= avail) {
    if (cr_moremem(buf, rc - avail + 1))
      return NDPI_CREDIS_ERR_NOMEM;

    va_start(ap, format);
    rc = vsnprintf(buf->data + buf->len, buf->size - buf->len, format, ap);
    va_end(ap);
  }
  buf->len += rc;

  return 0;
}

/* Appends a zero-terminated string `str' to the end of buffer `buf'. If 
 * available memory in buffer is not enough to hold `str' more memory is 
 * allocated to the buffer. If `space' is not 0 `str' is padded with a space.
 * Returns:
 *   0  on success
 *  <0  on error, i.e. more memory not available */
static int cr_appendstr(cr_buffer *buf, const char *str, int space)
{
  int avail, len, reqd;

  len = strlen(str);
  avail = buf->size - buf->len;

  /* required memory: len, terminating zero and possibly a space */
  reqd = len + 1;
  if (space)
    reqd++;

  if (reqd > avail)
    if (cr_moremem(buf, reqd - avail + 1))
      return NDPI_CREDIS_ERR_NOMEM;

  if (space)
    buf->data[buf->len++] = ' ';

  memcpy(buf->data + buf->len, str, len);
  buf->len += len;

  buf->data[buf->len] = '\0';

  return 0;
}

/* Appends an array of strings `strv' to the end of buffer `buf', each 
 * separated with a space. If `newline' is not 0 "\r\n" is added last 
 * to buffer.
 * Returns:
 *   0  on success
 *  <0  on error, i.e. more memory not available */
static int cr_appendstrarray(cr_buffer *buf, int strc, const char **strv, int newline)
{
  int rc, i;

  for (i = 0; i < strc; i++) {
    if ((rc = cr_appendstr(buf, strv[i], 1)) != 0)
      return rc;
  }

  if (newline) {
    if ((rc = cr_appendstr(buf, "\r\n", 0)) != 0)
      return rc;
  }

  return 0;
}

/* Helper function for select that waits for `timeout' milliseconds 
 * for `fd' to become readable (`readable' == 1) or writable.
 * Returns:
 *  >0  `fd' became readable or writable
 *   0  timeout 
 *  -1  on error */
int cr_select(int fd, int timeout, int readable)
{
  struct timeval tv;
  fd_set fds;

  tv.tv_sec = timeout/1000;
  tv.tv_usec = (timeout%1000)*1000;
  
  FD_ZERO(&fds);
  FD_SET(fd, &fds);
    
  if (readable == 1)
    return select(fd+1, &fds, NULL, NULL, &tv);    

  return select(fd+1, NULL, &fds, NULL, &tv);
}
#define cr_selectreadable(fd, timeout) cr_select(fd, timeout, 1)
#define cr_selectwritable(fd, timeout) cr_select(fd, timeout, 0)

/* Receives at most `size' bytes from socket `fd' to `buf'. Times out after 
 * `msecs' milliseconds if no data has yet arrived.
 * Returns:
 *  >0  number of read bytes on success
 *   0  server closed connection
 *  -1  on error
 *  -2  on timeout */
static int cr_receivedata(int fd, unsigned int msecs, char *buf, int size)
{
  int rc = cr_selectreadable(fd, msecs);

  if (rc > 0)
    return recv(fd, buf, size, 0);
  else if (rc == 0)
    return -2;
  else
    return -1;  
}

/* Sends `size' bytes from `buf' to socket `fd' and times out after `msecs' 
 * milliseconds if not all data has been sent. 
 * Returns:
 *  >0  number of bytes sent; if less than `size' it means that timeout occurred
 *  -1  on error */
static int cr_senddata(int fd, unsigned int msecs, char *buf, int size)
{
  fd_set fds;
  struct timeval tv;
  int rc, sent=0;
  
  /* NOTE: On Linux, select() modifies timeout to reflect the amount 
   * of time not slept, on other systems it is likely not the same */
  tv.tv_sec = msecs/1000;
  tv.tv_usec = (msecs%1000)*1000;

  while (sent < size) {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    rc = select(fd+1, NULL, &fds, NULL, &tv);

    if (rc > 0) {
      rc = send(fd, buf+sent, size-sent, 0);
      if (rc < 0)
        return -1;
      sent += rc;
    }
    else if (rc == 0) /* timeout */
      break;
    else
      return -1;  
  }

  return sent;
}

/* Buffered read line, returns pointer to zero-terminated string 
 * and length of that string. `start' specifies from which byte
 * to start looking for "\r\n".
 * Returns:
 *  >0  length of string to which pointer `line' refers. `idx' is
 *      an optional pointer for returning start index of line with
 *      respect to buffer.
 *   0  connection to Redis server was closed
 *  -1  on error, i.e. a string is not available */
static int cr_readln(NDPI_REDIS rhnd, int start, char **line, int *idx)
{
  cr_buffer *buf = &(rhnd->buf);
  char *nl;
  int rc, len, avail, more;

  /* do we need more data before we expect to find "\r\n"? */
  if ((more = buf->idx + start + 2 - buf->len) < 0)
    more = 0;
  
  while (more > 0 || 
         (nl = cr_findnl(buf->data + buf->idx + start, buf->len - (buf->idx + start))) == NULL) {
    avail = buf->size - buf->len;
    if (avail < CR_BUFFER_WATERMARK || avail < more) {
      DEBUG_PRINT("available buffer memory is low, get more memory");
      if (cr_moremem(buf, more>0?more:1))
        return NDPI_CREDIS_ERR_NOMEM;

      avail = buf->size - buf->len;
    }

    rc = cr_receivedata(rhnd->fd, rhnd->timeout, buf->data + buf->len, avail);
    if (rc > 0) {
      DEBUG_PRINT("received %d bytes: %s", rc, buf->data + buf->len);
      buf->len += rc;
    }
    else if (rc == 0)
      return 0; /* EOF reached, connection terminated */
    else 
      return -1; /* error */

    /* do we need more data before we expect to find "\r\n"? */
    if ((more = buf->idx + start + 2 - buf->len) < 0)
      more = 0;
  }

  *nl = '\0'; /* zero terminate */

  *line = buf->data + buf->idx;
  if (idx)
    *idx = buf->idx;
  len = nl - *line;
  buf->idx = (nl - buf->data) + 2; /* skip "\r\n" */

  DEBUG_PRINT("size=%d, len=%d, idx=%d, start=%d, line=%s", 
        buf->size, buf->len, buf->idx, start, *line);

  return len;
}

static int cr_receivemultibulk(NDPI_REDIS rhnd, char *line) 
{
  int bnum, blen, i, rc=0, idx;

  bnum = atoi(line);

  if (bnum == -1) {
    rhnd->reply.multibulk.len = 0; /* no data or key didn't exist */
    return 0;
  }
  else if (bnum > rhnd->reply.multibulk.size) {
    DEBUG_PRINT("available multibulk storage is low, get more memory");
    if (cr_morebulk(&(rhnd->reply.multibulk), bnum - rhnd->reply.multibulk.size))
      return NDPI_CREDIS_ERR_NOMEM;
  }

  for (i = 0; bnum > 0 && (rc = cr_readln(rhnd, 0, &line, NULL)) > 0; i++, bnum--) {
    if (*(line++) != CR_BULK)
      return NDPI_CREDIS_ERR_PROTOCOL;
    
    blen = atoi(line);
    if (blen == -1)
      rhnd->reply.multibulk.idxs[i] = -1;
    else {
      if ((rc = cr_readln(rhnd, blen, &line, &idx)) != blen)
        return NDPI_CREDIS_ERR_PROTOCOL;

      rhnd->reply.multibulk.idxs[i] = idx;
    }
  }
  
  if (bnum != 0) {
    DEBUG_PRINT("bnum != 0, bnum=%d, rc=%d", bnum, rc);
    return NDPI_CREDIS_ERR_PROTOCOL;
  }

  rhnd->reply.multibulk.len = i;
  for (i = 0; i < rhnd->reply.multibulk.len; i++) {
    if (rhnd->reply.multibulk.idxs[i] > 0)
      rhnd->reply.multibulk.bulks[i] = rhnd->buf.data + rhnd->reply.multibulk.idxs[i];
    else
      rhnd->reply.multibulk.bulks[i] = NULL;
  }

  return 0;
}

static int cr_receivebulk(NDPI_REDIS rhnd, char *line) 
{
  int blen;

  blen = atoi(line);
  if (blen == -1) {
    rhnd->reply.bulk = NULL; /* key didn't exist */
    return 0;
  }
  if (cr_readln(rhnd, blen, &line, NULL) >= 0) {
    rhnd->reply.bulk = line;
    return 0;
  }

  return NDPI_CREDIS_ERR_PROTOCOL;
}

static int cr_receiveinline(NDPI_REDIS rhnd, char *line) 
{
  rhnd->reply.line = line;
  return 0;
}

static int cr_receiveint(NDPI_REDIS rhnd, char *line) 
{
  rhnd->reply.integer = atoi(line);
  return 0;
}

static int cr_receiveerror(NDPI_REDIS rhnd, char *line) 
{
  rhnd->reply.line = line;
  return NDPI_CREDIS_ERR_PROTOCOL;
}

static int cr_receivereply(NDPI_REDIS rhnd, char recvtype) 
{
  char *line, prefix=0;

  /* reset common send/receive buffer */
  rhnd->buf.len = 0;
  rhnd->buf.idx = 0;

  if (cr_readln(rhnd, 0, &line, NULL) > 0) {
    prefix = *(line++);
 
    if (prefix != recvtype && prefix != CR_ERROR)
      return NDPI_CREDIS_ERR_PROTOCOL;

    switch(prefix) {
    case CR_ERROR:
      return cr_receiveerror(rhnd, line);
    case CR_INLINE:
      return cr_receiveinline(rhnd, line);
    case CR_INT:
      return cr_receiveint(rhnd, line);
    case CR_BULK:
      return cr_receivebulk(rhnd, line);
    case CR_MULTIBULK:
      return cr_receivemultibulk(rhnd, line);
    }   
  }

  return NDPI_CREDIS_ERR_RECV;
}

static void cr_delete(NDPI_REDIS rhnd) 
{
  if (rhnd->reply.multibulk.bulks != NULL)
    free(rhnd->reply.multibulk.bulks);
  if (rhnd->reply.multibulk.idxs != NULL)
    free(rhnd->reply.multibulk.idxs);
  if (rhnd->buf.data != NULL)
    free(rhnd->buf.data);
  if (rhnd->ip != NULL)
    free(rhnd->ip);
  if (rhnd != NULL)
    free(rhnd);
}

NDPI_REDIS cr_new(void) 
{
  NDPI_REDIS rhnd;

  if ((rhnd = (cr_redis*)calloc(sizeof(cr_redis), 1)) == NULL ||
      (rhnd->ip = (char*)malloc(32)) == NULL ||
      (rhnd->buf.data = (char*)malloc(CR_BUFFER_SIZE)) == NULL ||
      (rhnd->reply.multibulk.bulks = (char**)malloc(sizeof(char *)*CR_MULTIBULK_SIZE)) == NULL ||
      (rhnd->reply.multibulk.idxs = (int*)malloc(sizeof(int)*CR_MULTIBULK_SIZE)) == NULL) {
    cr_delete(rhnd);
    return NULL;   
  }

  rhnd->buf.size = CR_BUFFER_SIZE;
  rhnd->reply.multibulk.size = CR_MULTIBULK_SIZE;

  return rhnd;
}

/* Send message that has been prepared in message buffer prior to the call
 * to this function. Wait and receive reply. */
static int cr_sendandreceive(NDPI_REDIS rhnd, char recvtype)
{
  int rc;

  DEBUG_PRINT("Sending message: len=%d, data=%s", rhnd->buf.len, rhnd->buf.data);

  rc = cr_senddata(rhnd->fd, rhnd->timeout, rhnd->buf.data, rhnd->buf.len);

  if (rc != rhnd->buf.len) {
    if (rc < 0)
      return NDPI_CREDIS_ERR_SEND;
    return NDPI_CREDIS_ERR_TIMEOUT;
  }

  return cr_receivereply(rhnd, recvtype);
}

/* Prepare message buffer for sending using a printf()-style formatting. */
__attribute__ ((format(printf,3,4)))
static int cr_sendfandreceive(NDPI_REDIS rhnd, char recvtype, const char *format, ...)
{
  int rc;
  va_list ap;
  cr_buffer *buf = &(rhnd->buf);

  va_start(ap, format);
  rc = vsnprintf(buf->data, buf->size, format, ap);
  va_end(ap);

  if (rc < 0)
    return -1;

  if (rc >= buf->size) {
    DEBUG_PRINT("truncated, get more memory and try again");
    if (cr_moremem(buf, rc - buf->size + 1))
      return NDPI_CREDIS_ERR_NOMEM;

    va_start(ap, format);
    rc = vsnprintf(buf->data, buf->size, format, ap);
    va_end(ap);
  }

  buf->len = rc;

  return cr_sendandreceive(rhnd, recvtype);
}

char * ndpi_credis_errorreply(NDPI_REDIS rhnd)
{
  return rhnd->reply.line;
}

void ndpi_credis_close(NDPI_REDIS rhnd)
{
  if (rhnd) {
    if (rhnd->fd > 0)
      close(rhnd->fd);
#ifdef WIN32
    WSACleanup();
#endif
    cr_delete(rhnd);
  }
}

NDPI_REDIS ndpi_credis_connect(const char *host, int port, int timeout)
{
  int fd, rc, flags, yes = 1, use_he = 0;
  struct sockaddr_in sa;  
  struct hostent *he;
  NDPI_REDIS rhnd;

#ifdef WIN32
  unsigned long addr;
  WSADATA data;
  
  if (WSAStartup(MAKEWORD(2,2), &data) != 0) {
    DEBUG_PRINT("Failed to init Windows Sockets DLL\n");
    return NULL;
  }
#endif

  if ((rhnd = cr_new()) == NULL)
    return NULL;

  if (host == NULL)
    host = "127.0.0.1";
  if (port == 0)
    port = 6379;

#ifdef WIN32
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&yes, sizeof(yes)) == -1 ||
      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&yes, sizeof(yes)) == -1)
    goto error;
#else
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&yes, sizeof(yes)) == -1 ||
      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&yes, sizeof(yes)) == -1)
    goto error;
#endif

  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);

#ifdef WIN32
  /* TODO use getaddrinfo() instead! */
  addr = inet_addr(host);
  if (addr == INADDR_NONE) {
    he = gethostbyname(host);
    use_he = 1;
  }
  else {
    he = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
    use_he = 1;
  }
#else
  if (inet_aton(host, &sa.sin_addr) == 0) {
    he = gethostbyname(host);
    use_he = 1;
  }
#endif

  if (use_he) {
    if (he == NULL)
      goto error;
    memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
  } 

  /* connect with user specified timeout */

  flags = fcntl(fd, F_GETFL);
  if ((rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) < 0) {
    DEBUG_PRINT("Setting socket non-blocking failed with: %d\n", rc);
  }

  if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    if (errno != EINPROGRESS)
      goto error;

    if (cr_selectwritable(fd, timeout) > 0) {
      int err;
      unsigned int len = sizeof(err);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == -1 || err)
        goto error;
    }
    else /* timeout or select error */
      goto error;
  }
  /* else connect completed immediately */

  strcpy(rhnd->ip, inet_ntoa(sa.sin_addr));
  rhnd->port = port;
  rhnd->fd = fd;
  rhnd->timeout = timeout;

  /* We can receive 2 version formats: x.yz and x.y.z, where x.yz was only used prior 
   * first 1.1.0 release(?), e.g. stable releases 1.02 and 1.2.6 */
  if (cr_sendfandreceive(rhnd, CR_BULK, "INFO\r\n") == 0) {
    int items = sscanf(rhnd->reply.bulk,
                       "redis_version:%d.%d.%d\r\n",
                       &(rhnd->version.major),
                       &(rhnd->version.minor),
                       &(rhnd->version.patch));

    if(items == 0)
      items = sscanf(rhnd->reply.bulk,
		     "# Server\r\nredis_version:%d.%d.%d\r\n",
		     &(rhnd->version.major),
		     &(rhnd->version.minor),
		     &(rhnd->version.patch));
    
    if (items < 2)
      goto error;
    if (items == 2) {
      rhnd->version.patch = rhnd->version.minor;
      rhnd->version.minor = 0;
    }
    DEBUG_PRINT("Connected to Redis version: %d.%d.%d\n", 
          rhnd->version.major, rhnd->version.minor, rhnd->version.patch);
  }

  return rhnd;

error:
  if (fd > 0)
    close(fd);
  cr_delete(rhnd);

  return NULL;
}

void ndpi_credis_settimeout(NDPI_REDIS rhnd, int timeout)
{
  rhnd->timeout = timeout;
}

int ndpi_credis_set(NDPI_REDIS rhnd, const char *key, const char *val)
{
#ifdef ORIGINAL
  return cr_sendfandreceive(rhnd, CR_INLINE, "SET %s %zu\r\n%zs\r\n", 
                            key, strlen(val), val);
#else
  /* L.Deri */
  return cr_sendfandreceive(rhnd, CR_INLINE, "SET %s %s\r\n%zu\r\n", 
                            key, val, strlen(val));
#endif
}

int ndpi_credis_get(NDPI_REDIS rhnd, const char *key, char **val)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "GET %s\r\n", key);

  if (rc == 0 && (*val = rhnd->reply.bulk) == NULL)
    return -1;

  return rc;
}

int ndpi_credis_getset(NDPI_REDIS rhnd, const char *key, const char *set_val, char **get_val)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "GETSET %s %zu\r\n%s\r\n", 
                              key, strlen(set_val), set_val);

  if (rc == 0 && (*get_val = rhnd->reply.bulk) == NULL)
    return -1;

  return rc;
}

int ndpi_credis_ping(NDPI_REDIS rhnd) 
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "PING\r\n");
}

int ndpi_credis_auth(NDPI_REDIS rhnd, const char *password)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "AUTH %s\r\n", password);
}

static int cr_multikeybulkcommand(NDPI_REDIS rhnd, const char *cmd, int keyc, 
                                  const char **keyv, char ***valv)
{
  cr_buffer *buf = &(rhnd->buf);
  int rc;

  buf->len = 0;
  if ((rc = cr_appendstr(buf, cmd, 0)) != 0)
    return rc;
  if ((rc = cr_appendstrarray(buf, keyc, keyv, 1)) != 0)
    return rc;
  if ((rc = cr_sendandreceive(rhnd, CR_MULTIBULK)) == 0) {
    *valv = rhnd->reply.multibulk.bulks;
    rc = rhnd->reply.multibulk.len;
  }

  return rc;
}

static int cr_multikeystorecommand(NDPI_REDIS rhnd, const char *cmd, const char *destkey, 
                                   int keyc, const char **keyv)
{
  cr_buffer *buf = &(rhnd->buf);
  int rc;

  buf->len = 0;
  if ((rc = cr_appendstr(buf, cmd, 0)) != 0)
    return rc;
  if ((rc = cr_appendstr(buf, destkey, 1)) != 0)
    return rc;
  if ((rc = cr_appendstrarray(buf, keyc, keyv, 1)) != 0)
    return rc;

  return cr_sendandreceive(rhnd, CR_INLINE);
}

int ndpi_credis_mget(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***valv)
{
  return cr_multikeybulkcommand(rhnd, "MGET", keyc, keyv, valv);
}

int ndpi_credis_setnx(NDPI_REDIS rhnd, const char *key, const char *val)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "SETNX %s %zu\r\n%s\r\n", 
                              key, strlen(val), val);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

static int cr_incr(NDPI_REDIS rhnd, int incr, int decr, const char *key, int *new_val)
{
  int rc = 0;

  if (incr == 1 || decr == 1)
    rc = cr_sendfandreceive(rhnd, CR_INT, "%s %s\r\n", 
                            incr>0?"INCR":"DECR", key);
  else if (incr > 1 || decr > 1)
    rc = cr_sendfandreceive(rhnd, CR_INT, "%s %s %d\r\n", 
                            incr>0?"INCRBY":"DECRBY", key, incr>0?incr:decr);

  if (rc == 0 && new_val != NULL)
    *new_val = rhnd->reply.integer;

  return rc;
}

int ndpi_credis_incr(NDPI_REDIS rhnd, const char *key, int *new_val)
{
  return cr_incr(rhnd, 1, 0, key, new_val);
}

int ndpi_credis_decr(NDPI_REDIS rhnd, const char *key, int *new_val)
{
  return cr_incr(rhnd, 0, 1, key, new_val);
}

int ndpi_credis_incrby(NDPI_REDIS rhnd, const char *key, int incr_val, int *new_val)
{
  return cr_incr(rhnd, incr_val, 0, key, new_val);
}

int ndpi_credis_decrby(NDPI_REDIS rhnd, const char *key, int decr_val, int *new_val)
{
  return cr_incr(rhnd, 0, decr_val, key, new_val);
}

int ndpi_credis_append(NDPI_REDIS rhnd, const char *key, const char *val)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "APPEND %s %zu\r\n%s\r\n", 
                              key, strlen(val), val);
                            
  if (rc == 0)
    rc = rhnd->reply.integer;

  return rc;                            
}

int ndpi_credis_substr(NDPI_REDIS rhnd, const char *key, int start, int end, char **substr)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "SUBSTR %s %d %d\r\n", 
                              key, start, end);

  if (rc == 0 && substr) 
    *substr = rhnd->reply.bulk;

  return rc;                            
}

int ndpi_credis_exists(NDPI_REDIS rhnd, const char *key)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "EXISTS %s\r\n", key);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_del(NDPI_REDIS rhnd, const char *key)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "DEL %s\r\n", key);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_type(NDPI_REDIS rhnd, const char *key)
{
  int rc = cr_sendfandreceive(rhnd, CR_INLINE, "TYPE %s\r\n", key);

  if (rc == 0) {
    char *t = rhnd->reply.line;
    if (!strcmp("string", t))
      rc = NDPI_CREDIS_TYPE_STRING;
    else if (!strcmp("list", t))
      rc = NDPI_CREDIS_TYPE_LIST;
    else if (!strcmp("set", t))
      rc = NDPI_CREDIS_TYPE_SET;
    else
      rc = NDPI_CREDIS_TYPE_NONE;
  }

  return rc;
}

int ndpi_credis_keys(NDPI_REDIS rhnd, const char *pattern, char ***keyv)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "KEYS %s\r\n", pattern);

  if (rc == 0) {
    /* server returns keys as space-separated strings, use multi-bulk 
     * storage to store keys */
    if ((rc = cr_splitstrtromultibulk(rhnd, rhnd->reply.bulk, ' ')) == 0) {
      *keyv = rhnd->reply.multibulk.bulks;
      rc = rhnd->reply.multibulk.len;
    }
  }

  return rc;
}

int ndpi_credis_randomkey(NDPI_REDIS rhnd, char **key)
{
  int rc = cr_sendfandreceive(rhnd, CR_INLINE, "RANDOMKEY\r\n");

  if (rc == 0 && key) 
    *key = rhnd->reply.line;

  return rc;
}

int ndpi_credis_rename(NDPI_REDIS rhnd, const char *key, const char *new_key_name)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "RENAME %s %s\r\n", 
                            key, new_key_name);
}

int ndpi_credis_renamenx(NDPI_REDIS rhnd, const char *key, const char *new_key_name)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "RENAMENX %s %s\r\n", 
                              key, new_key_name);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_dbsize(NDPI_REDIS rhnd)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "DBSIZE\r\n");

  if (rc == 0) 
    rc = rhnd->reply.integer;

  return rc;
}

int ndpi_credis_expire(NDPI_REDIS rhnd, const char *key, int secs)
{ 
  int rc = cr_sendfandreceive(rhnd, CR_INT, "EXPIRE %s %d\r\n", key, secs);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_ttl(NDPI_REDIS rhnd, const char *key)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "TTL %s\r\n", key);

  if (rc == 0)
    rc = rhnd->reply.integer;

  return rc;
}

static int cr_push(NDPI_REDIS rhnd, int left, const char *key, const char *val)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "%s %s %s\r\n%zu\r\n", 
                            left==1?"LPUSH":"RPUSH", key, val, strlen(val));
}

static int cr_rpushx(NDPI_REDIS rhnd, const char *key, const char *val)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "%s %s %s\r\n%zu\r\n", 
                            "RPUSHX", key, val, strlen(val));
}

int ndpi_credis_rpush(NDPI_REDIS rhnd, const char *key, const char *val)
{
  return cr_push(rhnd, 0, key, val);
}

/* ntop */
int ndpi_credis_rpushx(NDPI_REDIS rhnd, const char *key, const char *val)
{
  return cr_rpushx(rhnd, key, val);
}

int ndpi_credis_lpush(NDPI_REDIS rhnd, const char *key, const char *val)
{
  return cr_push(rhnd, 1, key, val);
}

int ndpi_credis_llen(NDPI_REDIS rhnd, const char *key)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "LLEN %s\r\n", key);

  if (rc == 0) 
    rc = rhnd->reply.integer;

  return rc;
}

int ndpi_credis_lrange(NDPI_REDIS rhnd, const char *key, int start, int end, char ***valv)
{
  int rc;

  if ((rc = cr_sendfandreceive(rhnd, CR_MULTIBULK, "LRANGE %s %d %d\r\n", 
                               key, start, end)) == 0) {
    *valv = rhnd->reply.multibulk.bulks;
    rc = rhnd->reply.multibulk.len;
  }

  return rc;
}

int ndpi_credis_ltrim(NDPI_REDIS rhnd, const char *key, int start, int end)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "LTRIM %s %d %d\r\n", 
                            key, start, end);
}

int ndpi_credis_lindex(NDPI_REDIS rhnd, const char *key, int index, char **val)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "LINDEX %s %d\r\n", key, index);

  if (rc == 0 && (*val = rhnd->reply.bulk) == NULL)
    return -1;

  return rc;
}

int ndpi_credis_lset(NDPI_REDIS rhnd, const char *key, int index, const char *val)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "LSET %s %d %zu\r\n%s\r\n", 
                            key, index, strlen(val), val);
}

int ndpi_credis_lrem(NDPI_REDIS rhnd, const char *key, int count, const char *val)
{
  return cr_sendfandreceive(rhnd, CR_INT, "LREM %s %d %zu\r\n%s\r\n", 
                            key, count, strlen(val), val);
}

static int cr_pop(NDPI_REDIS rhnd, int left, const char *key, char **val)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "%s %s\r\n", 
                              left==1?"LPOP":"RPOP", key);

  if (rc == 0 && (*val = rhnd->reply.bulk) == NULL)
    return -1;

  return rc;
}

int ndpi_credis_lpop(NDPI_REDIS rhnd, const char *key, char **val)
{
  return cr_pop(rhnd, 1, key, val);
}

int ndpi_credis_rpop(NDPI_REDIS rhnd, const char *key, char **val)
{
  return cr_pop(rhnd, 0, key, val);
}

int ndpi_credis_select(NDPI_REDIS rhnd, int index)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "SELECT %d\r\n", index);
}

int ndpi_credis_move(NDPI_REDIS rhnd, const char *key, int index)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "MOVE %s %d\r\n", key, index);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_flushdb(NDPI_REDIS rhnd)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "FLUSHDB\r\n");
}

int ndpi_credis_flushall(NDPI_REDIS rhnd)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "FLUSHALL\r\n");
}

int ndpi_credis_sort(NDPI_REDIS rhnd, const char *query, char ***elementv)
{
  int rc;

  if ((rc = cr_sendfandreceive(rhnd, CR_MULTIBULK, "SORT %s\r\n", query)) == 0) {
    *elementv = rhnd->reply.multibulk.bulks;
    rc = rhnd->reply.multibulk.len;
  }

  return rc;
}

int ndpi_credis_save(NDPI_REDIS rhnd)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "SAVE\r\n");
}

int ndpi_credis_bgsave(NDPI_REDIS rhnd)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "BGSAVE\r\n");
}

int ndpi_credis_lastsave(NDPI_REDIS rhnd)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "LASTSAVE\r\n");

  if (rc == 0)
    rc = rhnd->reply.integer;

  return rc;
}

int ndpi_credis_shutdown(NDPI_REDIS rhnd)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "SHUTDOWN\r\n");
}

int ndpi_credis_bgrewriteaof(NDPI_REDIS rhnd)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "BGREWRITEAOF\r\n");
}

/* Parse Redis `info' string for a particular `fld', storing its value to 
 * `storage' according to `format'.
 */
void cr_parseinfo(const char *info, const char *fld, const char *format, void *storage)
{
  if(info) {
    char *str = (char*)strstr(info, (char*)fld);
    if (str) {
      str += strlen(fld) + 1; /* also skip the ':' */
      sscanf(str, format, storage); 
    }
  }
}

int ndpi_credis_info(NDPI_REDIS rhnd, NDPI_REDIS_INFO *info)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "INFO\r\n");

  if (rc == 0) {
    char role;
    memset(info, 0, sizeof(NDPI_REDIS_INFO));
    cr_parseinfo(rhnd->reply.bulk, "redis_version", "%"CR_VERSION_STRING_SIZE_STR"s\r\n", &(info->redis_version));
    cr_parseinfo(rhnd->reply.bulk, "arch_bits", "%d", &(info->arch_bits));
    cr_parseinfo(rhnd->reply.bulk, "multiplexing_api", "%"CR_MULTIPLEXING_API_SIZE_STR"s\r\n", &(info->multiplexing_api));
    cr_parseinfo(rhnd->reply.bulk, "process_id", "%ld", &(info->process_id));
    cr_parseinfo(rhnd->reply.bulk, "uptime_in_seconds", "%ld", &(info->uptime_in_seconds));
    cr_parseinfo(rhnd->reply.bulk, "uptime_in_days", "%ld", &(info->uptime_in_days));
    cr_parseinfo(rhnd->reply.bulk, "connected_clients", "%d", &(info->connected_clients));
    cr_parseinfo(rhnd->reply.bulk, "connected_slaves", "%d", &(info->connected_slaves));
    cr_parseinfo(rhnd->reply.bulk, "blocked_clients", "%d", &(info->blocked_clients));
    cr_parseinfo(rhnd->reply.bulk, "used_memory", "%zu", &(info->used_memory));
    cr_parseinfo(rhnd->reply.bulk, "used_memory_human", "%"CR_USED_MEMORY_HUMAN_SIZE_STR"s", &(info->used_memory_human));
    cr_parseinfo(rhnd->reply.bulk, "changes_since_last_save", "%lld", &(info->changes_since_last_save));
    cr_parseinfo(rhnd->reply.bulk, "bgsave_in_progress", "%d", &(info->bgsave_in_progress));
    cr_parseinfo(rhnd->reply.bulk, "last_save_time", "%ld", &(info->last_save_time));
    cr_parseinfo(rhnd->reply.bulk, "bgrewriteaof_in_progress", "%d", &(info->bgrewriteaof_in_progress));
    cr_parseinfo(rhnd->reply.bulk, "total_connections_received", "%lld", &(info->total_connections_received));
    cr_parseinfo(rhnd->reply.bulk, "total_commands_processed", "%lld", &(info->total_commands_processed));
    cr_parseinfo(rhnd->reply.bulk, "expired_keys", "%lld", &(info->expired_keys));
    cr_parseinfo(rhnd->reply.bulk, "hash_max_zipmap_entries", "%zu", &(info->hash_max_zipmap_entries));
    cr_parseinfo(rhnd->reply.bulk, "hash_max_zipmap_value", "%zu", &(info->hash_max_zipmap_value));
    cr_parseinfo(rhnd->reply.bulk, "pubsub_channels", "%ld", &(info->pubsub_channels));
    cr_parseinfo(rhnd->reply.bulk, "pubsub_patterns", "%u", &(info->pubsub_patterns));
    cr_parseinfo(rhnd->reply.bulk, "vm_enabled", "%d", &(info->vm_enabled));
    cr_parseinfo(rhnd->reply.bulk, "role", "%c", &role);

    info->role = ((role=='m')?NDPI_CREDIS_SERVER_MASTER:NDPI_CREDIS_SERVER_SLAVE);
  }
  
  return rc;
}

int ndpi_credis_monitor(NDPI_REDIS rhnd)
{
  return cr_sendfandreceive(rhnd, CR_INLINE, "MONITOR\r\n");
}

int ndpi_credis_slaveof(NDPI_REDIS rhnd, const char *host, int port)
{
  if (host == NULL || port == 0)
    return cr_sendfandreceive(rhnd, CR_INLINE, "SLAVEOF no one\r\n");
  else
    return cr_sendfandreceive(rhnd, CR_INLINE, "SLAVEOF %s %d\r\n", host, port);
}

static int cr_setaddrem(NDPI_REDIS rhnd, const char *cmd, const char *key, const char *member)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "%s %s %zu\r\n%s\r\n", 
                              cmd, key, strlen(member), member);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_sadd(NDPI_REDIS rhnd, const char *key, const char *member)
{
  return cr_setaddrem(rhnd, "SADD", key, member);
}

int ndpi_credis_srem(NDPI_REDIS rhnd, const char *key, const char *member)
{
  return cr_setaddrem(rhnd, "SREM", key, member);
}

int ndpi_credis_spop(NDPI_REDIS rhnd, const char *key, char **member)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "SPOP %s\r\n", key);

  if (rc == 0 && (*member = rhnd->reply.bulk) == NULL)
    rc = -1;

  return rc;
}

int ndpi_credis_smove(NDPI_REDIS rhnd, const char *sourcekey, const char *destkey, 
                 const char *member)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "SMOVE %s %s %s\r\n", 
                              sourcekey, destkey, member);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_scard(NDPI_REDIS rhnd, const char *key) 
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "SCARD %s\r\n", key);

  if (rc == 0)
    rc = rhnd->reply.integer;

  return rc;
}

int ndpi_credis_sinter(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***members)
{
  return cr_multikeybulkcommand(rhnd, "SINTER", keyc, keyv, members);
}

int ndpi_credis_sunion(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***members)
{
  return cr_multikeybulkcommand(rhnd, "SUNION", keyc, keyv, members);
}

int ndpi_credis_sdiff(NDPI_REDIS rhnd, int keyc, const char **keyv, char ***members)
{
  return cr_multikeybulkcommand(rhnd, "SDIFF", keyc, keyv, members);
}

int ndpi_credis_sinterstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv)
{
  return cr_multikeystorecommand(rhnd, "SINTERSTORE", destkey, keyc, keyv);
}

int ndpi_credis_sunionstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv)
{
  return cr_multikeystorecommand(rhnd, "SUNIONSTORE", destkey, keyc, keyv);
}

int ndpi_credis_sdiffstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv)
{
  return cr_multikeystorecommand(rhnd, "SDIFFSTORE", destkey, keyc, keyv);
}

int ndpi_credis_sismember(NDPI_REDIS rhnd, const char *key, const char *member)
{
  return cr_setaddrem(rhnd, "SISMEMBER", key, member);
}

int ndpi_credis_smembers(NDPI_REDIS rhnd, const char *key, char ***members)
{
  return cr_multikeybulkcommand(rhnd, "SMEMBERS", 1, &key, members);
}

int ndpi_credis_zadd(NDPI_REDIS rhnd, const char *key, double score, const char *member)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "ZADD %s %f %zu\r\n%s\r\n", 
                              key, score, strlen(member), member);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

int ndpi_credis_zrem(NDPI_REDIS rhnd, const char *key, const char *member)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "ZREM %s %zu\r\n%s\r\n", 
                              key, strlen(member), member);

  if (rc == 0 && rhnd->reply.integer == 0)
    rc = -1;

  return rc;
}

/* TODO what does Redis return if member is not member of set? */
int ndpi_credis_zincrby(NDPI_REDIS rhnd, const char *key, double incr_score, const char *member, double *new_score)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "ZINCRBY %s %f %zu\r\n%s\r\n", 
                              key, incr_score, strlen(member), member);

  if (rc == 0 && new_score)
    *new_score = strtod(rhnd->reply.bulk, NULL);

  return rc;
}

/* TODO what does Redis return if member is not member of set? */
static int cr_zrank(NDPI_REDIS rhnd, int reverse, const char *key, const char *member)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "%s %s %zu\r\n%s\r\n", 
                              reverse==1?"ZREVRANK":"ZRANK", key, strlen(member), member);

  if (rc == 0)
    rc = atoi(rhnd->reply.bulk);

  return rc;
}

int ndpi_credis_zrank(NDPI_REDIS rhnd, const char *key, const char *member)
{
  return cr_zrank(rhnd, 0, key, member);
}

int ndpi_credis_zrevrank(NDPI_REDIS rhnd, const char *key, const char *member)
{
  return cr_zrank(rhnd, 1, key, member);
}

int cr_zrange(NDPI_REDIS rhnd, int reverse, const char *key, int start, int end, char ***elementv)
{
  int rc = cr_sendfandreceive(rhnd, CR_MULTIBULK, "%s %s %d %d\r\n",
                              reverse==1?"ZREVRANGE":"ZRANGE", key, start, end);

  if (rc == 0) {
    *elementv = rhnd->reply.multibulk.bulks;
    rc = rhnd->reply.multibulk.len;
  }

  return rc;
}

int ndpi_credis_zrange(NDPI_REDIS rhnd, const char *key, int start, int end, char ***elementv)
{
  return cr_zrange(rhnd, 0, key, start, end, elementv);
}

int ndpi_credis_zrevrange(NDPI_REDIS rhnd, const char *key, int start, int end, char ***elementv)
{
  return cr_zrange(rhnd, 1, key, start, end, elementv);
}

int ndpi_credis_zcard(NDPI_REDIS rhnd, const char *key)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "ZCARD %s\r\n", key);

  if (rc == 0) {
    if (rhnd->reply.integer == 0)
      rc = -1;
    else
      rc = rhnd->reply.integer;
  }

  return rc;
}

int ndpi_credis_zscore(NDPI_REDIS rhnd, const char *key, const char *member, double *score)
{
  int rc = cr_sendfandreceive(rhnd, CR_BULK, "ZSCORE %s %zu\r\n%s\r\n", 
                              key, strlen(member), member);

  if (rc == 0) {
    if (!rhnd->reply.bulk)
      rc = -1;
    else if (score)
      *score = strtod(rhnd->reply.bulk, NULL);
  }

  return rc;
}

int ndpi_credis_zremrangebyscore(NDPI_REDIS rhnd, const char *key, double min, double max)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "ZREMRANGEBYSCORE %s %f %f\r\n", 
                              key, min, max);

  if (rc == 0)
    rc = rhnd->reply.integer;

  return rc;
}

int ndpi_credis_zremrangebyrank(NDPI_REDIS rhnd, const char *key, int start, int end)
{
  int rc = cr_sendfandreceive(rhnd, CR_INT, "ZREMRANGEBYRANK %s %d %d\r\n", 
                              key, start, end);

  if (rc == 0)
    rc = rhnd->reply.integer;

  return rc;
}

/* TODO add writev() support instead and push strings to send onto a vector of
 * strings to send instead... */
static int cr_zstore(NDPI_REDIS rhnd, int inter, const char *destkey, int keyc, const char **keyv, 
                     const int *weightv, NDPI_REDIS_AGGREGATE aggregate)
{
  cr_buffer *buf = &(rhnd->buf);
  int rc, i;

  buf->len = 0;
  
  if ((rc = cr_appendstrf(buf, "%s %s %d ", inter?"ZINTERSTORE":"ZUNIONSTORE", destkey, keyc)) != 0)
    return rc;
  if ((rc = cr_appendstrarray(buf, keyc, keyv, 0)) != 0)
    return rc;
  if (weightv != NULL)
    for (i = 0; i < keyc; i++)
      if ((rc = cr_appendstrf(buf, " %d", weightv[i])) != 0)
        return rc;

  switch (aggregate) {
  case NDPI_SUM: 
    rc = cr_appendstr(buf, "AGGREGATE SUM", 0);
    break;
  case NDPI_MIN:
    rc = cr_appendstr(buf, "AGGREGATE MIN", 0);
    break;
  case NDPI_MAX:
    rc = cr_appendstr(buf, "AGGREGATE MAX", 0);
    break;
  case NDPI_NONE:
    ; /* avoiding compiler warning */
  }
  if (rc != 0)
    return rc;

  if ((rc = cr_appendstr(buf, "\r\n", 0)) != 0)
    return rc;

  if ((rc = cr_sendandreceive(rhnd, CR_INT)) == 0) 
    rc = rhnd->reply.integer;

  return rc;
}

int ndpi_credis_zinterstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv, 
                       const int *weightv, NDPI_REDIS_AGGREGATE aggregate)
{
  return cr_zstore(rhnd, 1, destkey, keyc, keyv, weightv, aggregate);
}

int ndpi_credis_zunionstore(NDPI_REDIS rhnd, const char *destkey, int keyc, const char **keyv, 
                       const int *weightv, NDPI_REDIS_AGGREGATE aggregate)
{
  return cr_zstore(rhnd, 0, destkey, keyc, keyv, weightv, aggregate);
}
