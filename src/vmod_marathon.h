/*
The MIT License (MIT)

Copyright (c) 2017 Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#define MARATHON_SSE_PATH "/v2/events?event_type=status_update_event"
#define MARATHON_APP_PATH "/v2/apps"
#define SSE_EVENT_SIZE_MAX 64
#define SSE_DATA_SIZE_MAX 4096
#define CURL_BUF_SIZE_MAX 65536 // 64kB

#define IPBUFSIZ (VTCP_ADDRBUFSIZE + VTCP_PORTBUFSIZE + 2)

#define MARATHON_LOG(ctx, level, message, ...) \
    do { \
        const struct vrt_ctx *_ctx = ctx; \
        \
        char *_buffer; \
        if (level == LOG_ERR) { \
            assert(asprintf( \
                &_buffer, \
                "[MARATHON][%s] %s", __func__, message) > 0); \
        } else { \
            assert(asprintf( \
                &_buffer, \
                "[MARATHON] %s", message) > 0); \
        } \
        \
        syslog(level, _buffer, ##__VA_ARGS__); \
        \
        unsigned _tag; \
        if (level == LOG_ERR) { \
            _tag = SLT_VCL_Error; \
        } else { \
            _tag = SLT_VCL_Log; \
        } \
        if ((_ctx != NULL) && (_ctx->vsl != NULL)) { \
            VSLb(_ctx->vsl, _tag, _buffer, ##__VA_ARGS__); \
        } else { \
            VSL(_tag, 0, _buffer, ##__VA_ARGS__); \
        } \
        \
        free(_buffer); \
    } while (0)

#define MARATHON_LOG_ERROR(ctx, message, ...) \
    MARATHON_LOG(ctx, LOG_ERR, message, ##__VA_ARGS__)
#define MARATHON_LOG_WARNING(ctx, message, ...) \
    MARATHON_LOG(ctx, LOG_WARNING, message, ##__VA_ARGS__)
#define MARATHON_LOG_INFO(ctx, message, ...) \
    MARATHON_LOG(ctx, LOG_INFO, message, ##__VA_ARGS__)

struct VSC_C_lck *app_lck = NULL;
struct VSC_C_lck *queue_lck = NULL;

struct marathon_backend {
  unsigned int magic;
  #define VMOD_MARATHON_BACKEND_MAGIC 0x8476ab2f
  double time_added;
  struct director *dir;
  char *host_str;
  char *port_str;
  VTAILQ_ENTRY(marathon_backend) next;
};

struct marathon_application {
  unsigned int magic;
  #define VMOD_MARATHON_APPLICATION_MAGIC 0x8476ab3f
  struct lock mtx;
  char *id;
  unsigned int port_index;
  double last_update;
  const struct vrt_backend_probe	*probe;
  struct marathon_backend *curbe;
  VRT_BACKEND_FIELDS();
  VTAILQ_HEAD(,marathon_backend) belist;
  VTAILQ_ENTRY(marathon_application) next;
};

struct vmod_marathon_server {
  unsigned int magic;
  #define VMOD_MARATHON_SERVER_MAGIC 0x8476ab4f
  char                              *marathon_endpoint;
  VRT_CTX;
  char                              *vcl_name;
  struct vcl                        *vcl;
  unsigned int                      active;
  pthread_t                         sse_th;
  pthread_t                         update_th;
  pthread_cond_t                    update_cond;
  struct lock                       queue_mtx;
  VTAILQ_ENTRY(vmod_marathon_server) next;
  VTAILQ_HEAD(,marathon_application) app_list;
  VTAILQ_HEAD(,marathon_application) update_queue;
};

struct curl_recvbuf {
  size_t len;  
  char data[CURL_BUF_SIZE_MAX];
};

struct sse_cb_ctx {
  unsigned int magic;
  #define SSE_CB_CTX_MAGIC 0x8476ab5f
  struct curl_recvbuf *buf;
  struct vmod_marathon_server *srv;
};

VTAILQ_HEAD(vmod_marathon_head, vmod_marathon_server) objects;
extern struct vmod_marathon_head objects;