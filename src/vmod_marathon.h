#define MARATHON_SSE_PATH "/v2/events?event_type=status_update_event&event_type=health_status_changed_event"
#define MARATHON_APP_PATH "/v2/apps"
#define SSE_EVENT_SIZE_MAX 64
#define SSE_DATA_SIZE_MAX 4096
#define CURL_BUF_SIZE_MAX 8388608 // 8MiB.
#define SSE_PING_TIMEOUT  30

#define IPBUFSIZ (VTCP_ADDRBUFSIZE + VTCP_PORTBUFSIZE + 2)

unsigned int log_debug;

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

#define MARATHON_LOG_DEBUG(ctx, message, ...) \
    if (log_debug) {\
    MARATHON_LOG(ctx, LOG_INFO, message, ##__VA_ARGS__); \
    }

struct marathon_backend_config {
  VRT_BACKEND_FIELDS();
  const struct vrt_backend_probe	*probe;
  unsigned int port_index;

};

struct marathon_backend {
  unsigned int magic;
  #define VMOD_MARATHON_BACKEND_MAGIC 0x8476ab2f
  double time_added;
  struct marathon_backend_config config;
  struct director *dir;
  char *task_id;
  char *vcl_name;
  char *ipv4_addr;
  char *ipv6_addr;
  char *port;
  VTAILQ_ENTRY(marathon_backend) next;
};

VTAILQ_HEAD(marathon_backend_head, marathon_backend);

struct marathon_application_label {
    #define VMOD_MARATHON_APPLICATION_LABEL_MAGIC 0x8506ab9f
    unsigned int magic;
    char *key;
    char *val;
    size_t key_len;
    size_t val_len;
    VTAILQ_ENTRY(marathon_application_label) next;
};


VTAILQ_HEAD(marathon_application_label_head, marathon_application_label);

struct marathon_application {
  unsigned int magic;
  double last_update;
  #define VMOD_MARATHON_APPLICATION_MAGIC 0x8476ab3f
  char *id;
  size_t id_len;

  char *marathon_app_endpoint;

  struct marathon_backend_config backend_config;
  struct marathon_backend *curbe;
  struct director dir;
  VRT_BACKEND_FIELDS();
  struct marathon_backend_head belist;
  struct marathon_application_label_head labels;
  unsigned int has_healthchecks;
  
  struct lock mtx;
  VTAILQ_ENTRY(marathon_application) next;
};

VTAILQ_HEAD(marathon_application_head, marathon_application);

struct marathon_update_queue_item {
  unsigned int magic;
  #define MARATHON_UPDATE_QUEUE_ITEM_MAGIC 0x8476ab7f
  struct marathon_application *app;
  VTAILQ_ENTRY(marathon_update_queue_item) next;
};

VTAILQ_HEAD(marathon_update_queue, marathon_update_queue_item);

struct vmod_marathon_server {
  unsigned int magic;
  #define VMOD_MARATHON_SERVER_MAGIC 0x8476ab4f
  char                              *marathon_app_endpoint;
  char                              *marathon_sse_endpoint;
  VRT_CTX;
  char                              *vcl_name;
  struct vcl                        *vcl;
  unsigned int                      active;
  pthread_t                         sse_th;
  pthread_t                         update_th;
  pthread_cond_t                    update_cond;
  struct lock                       queue_mtx;

  VTAILQ_ENTRY(vmod_marathon_server) next;
  struct marathon_application_head app_list;
  struct marathon_update_queue update_queue;
  struct marathon_backend_config default_backend_config;
};

struct curl_recvbuf {
  unsigned int magic;
  #define CURL_RECVBUF_MAGIC 0x8476ab8f
  #define CURL_RECVBUF_INITIAL_ALLOC_SIZE 16384
  size_t size;
  size_t data_len;
  char *data;
};

struct sse_cb_ctx {
  unsigned int magic;
  #define SSE_CB_CTX_MAGIC 0x8476ab5f
  struct curl_recvbuf *buf;
  struct vmod_marathon_server *srv;
  double last_recv_time;
};

VTAILQ_HEAD(vmod_marathon_head, vmod_marathon_server) objects;
extern struct vmod_marathon_head objects;
