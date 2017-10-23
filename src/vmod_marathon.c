#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>

#include <curl/curl.h>
#include <yajl/yajl_tree.h>

#include "config.h"
#include "vcl.h"
#include "vtcp.h"
#include "vrt.h"
#include "vsa.h"
#include "vtim.h"
#include "cache/cache.h"
#include "cache/cache_director.h"

#include "vtim.h"
#include "vcc_marathon_if.h"

#include "vmod_marathon.h"

struct vmod_marathon_head objects = VTAILQ_HEAD_INITIALIZER(objects);

/*
* Initialize curl_recvbuffer.
*/
static void 
init_curl_buffer(struct curl_recvbuf *buf)
{
  INIT_OBJ(buf, CURL_RECVBUF_MAGIC);
  buf->data = (char*)malloc(CURL_RECVBUF_INITIAL_ALLOC_SIZE * sizeof(char));
  AN(buf->data);
  buf->size = CURL_RECVBUF_INITIAL_ALLOC_SIZE;
  buf->data_len = 0;
  buf->data[0] = '\0';
}

/*
* Free curl_recvbuffer.
*/
static void
free_curl_buffer(struct curl_recvbuf *buf) {
  buf->size = 0;
  buf->data_len = 0;
  free(buf->data);
  buf->data = NULL;
}

/*
* Curl write callback func used in curl_fetch().
*/
static size_t 
curl_fetch_cb(char *ptr, size_t size, size_t nmemb, void *userdata) 
{
  size_t recv_len, req_alloc;
  struct curl_recvbuf* buf = userdata;

  CAST_OBJ_NOTNULL(buf, userdata, CURL_RECVBUF_MAGIC);

  recv_len = (size * nmemb);
  req_alloc = buf->data_len + recv_len + 1;

  if (req_alloc > CURL_BUF_SIZE_MAX) {
    MARATHON_LOG_WARNING(NULL, "Buffer exhaustion while fetching data from Marathon. Buffer size was %d.", req_alloc);
    buf->data_len = 0;
    buf->data[0] = '\0';
    return recv_len;
  }

  if (buf->size < req_alloc) {
    buf->data = (char*)realloc(buf->data, req_alloc);
    AN(buf->data);
    buf->size = req_alloc;
  }

  memcpy(buf->data+buf->data_len, ptr, recv_len);

  buf->data_len += recv_len;
  buf->data[buf->data_len] = '\0';

  return recv_len;
}

/*
* Fetch URL using libcurl.
*/
static CURLcode 
curl_fetch(struct curl_recvbuf *buf, const char* url) 
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, buf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_fetch_cb);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    return res;
  }

  curl_easy_cleanup(curl);
  return res;
}

/* 
* Fill suckaddr struct from hoststr, portstr and family.
*/
static struct suckaddr *
get_suckaddr(VCL_STRING host, VCL_STRING port, int family)
{
  struct addrinfo hints, *res = NULL;
  struct suckaddr *sa = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = family;

  if (getaddrinfo(host, port, &hints, &res) != 0)
    return NULL;

  if (res->ai_next != NULL)
    return NULL;

  sa = VSA_Malloc(res->ai_addr, res->ai_addrlen);
  AN(sa);
  assert(VSA_Sane(sa));
  assert(VSA_Get_Proto(sa) == family);

  freeaddrinfo(res);
  return sa;
}

/*
* Get addr:port as string from suckaddr struct.
*/
static void
get_addrname(char *addr, struct suckaddr *sa)
{
  char a[VTCP_ADDRBUFSIZE], p[VTCP_PORTBUFSIZE];

  VTCP_name(sa, a, sizeof(a), p, sizeof(p));
  snprintf(addr, IPBUFSIZ, "%s:%s", a, p);
}

/*
* Free all backends assigned to a mararhon_application.
*/
static void 
free_be_list(struct vmod_marathon_server *srv, struct marathon_application *app)
{
  struct marathon_backend *mbe = NULL, *mben = NULL;
  struct vrt_ctx ctx;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);

  INIT_OBJ(&ctx, VRT_CTX_MAGIC);
  ctx.vcl = srv->vcl;
  ctx.vsl = NULL;

  Lck_Lock(&app->mtx);

  VTAILQ_FOREACH_SAFE(mbe, &app->belist, next, mben) {
  free(mbe->vcl_name);
  free(mbe->ipv4_addr);
  free(mbe->ipv6_addr);
  free(mbe->port);
  VRT_delete_backend(&ctx, &mbe->dir);
  VTAILQ_REMOVE(&app->belist, mbe, next);
  FREE_OBJ(mbe);
  AZ(mbe);
}

  VTAILQ_INIT(&app->belist);

  app->curbe = NULL;
  Lck_Unlock(&app->mtx);
}

/*
* Free all labels assigned to a marathon_application.
*/
static void 
free_label_list(struct marathon_application *app) 
{
  struct marathon_application_label *mlabel = NULL, *mlabel_next = NULL;

  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);

  Lck_Lock(&app->mtx);

  VTAILQ_FOREACH_SAFE(mlabel, &app->labels, next, mlabel_next) {
    free(mlabel->key);
    free(mlabel->val);
    VTAILQ_REMOVE(&app->labels, mlabel, next);
    FREE_OBJ(mlabel);
    AZ(mlabel);
  }

  VTAILQ_INIT(&app->labels);

  Lck_Unlock(&app->mtx);
}

/*
* Get marathon_application from ID.
* Returns NULL if not found.
*/
static struct marathon_application* 
marathon_get_app(struct vmod_marathon_server *srv, const char *id)
{
  struct marathon_application *obj = NULL;
  size_t id_len;

  if (id == NULL)
    return NULL;

  id_len = strlen(id);

  VTAILQ_FOREACH(obj, &srv->app_list, next) {
    CHECK_OBJ_NOTNULL(obj, VMOD_MARATHON_APPLICATION_MAGIC);
    if (obj->id_len == id_len) {
      if (memcmp(id, obj->id, id_len) == 0) {
        return obj;
      }
    } 
  }

  return NULL;
}

/*

* Get marathon_application from label.
* If multiple applications have the matching label the first match will be returned.
* Returns NULL if not found.
*/
static struct marathon_application*
marathon_get_app_by_label(struct vmod_marathon_server* srv, const char *key, const char *val)
{
  struct marathon_application *app = NULL;
  struct marathon_application_label *label = NULL;
  size_t key_len, val_len;

  if (key == NULL || val == NULL)
    return 0;

  key_len = strlen(key);
  val_len = strlen(val);

  VTAILQ_FOREACH(app, &srv->app_list, next) {
    CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);

    if (!VTAILQ_EMPTY(&app->labels)) {
      VTAILQ_FOREACH(label, &app->labels, next) {
        CHECK_OBJ_NOTNULL(label, VMOD_MARATHON_APPLICATION_LABEL_MAGIC);
        if (label->key_len == key_len && label->val_len == val_len) {
          if (memcmp(label->key, key, label->key_len) == 0 && memcmp(label->val, val, label->val_len) == 0) {
            return app;
          }
        }
      }
    }
  }

  return NULL;
}

/*
 Round-robin director resolver function.
*/
static const struct director * __match_proto__(vdi_resolve_f)
marathon_resolve(const struct director *dir, struct worker *wrk,
    struct busyobj *bo)
{
  struct marathon_application *app = NULL;

  (void)wrk;
  (void)bo;

  CAST_OBJ_NOTNULL(app, dir->priv, VMOD_MARATHON_APPLICATION_MAGIC);

  Lck_Lock(&app->mtx);
  if (VTAILQ_EMPTY(&app->belist)) {
    MARATHON_LOG_INFO(NULL, "APP %s: belist is empty", app->id);
    Lck_Unlock(&app->mtx);
    return NULL;
  }

  // Round robin the application backend list.
  if (app->curbe == NULL) {
    app->curbe = VTAILQ_FIRST(&app->belist);
  } else {
    app->curbe = VTAILQ_NEXT(app->curbe, next);
    if (app->curbe == NULL) app->curbe = VTAILQ_FIRST(&app->belist);
  }

  CHECK_OBJ_NOTNULL(app->curbe, VMOD_MARATHON_BACKEND_MAGIC);
  CHECK_OBJ_NOTNULL(app->curbe->dir, DIRECTOR_MAGIC);

  Lck_Unlock(&app->mtx);
  return app->curbe->dir;
}

static unsigned __match_proto__(vdi_healthy_f)
marathon_healthy(const struct director *dir, const struct busyobj *bo,
                 double *changed)
{
  return 1;
}

/*
* Add backend to marathon_application.
*/
static void 
add_backend(struct vmod_marathon_server *srv, struct marathon_application *app,
            const char *host, const char *port)
{
  struct vrt_backend be;
  struct marathon_backend *mbe = NULL;
  struct director *dir = NULL;
  struct suckaddr *sa4 = NULL, *sa6 = NULL;
  char ipv4_addr[IPBUFSIZ] = "", ipv6_addr[IPBUFSIZ] = "";
  struct vrt_ctx ctx;
  struct vsb *vsb;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);
  AN(host);
  AN(port);

  INIT_OBJ(&ctx, VRT_CTX_MAGIC);
  ctx.vcl = srv->vcl;

  sa4 = get_suckaddr(host, port, AF_INET);
  sa6 = get_suckaddr(host, port, AF_INET6);

  if (sa4 != NULL)
    get_addrname(ipv4_addr, sa4);
  if (sa6 != NULL)
    get_addrname(ipv6_addr, sa6);

  ALLOC_OBJ(mbe, VMOD_MARATHON_BACKEND_MAGIC);
  AN(mbe);

  mbe->ipv4_addr = strdup(ipv4_addr);
  mbe->ipv6_addr = strdup(ipv6_addr);
  mbe->port = strdup(port);

  memset(&be, 0, sizeof(struct vrt_backend));
  INIT_OBJ(&be, VRT_BACKEND_MAGIC);

  vsb = VSB_new_auto();
  AN(vsb);

  VSB_printf(vsb, "%s-%s:%s", app->id, host, port);
  AZ(VSB_finish(vsb));

  mbe->vcl_name = strdup(VSB_data(vsb));
  VSB_delete(vsb);

  be.vcl_name = mbe->vcl_name;
  be.ipv4_suckaddr = sa4;
  be.ipv6_suckaddr = sa6;
  be.ipv4_addr = mbe->ipv4_addr;
  be.ipv6_addr = mbe->ipv6_addr;
  be.port = mbe->port;
  be.probe = app->backend_config.probe;
  be.hosthdr = app->backend_config.hosthdr;
  be.connect_timeout = app->backend_config.connect_timeout;
  be.first_byte_timeout = app->backend_config.first_byte_timeout;
  be.between_bytes_timeout = app->backend_config.between_bytes_timeout;
  be.max_connections = app->backend_config.max_connections;

  dir = VRT_new_backend(&ctx, &be);
  AN(dir);

  mbe->dir = dir;

  Lck_AssertHeld(&app->mtx);

  mbe->time_added = VTIM_real();
  VTAILQ_INSERT_TAIL(&app->belist, mbe, next);
}

/*
* Fetch JSON from a URL into a yajl_val object.
*/
static int fetch_json_data(yajl_val *node, const char *endpoint) {
  struct curl_recvbuf buf;
  CURLcode res;
  char errbuf[1024];

  init_curl_buffer(&buf);
  res = curl_fetch(&buf, endpoint);
  
  if (res != CURLE_OK) {
    free_curl_buffer(&buf);
    return 0;
  }

  *node = yajl_tree_parse((const char*)buf.data, errbuf, 1024);
  free_curl_buffer(&buf);

  if (*node == NULL) {
    return 0;
  }

  return 1;
}

/*
* Fetch labels from Marathon.
*/
static int
marathon_update_application_labels(struct marathon_application *app, yajl_val json_node) {
  const char *labels_path[] = { "app", "labels", (const char *) 0 };

  yajl_val labels = yajl_tree_get(json_node, labels_path, yajl_t_object);

  if (labels && YAJL_IS_OBJECT(labels)) {
    free_label_list(app);
    Lck_Lock(&app->mtx);
    for (unsigned int i = 0; i < labels->u.object.len; i++) {
      const char* key = labels->u.object.keys[i];
      yajl_val val = labels->u.object.values[i];

      if (YAJL_IS_STRING(val)) {
        const char *valstr = YAJL_GET_STRING(val);
        struct marathon_application_label *mlabel;
        ALLOC_OBJ(mlabel, VMOD_MARATHON_APPLICATION_LABEL_MAGIC);
        CHECK_OBJ_NOTNULL(mlabel, VMOD_MARATHON_APPLICATION_LABEL_MAGIC);

        mlabel->key     = strdup(key);
        mlabel->val     = strdup(valstr);
        mlabel->key_len = strlen(mlabel->key);
        mlabel->val_len = strlen(mlabel->val);

        VTAILQ_INSERT_TAIL(&app->labels, mlabel, next);
      }
    }
    Lck_Unlock(&app->mtx);
  }

  return 1;
}

/*
* Fetch backends from Marathon.
*/
static int marathon_update_backends(struct vmod_marathon_server *srv, struct marathon_application *app,
                                    yajl_val json_node)
{
  const char *task_path[]  = {"app", "tasks", (const char *) 0};
  const char *host_path[]  = {"host",  (const char *) 0};
  const char *ports_path[] = {"ports", (const char *) 0};
  const char *state_path[] = {"state", (const char *) 0};

  yajl_val tasks = yajl_tree_get(json_node, task_path, yajl_t_array);

    if (tasks && YAJL_IS_ARRAY(tasks)) {
      free_be_list(srv, app);

      Lck_Lock(&app->mtx);
      for (unsigned int i = 0; i < tasks->u.array.len; i++) {
        yajl_val task = tasks->u.array.values[i];
        yajl_val host = yajl_tree_get(task, host_path, yajl_t_string);
        yajl_val ports = yajl_tree_get(task, ports_path, yajl_t_array);
        yajl_val state = yajl_tree_get(task, state_path, yajl_t_string);

        if (!YAJL_IS_STRING(host) || !YAJL_IS_ARRAY(ports) || ports->u.array.len == 0 ||
            !YAJL_IS_INTEGER(ports->u.array.values[0])) {
          continue;
        }

        if (!YAJL_IS_STRING(state))
          continue;

        const char *state_str = YAJL_GET_STRING(state);

        // Only add tasks that is in TASK_RUNNING state.
        if (strncmp(state_str, "TASK_RUNNING", 12) != 0)
          continue;

        unsigned int port_index = 0;
        if (ports->u.array.len > app->backend_config.port_index)
          port_index = app->backend_config.port_index;
        else
          port_index = 0;

        char port[6];
        snprintf(port, 6, "%lld", YAJL_GET_INTEGER(ports->u.array.values[port_index]));
        add_backend(srv, app, YAJL_GET_STRING(host), port);
      }
      Lck_Unlock(&app->mtx);

      app->last_update = VTIM_real();
    }

  return 1;
}

/*
* Update application with data from Marathon.
*/
static int
marathon_update_application (struct vmod_marathon_server *srv,
                             struct marathon_application *app)
{
  yajl_val node = NULL;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);

  MARATHON_LOG_INFO(NULL, "Updating application %s.", app->id);

  if (!fetch_json_data(&node, app->marathon_app_endpoint)) {
    return 0;
  }

  marathon_update_backends(srv, app, node);
  marathon_update_application_labels(app, node);

  yajl_tree_free(node);

  return 1;
}

/*
* Schedule update of a given marathon_application.
*/
static void
marathon_schedule_update(struct vmod_marathon_server *srv, struct marathon_application *app) {

  struct marathon_update_queue_item *queue_elm = NULL;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);

  Lck_Lock(&srv->queue_mtx);
  VTAILQ_FOREACH(queue_elm, &srv->update_queue, next) {
    if (queue_elm->app == app) {
      Lck_Unlock(&srv->queue_mtx);
      return;
    }
  }

  queue_elm = NULL;

  ALLOC_OBJ(queue_elm, MARATHON_UPDATE_QUEUE_ITEM_MAGIC);
  CHECK_OBJ_NOTNULL(queue_elm, MARATHON_UPDATE_QUEUE_ITEM_MAGIC);

  queue_elm->app = app;

  VTAILQ_INSERT_TAIL(&srv->update_queue, queue_elm, next);
  Lck_Unlock(&srv->queue_mtx);
}

/*
* Perform all schedules updates.
*/
static void
marathon_perform_update(struct vmod_marathon_server *srv) {
  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  // Trigger update condition.
  AZ(pthread_cond_broadcast(&srv->update_cond));
}

/*
* Add application to srv->app_list.
*/
static struct marathon_application *
add_application(struct vmod_marathon_server *srv, const char *appid)
{
  struct marathon_application *app;
  struct vsb *vsb;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  AN(appid);

  if ((app = marathon_get_app(srv, appid)) != NULL)
    return app;

  ALLOC_OBJ(app, VMOD_MARATHON_APPLICATION_MAGIC);
  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);
  VTAILQ_INIT(&app->belist);
  VTAILQ_INIT(&app->labels);

  AN(memcpy(&app->backend_config, &srv->default_backend_config,
            sizeof(struct marathon_backend_config)));

  app->id = strdup(appid);
  app->id_len = strlen(app->id);
  app->curbe = NULL;
  app->lck = Lck_CreateClass("marathon.application");

  INIT_OBJ(&app->dir, DIRECTOR_MAGIC);

  app->dir.name     = "marathon-backend";
  app->dir.vcl_name = strdup(appid);
  app->dir.resolve  = marathon_resolve;
  app->dir.healthy  = marathon_healthy;
  app->dir.priv     = app;

  vsb = VSB_new_auto();
  AN(vsb);

  VSB_printf(vsb, "%s%s", srv->marathon_app_endpoint, appid);
  AZ(VSB_finish(vsb));

  app->marathon_app_endpoint = strdup(VSB_data(vsb));

  VSB_delete(vsb);

  AN(app->lck);
  Lck_New(&app->mtx, app->lck);

  VTAILQ_INSERT_TAIL(&srv->app_list, app, next);
  marathon_schedule_update(srv, app);

  return app;
}

/*
* Delete application from srv->app_list.
*/
static void
delete_application(struct vmod_marathon_server *srv, struct marathon_application *app)
{
  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);

  free_be_list(srv, app);
  free_label_list(app);

  Lck_Delete(&app->mtx);
  free(app->id);
  free(app->marathon_app_endpoint);
  FREE_OBJ(app);
  AZ(app);
}

/*
* Fetch application list from Marathon and import it to srv->app_list.
*/
static int
get_application_list(struct vmod_marathon_server *srv) {
  yajl_val node = NULL;
  const char *apps_path[] = {"apps", (const char *) 0};
  const char *id_path[]   = {"id",   (const char *) 0};

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  MARATHON_LOG_INFO(NULL, "get_application_list endpoint: %s", srv->marathon_app_endpoint);

  if (!fetch_json_data(&node, srv->marathon_app_endpoint)) {
    return 0;
  }

  yajl_val apps = yajl_tree_get(node, apps_path, yajl_t_array);

  if (YAJL_IS_ARRAY(apps)) {
    for (unsigned int i = 0; i < apps->u.array.len; i++) {
      yajl_val app = apps->u.array.values[i];
      yajl_val appid = yajl_tree_get(app, id_path, yajl_t_string);

      if (!YAJL_IS_STRING(appid)) {
        continue;
      }

      add_application(srv, YAJL_GET_STRING(appid));
   }
  }

  yajl_tree_free(node);

  return 1;
}

/*
* Thread that reads scheduled updates from queue and perform the update.
* Woken up by triggering srv->update_cond.
*/
void *
marathon_update_thread_func(void *ptr) {
  struct vmod_marathon_server *srv = NULL;
  struct marathon_update_queue_item *queue_elm = NULL, *queue_elm_n = NULL;

  CAST_OBJ_NOTNULL(srv, ptr, VMOD_MARATHON_SERVER_MAGIC);

  while(srv->active) {
    Lck_Lock(&srv->queue_mtx);
    Lck_CondWait(&srv->update_cond, &srv->queue_mtx, 0);

    if (!srv->active) {
      Lck_Unlock(&srv->queue_mtx);
      return NULL;
    }

    VTAILQ_FOREACH_SAFE(queue_elm, &srv->update_queue, next, queue_elm_n) {
      CHECK_OBJ_NOTNULL(queue_elm, MARATHON_UPDATE_QUEUE_ITEM_MAGIC);
      if (marathon_update_application(srv, queue_elm->app)) {
        VTAILQ_REMOVE(&srv->update_queue, queue_elm, next);
        FREE_OBJ(queue_elm);
        AZ(queue_elm);
      }
    }

    VTAILQ_INIT(&srv->update_queue);
    Lck_Unlock(&srv->queue_mtx);
  }

  return NULL;
}

/*
* Curl write callback for sse_event_thread_func.
*/
static size_t 
curl_sse_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
 {
  struct sse_cb_ctx *cb_ctx = NULL;
  struct vmod_marathon_server *srv = NULL;
  struct curl_recvbuf *buf = NULL;
  size_t recv_len, req_alloc;

  CAST_OBJ_NOTNULL(cb_ctx, userdata, SSE_CB_CTX_MAGIC);
  CHECK_OBJ_NOTNULL(cb_ctx->srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(cb_ctx->buf, CURL_RECVBUF_MAGIC);

  srv = cb_ctx->srv;
  buf = cb_ctx->buf;

  recv_len = (size * nmemb);

  if (!srv->active)
    return CURL_READFUNC_ABORT;

  if (recv_len > 0)
    cb_ctx->last_recv_time = VTIM_real();

  req_alloc = buf->data_len+recv_len+1;
  if (req_alloc > CURL_BUF_SIZE_MAX) {
    MARATHON_LOG_WARNING(NULL, "curl_sse_cb: Curl fetch buffer exceeded CURL_BUF_SIZE_MAX (%d > %d>. Discarding data.", 
      req_alloc, CURL_BUF_SIZE_MAX);
    buf->data_len = 0;
    buf->data[0] = '\0';
    return recv_len;
  }

  if (buf->size < req_alloc) {
    buf->data = (char*)realloc(buf->data, req_alloc);
    AN(buf->data);
    buf->size = req_alloc;
  }
  
  memcpy(buf->data+buf->data_len, ptr, recv_len);
  buf->data_len += recv_len;
  buf->data[buf->data_len] = '\0';

  /* All SSE Events should end with \n\r\n or \n\n. 
   * We use this assumption to figure out when we have enough
   * data in our buffer to parse the event. 
  */
  char *event_tail = strstr(buf->data, "\n\r\n");
  if (event_tail == NULL) event_tail = strstr(buf->data, "\n\n");
  if (event_tail == NULL) return recv_len;

  char event_type[SSE_EVENT_SIZE_MAX];
  char event_data[SSE_DATA_SIZE_MAX];


  event_type[0] = '\0';
  event_data[0] = '\0';

  /* Break up buffer into lines. */
  for (char *ptr = buf->data, *ptr2 = buf->data; ptr < event_tail+2; ptr++) {
    if (*ptr == '\n' || *ptr == '\r') {
      unsigned long llen = ptr - ptr2;
      char lbuf[llen];

      memcpy(lbuf, ptr2, llen);
      lbuf[llen] = '\0';
      ptr2 = ptr + 1; 

      /* Extract events and data. */
      if (strncmp(lbuf, "event: ", 7) == 0) {
        if (llen - 7 > SSE_EVENT_SIZE_MAX) continue; // EventID too large.
        memcpy(event_type, lbuf + 7, llen - 7);
        event_type[llen - 7] = '\0';
      } else if (strncmp(lbuf, "data: ", 6) == 0) {
        if (llen - 6 > SSE_DATA_SIZE_MAX) continue; // Event data too large.
        memcpy(event_data, lbuf + 6, llen - 6);
        event_data[llen - 6] = '\0';
      }
    }
  }

  /* Handle SSE event. */
  if (event_type[0] != '\0' && event_data[0] != '\0') {
      if (strncmp(event_type, "status_update_event", 22) == 0) {
      yajl_val node;
      char errbuf[1024];
      node = yajl_tree_parse((const char*)event_data, errbuf, 1024);
      
      if (node != NULL) {
        const char *appid_path[] = {"appId", (const char *) 0};
        yajl_val app_id = yajl_tree_get(node, appid_path, yajl_t_string);

        if (YAJL_IS_STRING(app_id)) {
          struct marathon_application *app = marathon_get_app(srv, YAJL_GET_STRING(app_id));
          if (app != NULL) {
            MARATHON_LOG_INFO(NULL, "Status change on %s.", YAJL_GET_STRING(app_id));
            marathon_schedule_update(srv, app);
            marathon_perform_update(srv);
          } else {
            MARATHON_LOG_INFO(NULL, "New application %s detected, adding to applist.", YAJL_GET_STRING(app_id));
            add_application(srv, YAJL_GET_STRING(app_id));
            marathon_perform_update(srv);
          }
        }
      }
      yajl_tree_free(node);
    } // TODO: Handle delete and health_status_changed_event event.
  }

  /* If we have some data remaining in buffer after end of current event
   * add it back to the curl buffer so it wil be included on next call.
   */
  unsigned long until_crlf_len = (event_tail - buf->data) + 2;
  if (buf->data_len == until_crlf_len) {
    buf->data_len = 0;
    buf->data[0] = '\0';
  } else {
    unsigned long rest_len = buf->data_len - until_crlf_len;
    memcpy(buf->data, buf->data + (buf->data_len - rest_len), rest_len);
    buf->data[rest_len] = '\0';
    buf->data_len = rest_len;
  }

  return recv_len;
}

/*
* Timeout SSE socket if we dont receive any data in SSE_PING_TIMEOUT seconds.
*/
int
sse_progress_callback(void *clientp, curl_off_t dltotal,
                      curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
  struct sse_cb_ctx *cb_ctx = NULL;

  CAST_OBJ_NOTNULL(cb_ctx, clientp, SSE_CB_CTX_MAGIC);
  CHECK_OBJ_NOTNULL(cb_ctx->srv, VMOD_MARATHON_SERVER_MAGIC);

  if (cb_ctx->srv->active == 0)
    return -1;

  if (VTIM_real() >= (cb_ctx->last_recv_time + SSE_PING_TIMEOUT)) {
    MARATHON_LOG_ERROR(NULL, "SSE Eventbus: No data received in %d seconds. Reconnecting.", SSE_PING_TIMEOUT);
    cb_ctx->last_recv_time = VTIM_real();
    return -1;
  }

  return 0;
}

/*
* Listen for SSE events from Marathon and update apps accordingly.
*/
static void* 
sse_event_thread_func(void *ptr) 
{
  struct marathon_application *app = NULL;
  struct vmod_marathon_server *srv = NULL;
  struct curl_recvbuf buf;
  struct sse_cb_ctx cb_ctx;
  struct curl_slist *headers = NULL;
  CURL *curl;
  CURLcode res;

  CAST_OBJ_NOTNULL(srv, ptr, VMOD_MARATHON_SERVER_MAGIC);
  INIT_OBJ(&cb_ctx, SSE_CB_CTX_MAGIC);

  cb_ctx.srv = srv;
  cb_ctx.buf = &buf;
  cb_ctx.last_recv_time = VTIM_real();

  MARATHON_LOG_INFO(NULL, "SSE Endpoint: %s", srv->marathon_sse_endpoint);

  init_curl_buffer(&buf);
  curl = curl_easy_init();

  headers = curl_slist_append(headers, "Accept: text/event-stream");
  res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, &sse_progress_callback);
  curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &cb_ctx);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &cb_ctx);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_sse_cb);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_URL, srv->marathon_sse_endpoint);

  while(srv->active) {
    get_application_list(srv);
    marathon_perform_update(srv);

    MARATHON_LOG_INFO(NULL, "Starting SSE connection.");
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      MARATHON_LOG_ERROR(NULL, "SSE Eventbus: Curl failed: %s\n", curl_easy_strerror(res));
    }

    if (!srv->active)
      break;

    MARATHON_LOG_INFO(NULL, "Disconnected from SSE Eventbus, reconnecting.");

    /*
     * If we reach this point we should reschedule updates of all applications.
     */
    VTAILQ_FOREACH(app, &srv->app_list, next) {
      marathon_schedule_update(srv, app);
    }

    usleep(1000000);
  }

  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  free_curl_buffer(&buf);

  return NULL;
}

/*
* Set backend configuration.
*/
VCL_VOID
vmod_server_set_backend_config(VRT_CTX, struct vmod_marathon_server *srv,
                   VCL_STRING id, VCL_PROBE probe, VCL_INT port_index,
                   VCL_DURATION connect_timeout, VCL_DURATION first_byte_timeout,
                   VCL_DURATION between_bytes_timeout, VCL_INT max_connections)
{
  struct marathon_application *app = NULL;
  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);

  AN(id);
  app = add_application(srv, id);
  AN(app);

  app->backend_config.port_index            = port_index;
  app->backend_config.probe                 = probe;
  app->backend_config.connect_timeout       = connect_timeout;
  app->backend_config.first_byte_timeout    = first_byte_timeout;
  app->backend_config.between_bytes_timeout = between_bytes_timeout;
  app->backend_config.max_connections       = max_connections;
}

/*
* VCL function .backend_by_label()
* Returns current active backends for a given marathon application identified by label.
*/
VCL_BACKEND
vmod_server_backend_by_label(VRT_CTX, struct vmod_marathon_server *srv,
                          VCL_STRING key, VCL_STRING val)
{
  struct marathon_application *app = NULL;

    CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

    VSLb(ctx->vsl, SLT_Debug, "backend_by_label(%s, %s)", key, val);

    app = marathon_get_app_by_label(srv, key, val);

    if (app != NULL) {
      return &app->dir;
    }

    return NULL;
}

/*
* VCL function .backend_by_id()
* Returns current active backends for a given marathon application identified by id.
*/
VCL_BACKEND 
vmod_server_backend_by_id(VRT_CTX, struct vmod_marathon_server *srv,
                    VCL_STRING id)
{
  struct marathon_application *app = NULL;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

  VSLb(ctx->vsl, SLT_Debug, "backend_by_id(%s)", id);

  app = marathon_get_app(srv, id);

  if (app != NULL) {
    return &app->dir;
  } 

  return NULL;
}

/*
* Start SSE event thread and marathon update thread.
*/
static void
marathon_start(struct vmod_marathon_server *srv) {
  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);

  MARATHON_LOG_INFO(NULL, "Starting update thread.");
  AZ(pthread_create(&srv->update_th, NULL, &marathon_update_thread_func, srv));
  MARATHON_LOG_INFO(NULL, "Starting SSE thread.");
  AZ(pthread_create(&srv->sse_th, NULL, &sse_event_thread_func, srv));
}

/*
* Stop running threads and free backend list.
*/
static void
marathon_stop(struct vmod_marathon_server *srv) {
  struct marathon_application *app = NULL, *appn = NULL;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);

  AZ(srv->active);

  pthread_cond_broadcast(&srv->update_cond);
  AZ(pthread_join(srv->sse_th, NULL));
  MARATHON_LOG_INFO(NULL, "SSE thread terminated.");
  AZ(pthread_join(srv->update_th, NULL));
  MARATHON_LOG_INFO(NULL, "Update thread terminated.");

  VTAILQ_FOREACH_SAFE(app, &srv->app_list, next, appn) {
    delete_application(srv, app);
  }
}

/*
* Varnish' event callback function.
*/
int
event_func(VRT_CTX, struct vmod_priv *vcl_priv, enum vcl_event_e e)
{
  unsigned int active = 0;
  struct vmod_marathon_server *obj = NULL;

  CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

  switch(e) {
    case VCL_EVENT_LOAD:
      return 0;
    break;

    case VCL_EVENT_DISCARD:
      return 0;
    break;

    case VCL_EVENT_WARM:
      active = 1;
    break;

    case VCL_EVENT_COLD:
      active = 0;
    break;
  }

  VTAILQ_FOREACH(obj, &objects, next) {
    if (obj->vcl == ctx->vcl) {
      assert(obj->active != active);
      obj->active = active;

      if (active) {
        marathon_start(obj);
      } else {
        marathon_stop(obj);
      }
    }
  }

  return 0;
}

/* 
 * Constructor for marathon.server object.
*/
VCL_VOID
vmod_server__init(VRT_CTX, struct vmod_marathon_server **srvp,
                  const char *vcl_name, VCL_STRING endpoint,
                  VCL_DURATION connect_timeout, VCL_DURATION first_byte_timeout, 
                  VCL_DURATION between_bytes_timeout, VCL_INT max_connections)
{
  struct vmod_marathon_server *srv = NULL;
  struct vsb *vsb;

  CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

  AN(srvp);
  AZ(*srvp);
  AN(vcl_name);
  AN(endpoint);

  ALLOC_OBJ(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);

  srv->vcl                = ctx->vcl;
  srv->vcl_name           = strdup(vcl_name);
  srv->active             = 0;

  vsb = VSB_new_auto();
  AN(vsb);

  VSB_printf(vsb, "%s%s", endpoint, MARATHON_APP_PATH);
  AZ(VSB_finish(vsb));

  srv->marathon_app_endpoint = strdup(VSB_data(vsb));
  VSB_clear(vsb);

  VSB_printf(vsb, "%s%s", endpoint, MARATHON_SSE_PATH);
  AZ(VSB_finish(vsb));

  srv->marathon_sse_endpoint = strdup(VSB_data(vsb));
  VSB_delete(vsb);

  VTAILQ_INIT(&srv->app_list);
  VTAILQ_INIT(&srv->update_queue);

  *srvp = srv;

  srv->queue_lck = Lck_CreateClass("marathon.updatequeue");
  AN(srv->queue_lck);

  Lck_New(&srv->queue_mtx, srv->queue_lck);

  srv->default_backend_config.vcl_name              = srv->vcl_name;
  srv->default_backend_config.ipv4_addr             = NULL;
  srv->default_backend_config.ipv6_addr             = NULL;
  srv->default_backend_config.port                  = NULL;
  srv->default_backend_config.hosthdr               = NULL;
  srv->default_backend_config.connect_timeout       = connect_timeout;
  srv->default_backend_config.first_byte_timeout    = first_byte_timeout;
  srv->default_backend_config.between_bytes_timeout = between_bytes_timeout;
  srv->default_backend_config.max_connections       = max_connections;
  srv->default_backend_config.proxy_header          = 0;
  srv->default_backend_config.probe                 = NULL;
  srv->default_backend_config.port_index            = 0;
  
  VTAILQ_INSERT_TAIL(&objects, srv, next);
}

/* 
 * Destructor for marathon.server object.
*/
VCL_VOID
vmod_server__fini(struct vmod_marathon_server **srvp)
{
  struct vmod_marathon_server *srv;

  if (srvp == NULL || *srvp == NULL) return;

  srv = *srvp;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  AZ(srv->active);

  free(srv->vcl_name);
  free(srv->marathon_app_endpoint);
  free(srv->marathon_sse_endpoint);

  Lck_Delete(&srv->queue_mtx);
  FREE_OBJ(srv);
  AZ(srv);
}
