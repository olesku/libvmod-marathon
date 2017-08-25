
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
* Initialize / zero out curl_recvbuffer.
*/
static void 
zero_curl_buffer(struct curl_recvbuf *buf) 
{
  buf->len = 0;
  buf->data[0] = '\0';
}

/*
* Curl write callback func used in curl_fetch()
*/
static size_t 
curl_fetch_cb(char *ptr, size_t size, size_t nmemb, void *userdata) 
{
  size_t len = (size*nmemb);
  struct curl_recvbuf* buf = userdata;

  if (buf->len + len > CURL_BUF_SIZE_MAX) {
    MARATHON_LOG_WARNING(NULL, "Buffer exhaustion while fetching data from Marathon. Buffer size was %d.", buf->len+len);
    return len;
  }

  memcpy(buf->data+buf->len, ptr, len);

  buf->len += len;  
  buf->data[buf->len] = '\0';

  return len;
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
free_be_list(VRT_CTX, struct marathon_application *app)
{
  struct marathon_backend *mbe = NULL, *mben = NULL;

  Lck_Lock(&app->mtx);

  VTAILQ_FOREACH_SAFE(mbe, &app->belist, next, mben) {
  free(mbe->host_str);
  free(mbe->port_str);
  VRT_delete_backend(ctx, &mbe->dir);
  // TODO: Check if VRT_delete_backend also does a free of ipv(4|6)_addr and port.
  VTAILQ_REMOVE(&app->belist, mbe, next);
  FREE_OBJ(mbe);
}

  VTAILQ_INIT(&app->belist);

  app->curbe = NULL;
  Lck_Unlock(&app->mtx);
}

/*
* Get marathon_application from ID.
* Returns NULL if not found.
*/
static struct marathon_application* 
marathon_get_app(struct vmod_marathon_server* srv, const char* id) 
{
  struct marathon_application *obj = NULL;

  VTAILQ_FOREACH(obj, &srv->app_list, next) {
    if (strncmp(id, obj->id, strlen(id)) == 0) {
      return obj;
    } 
  }

  return NULL;
}

/*
* Add backend to marathon_application.
*/
static void 
add_backend(VRT_CTX, struct marathon_application *app, 
            const char *host, const char *port)
{
  struct vrt_backend be;
  struct marathon_backend *mbe = NULL;
  struct director *dir = NULL;
  struct suckaddr *sa4 = NULL, *sa6 = NULL;
  char ipv4_addr[IPBUFSIZ] = "", ipv6_addr[IPBUFSIZ] = "";

  sa4 = get_suckaddr(host, port, AF_INET);
  sa6 = get_suckaddr(host, port, AF_INET6);

  if (sa4 != NULL)
		get_addrname(ipv4_addr, sa4);
	if (sa6 != NULL)
		get_addrname(ipv6_addr, sa6);


  INIT_OBJ(&be, VRT_BACKEND_MAGIC);

  be.probe = NULL;
  be.ipv4_suckaddr = sa4;
  be.ipv6_suckaddr = sa6;
  /* TODO: Do we actually need these fields ?
  be.ipv4_addr = strdup(ipv4_addr);
  be.ipv6_addr = strdup(ipv6_addr);
  be.port = strdup(port);
  */
  be.vcl_name = app->vcl_name;
  be.probe = app->probe;
  be.hosthdr = app->hosthdr;
  be.connect_timeout = app->connect_timeout;
  be.first_byte_timeout = app->first_byte_timeout;
  be.between_bytes_timeout = app->between_bytes_timeout;
  be.max_connections = app->max_connections;

  ALLOC_OBJ(mbe, VMOD_MARATHON_BACKEND_MAGIC);
  AN(mbe);

  // TODO: Only here for debugging purposes, remove me and clean up the struct.
  mbe->host_str = strdup(host);
  mbe->port_str = strdup(port);

  dir = VRT_new_backend(ctx, &be);
  AN(dir);

  mbe->dir = dir;

  // TODO: Consider moving app lock to here.
  Lck_AssertHeld(&app->mtx);

  mbe->time_added = VTIM_real();
  VTAILQ_INSERT_TAIL(&app->belist, mbe, next);
}

/*
* Fetch backends for a given marathon_application from Marathon.
*/
static int 
marathon_update_application (VRT_CTX, struct vmod_marathon_server *srv, 
                             struct marathon_application *app)
{
  struct curl_recvbuf buf;
  char endpoint[1024];
  CURLcode res;

  zero_curl_buffer(&buf);

  MARATHON_LOG_INFO(ctx, "marathon_update_application: %s", app->id);
  snprintf(endpoint, 1024, "%s%s%s", srv->marathon_endpoint, MARATHON_APP_PATH, app->id);

  res = curl_fetch(&buf, endpoint);

  if (res != CURLE_OK) {
    return 0;
  }

  yajl_val node;
  char errbuf[1024];
  node = yajl_tree_parse((const char*)buf.data, errbuf, 1024);
  
  if (node == NULL) {
    return 0;
  }

  const char *task_path[] = {"app", "tasks", (const char *) 0};
  const char *host_path[] = {"host", (const char *) 0};
  const char *ports_path[] = {"ports", (const char *) 0};
  const char *state_path[] = {"state", (const char *) 0};

  yajl_val tasks = yajl_tree_get(node, task_path, yajl_t_array);

  if (tasks && YAJL_IS_ARRAY(tasks)) {
    free_be_list(ctx, app);
    Lck_Lock(&app->mtx);

    for (unsigned int i = 0; i < tasks->u.array.len; i++) {
      yajl_val task = tasks->u.array.values[i];
      yajl_val host = yajl_tree_get(task, host_path, yajl_t_string);
      yajl_val ports = yajl_tree_get(task, ports_path, yajl_t_array);
      yajl_val state = yajl_tree_get(task, state_path, yajl_t_string);

      if (!YAJL_IS_STRING(host) || !YAJL_IS_ARRAY(ports) || 
          !YAJL_IS_INTEGER(ports->u.array.values[0])) {
        continue;
      }

      // Only add tasks that is in TASK_RUNNING state.
      if (YAJL_IS_STRING(state) && strncmp(YAJL_GET_STRING(state), "TASK_RUNNING", 12) != 0)
        continue;

      unsigned int port_index = 0;
      if (ports->u.array.len >= app->port_index)
        port_index = app->port_index;

      char port[6];
      snprintf(port, 6, "%lld", YAJL_GET_INTEGER(ports->u.array.values[port_index]));
      add_backend(ctx, app, YAJL_GET_STRING(host), port);
    }
    
    app->last_update = VTIM_real();

    Lck_Unlock(&app->mtx);
  }

  yajl_tree_free(node);

  return 1;
}

/*
* Schedule update of a given marathon_application.
*/
static void
marathon_schedule_update(struct vmod_marathon_server *srv, struct marathon_application *app) {
  struct marathon_application *qelm = NULL;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);

  Lck_Lock(&srv->queue_mtx);

  // First ensure an update is not already scheduled for this app.
  VTAILQ_FOREACH(qelm, &srv->update_queue, next) {
    if (qelm == app) {
      Lck_Unlock(&srv->queue_mtx);
      return;
    }
  }

  // Add it to the update queue.
  VTAILQ_INSERT_TAIL(&srv->update_queue, app, next);
  Lck_Unlock(&srv->queue_mtx);
}

/*
* Schedule update of all marathon_application's.
*/
static void
marathon_schedule_update_all(struct vmod_marathon_server *srv) {
  struct marathon_application *app = NULL;
  VTAILQ_FOREACH(app, &srv->app_list, next) {
    CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);
    marathon_schedule_update(srv, app);
  }
}

/*
* Perform all schedules updates.
*/
static void
marathon_perform_update(struct vmod_marathon_server *srv) {
  // Trigger update condition.
  AZ(pthread_cond_broadcast(&srv->update_cond));
}

/*
* Thread that reads scheduled updates and do the actual update.
* Woken up by triggering sev->update_cond.
*/
void *
marathon_update_thread_func(void* ptr) {
  struct vmod_marathon_server *srv = NULL;
  struct marathon_application *qelm = NULL;
  struct vrt_ctx ctx;
  
  CAST_OBJ_NOTNULL(srv, ptr, VMOD_MARATHON_SERVER_MAGIC);

  INIT_OBJ(&ctx, VRT_CTX_MAGIC);
  ctx.vcl = srv->vcl;

  do {
    Lck_Lock(&srv->queue_mtx);
    Lck_CondWait(&srv->update_cond, &srv->queue_mtx, VTIM_real() + 30); // TODO: Consider if we actually need a timeout here.
    Lck_Unlock(&srv->queue_mtx);

    if (!srv->active) return NULL;

    while(!VTAILQ_EMPTY(&srv->update_queue)) {
      qelm = VTAILQ_FIRST(&srv->update_queue);
      CHECK_OBJ_NOTNULL(qelm, VMOD_MARATHON_APPLICATION_MAGIC);

      if (marathon_update_application(&ctx, srv, qelm)) {
        Lck_Lock(&srv->queue_mtx);
        VTAILQ_REMOVE(&srv->update_queue, qelm, next);
        Lck_Unlock(&srv->queue_mtx);
      }
    }
  } while(1);
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
  size_t recv_len = (size * nmemb);

  CAST_OBJ_NOTNULL(cb_ctx, userdata, SSE_CB_CTX_MAGIC);
  CHECK_OBJ_NOTNULL(cb_ctx->srv, VMOD_MARATHON_SERVER_MAGIC);

  srv = cb_ctx->srv;
  buf = cb_ctx->buf;

  if (!srv->active)
    return CURL_READFUNC_ABORT;

  if (buf->len+recv_len < CURL_BUF_SIZE_MAX) {
    memcpy(buf->data+buf->len, ptr, recv_len);
    buf->len += recv_len; 
  }
  else if (recv_len < CURL_BUF_SIZE_MAX) {
    memcpy(buf->data, ptr, recv_len);
    buf->len = recv_len;  
  } else {
    // Discard data since it cannot fit in the buffer.
    zero_curl_buffer(buf);
    return recv_len;
  }
  
  buf->data[buf->len] = '\0';

  /* All SSE Events should end with  \n\r\n or \n\n. 
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
            marathon_schedule_update(srv, app);
            marathon_perform_update(srv);
          }
        }
      }
      yajl_tree_free(node);
    }
  }

  /* If we have some data remaining in buffer after end of current event
   * add it back to the curl buffer so it wil be included on next call.
   */
  unsigned long until_crlf_len = (event_tail - buf->data) + 2;
  if (buf->len == until_crlf_len) {
    zero_curl_buffer(buf);
  } else {
    unsigned long rest_len = buf->len - until_crlf_len;
    memcpy(buf->data, buf->data + (buf->len - rest_len), rest_len);
    buf->data[rest_len] = '\0';
    buf->len = rest_len;
  }

  return recv_len;
}

/*
* Listen for SSE events from Marathon and update apps accordingly.
*/
static void* 
sse_event_thread_func(void *ptr) 
{
  struct vmod_marathon_server *srv = NULL;
  struct curl_recvbuf buf;
  struct sse_cb_ctx cb_ctx;
  struct curl_slist *headers = NULL;
  char endpoint[1024];
  CURL *curl;
  CURLcode res;

  CAST_OBJ_NOTNULL(srv, ptr, VMOD_MARATHON_SERVER_MAGIC);
  INIT_OBJ(&cb_ctx, SSE_CB_CTX_MAGIC);

  cb_ctx.srv = srv;
  cb_ctx.buf = &buf;

  snprintf(endpoint, 1024, "%s%s", srv->marathon_endpoint, MARATHON_SSE_PATH);
  MARATHON_LOG_INFO(NULL, "SSE Endpoint: %s", endpoint);

  zero_curl_buffer(&buf);
  curl = curl_easy_init();

  headers = curl_slist_append(headers, "Accept: text/event-stream");
  res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &cb_ctx);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_sse_cb);
  curl_easy_setopt(curl, CURLOPT_URL, endpoint);

  // TODO: We should have some sort of timeout here.. Checking for SSE pings is probably the best approach.

  while(srv->active) {
    marathon_schedule_update_all(srv);
    marathon_perform_update(srv);

    MARATHON_LOG_INFO(NULL, "Starting SSE connection.");
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      MARATHON_LOG_ERROR(NULL, "curl failed: %s\n", curl_easy_strerror(res));
    }
  }

  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  return NULL;
}

/*
* VCL function .add_application()
* Adds a Marathon application to our list.
*/
VCL_VOID 
vmod_server_add_application(VRT_CTX, struct vmod_marathon_server *srv, 
                                   VCL_STRING id, VCL_INT port_index, 
                                   VCL_PROBE probe, VCL_STRING host_header, 
                                   VCL_DURATION connect_timeout, VCL_DURATION first_byte_timeout,
                                   VCL_DURATION between_bytes_timeout, VCL_INT max_connections,
                                   VCL_INT proxy_header)
{
  struct marathon_application *app = marathon_get_app(srv, id);

  if (app == NULL) {
    ALLOC_OBJ(app, VMOD_MARATHON_APPLICATION_MAGIC);
    CHECK_OBJ_NOTNULL(app, VMOD_MARATHON_APPLICATION_MAGIC);
    VTAILQ_INIT(&app->belist);
    MARATHON_LOG_INFO(ctx, "Initialized app: %s", id);
  }

  app->id = strdup(id);
  app->port_index = port_index;
  app->probe = probe;
  app->hosthdr = strdup(host_header);
  app->connect_timeout = connect_timeout;
  app->first_byte_timeout = first_byte_timeout;
  app->between_bytes_timeout = between_bytes_timeout;
  app->max_connections = max_connections;
  app->vcl_name = srv->vcl_name;
  app->curbe = NULL;
  app->lck = Lck_CreateClass("marathon.application");

  Lck_New(&app->mtx, app->lck);
  VTAILQ_INSERT_TAIL(&srv->app_list, app, next);
  marathon_schedule_update(srv, app);
}

/*
* VCL function .backend()
* Returns current active backends for a given marathon application.
*/
VCL_BACKEND 
vmod_server_backend(VRT_CTX, struct vmod_marathon_server *srv,
                        VCL_STRING id) 
{
  struct marathon_application *app = NULL;

  VSLb(ctx->vsl, SLT_Debug, "Call to .application(%s)", id);

  app = marathon_get_app(srv, id);

  if (app != NULL) {
    Lck_Lock(&app->mtx);
    if (VTAILQ_EMPTY(&app->belist)) {
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

    VSLb(ctx->vsl, SLT_Debug, "APP: %s Backend: %s:%s", app->id, app->curbe->host_str, app->curbe->port_str);

    Lck_Unlock(&app->mtx);
    return app->curbe->dir;
  } 

  return NULL;
}

/*
* Start SSE event thread and marathon update thread.
*/
static void
marathon_start(struct vmod_marathon_server *srv) {
  MARATHON_LOG_INFO(NULL, "Starting SSE thread.");
  AZ(pthread_create(&srv->sse_th, NULL, &sse_event_thread_func, srv));
  MARATHON_LOG_INFO(NULL, "Starting update thread.");
  AZ(pthread_create(&srv->update_th, NULL, &marathon_update_thread_func, srv));
}

/*
* Stop running threads and free backend list.
*/
static void
marathon_stop(struct vmod_marathon_server *srv) {
  struct marathon_application *app = NULL, *appn = NULL;
  struct vrt_ctx ctx;

  // TODO: We need to stop the ongoing curl calls somehow.

  AZ(srv->active);

  MARATHON_LOG_INFO(NULL, "Performing cleanup of %s.", srv->vcl_name);
  pthread_cond_broadcast(&srv->update_cond);
  AZ(pthread_join(srv->sse_th, NULL));
  AZ(pthread_join(srv->update_th, NULL));
  MARATHON_LOG_INFO(NULL, "Threads joined.");

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);

  INIT_OBJ(&ctx, VRT_CTX_MAGIC);
  ctx.vcl = srv->vcl;
  ctx.vsl = NULL;

  AZ(srv->active);

  VTAILQ_FOREACH_SAFE(app, &srv->app_list, next, appn) {
    free_be_list(&ctx, app);
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

  switch(e) {
    case VCL_EVENT_LOAD:
      MARATHON_LOG_INFO(ctx, "VCL_EVENT_LOAD");
      return(0);
    break;

    case VCL_EVENT_DISCARD:
      MARATHON_LOG_INFO(ctx, "VCL_EVENT_DISCARD");
      return(0);
    break;

    case VCL_EVENT_WARM:
      MARATHON_LOG_INFO(ctx, "VCL_EVENT_WARM");
      active = 1;
    break;

    case VCL_EVENT_COLD:
      MARATHON_LOG_INFO(ctx, "VCL_EVENT_COLD");
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
                  const char *vcl_name, VCL_STRING endpoint)
{
  struct vmod_marathon_server *srv = NULL;

  MARATHON_LOG_INFO(NULL, "Call to __init");

  CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

  AN(srvp);
  AZ(*srvp);
  AN(vcl_name);
  AN(endpoint);

  ALLOC_OBJ(srv, VMOD_MARATHON_SERVER_MAGIC);
  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);

  srv->vcl                = ctx->vcl;
  srv->vcl_name           = strdup(vcl_name);
  srv->marathon_endpoint  = strdup(endpoint);
  srv->active             = 0;

  VTAILQ_INIT(&srv->app_list);
  VTAILQ_INIT(&srv->update_queue);

  *srvp = srv;

  srv->queue_lck = Lck_CreateClass("marathon.updatequeue");
  Lck_New(&srv->queue_mtx, srv->queue_lck);
  VTAILQ_INSERT_TAIL(&objects, srv, next);
}

/* 
 * Destructor for marathon.server object.
*/
VCL_VOID
vmod_server__fini(struct vmod_marathon_server **srvp)
{
  struct vmod_marathon_server *srv;
  struct marathon_application *app = NULL, *appn = NULL;

  MARATHON_LOG_INFO(NULL, "Call to __fini");

  if (srvp == NULL || *srvp == NULL) return;

  srv = *srvp;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  AZ(srv->active);

  VTAILQ_FOREACH_SAFE(app, &srv->app_list, next, appn) {
    VTAILQ_REMOVE(&srv->app_list, app, next);
    free(app->id);
    free(app->hosthdr);
    Lck_Delete(&app->mtx);
    VSM_Free(app->lck);
    FREE_OBJ(app);
    AZ(app);
  }

  Lck_Delete(&srv->queue_mtx);
  VSM_Free(srv->queue_lck);

  FREE_OBJ(srv);
  AZ(srv);
}
