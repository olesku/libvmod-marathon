struct marathon_backend {
  unsigned int magic;
  #define VMOD_MARATHON_BACKEND_MAGIC 0x8476ab2f
  double time_added;
  struct director *dir;
  VTAILQ_ENTRY(marathon_backend) next;
};

struct marathon_application {
  unsigned int magic;
  #define VMOD_MARATHON_SERVER_MAGIC 0x8476ab3f
  char *id;
  double last_update;
  VRT_BACKEND_FIELDS();
  VTAILQ_HEAD(,marathon_backend) belist;
};

struct vmod_marathon_server {
  unsigned magic;
  #define VMOD_MARATHON_SERVER_MAGIC 0x8476ab4f
  char                               *marathon_endpoint;
  const char                         *vcl_name;
  VTAILQ_HEAD(,marathon_application) applist;
};