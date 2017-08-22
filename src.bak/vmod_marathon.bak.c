#include "vmod_marathon.h"

#define IPBUFSIZ (VTCP_ADDRBUFSIZE + VTCP_PORTBUFSIZE + 2)

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

static void
get_addrname(char *addr, struct suckaddr *sa)
{
	char a[VTCP_ADDRBUFSIZE], p[VTCP_PORTBUFSIZE];

	VTCP_name(sa, a, sizeof(a), p, sizeof(p));
	snprintf(addr, IPBUFSIZ, "%s:%s", a, p);
}

int __match_proto__(vmod_event_f)
event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{

	(void) ctx;
	(void) priv;

	switch (e) {
	case VCL_EVENT_LOAD:
		break;
	case VCL_EVENT_WARM:
		break;
	case VCL_EVENT_COLD:
		break;
	case VCL_EVENT_DISCARD:
		return (0);
		break;
	default:
		return (0);
	}

	return (0);
}

/* Constructor for marathon.server object. */
VCL_VOID vmod_server__init(VRT_CTX, struct vmod_marathon_server **srvp, const char *vcl_name, 
  VCL_STRING marathonurl) {
  
  struct vmod_marathon_server *srv;

  CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

  AN(srvp);
  AZ(*srvp);  
  AN(vcl_name);
  AN(marathonurl);

  ALLOC_OBJ(srv, VMOD_MARATHON_SERVER_MAGIC);
  AN(srv);

  srv->vcl_name = vcl_name;
  srv->marathonurl = WS_Copy(ctx->ws, (const void*)marathonurl, strlen(marathonurl));
  *srvp = srv;
}

/* Destructor for marathon.server object. */
VCL_VOID vmod_server__fini(struct vmod_marathon_server **srvp) {
  struct vmod_marathon_server *srv;

  if (srvp == NULL || *srvp == NULL) return;

  srv = *srvp;

  CHECK_OBJ_NOTNULL(srv, VMOD_MARATHON_SERVER_MAGIC);
  if (srv->marathonurl != NULL) free(srv->marathonurl);
  FREE_OBJ(srv);
}

/*
VCL_BACKEND vmod_server_backend(VRT_CTX, struct vmod_marathon_server *srv) {
  struct vrt_backend be;
  struct director *dir;
  struct suckaddr *sa4 = NULL, *sa6 = NULL;
  char ipv4_addr[IPBUFSIZ] = "", ipv6_addr[IPBUFSIZ] = "";

  const char* host = "drm.skudsvik.no";
  const char* port = "80";

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
  be.vcl_name = srv->vcl_name;

  be.ipv4_addr = strdup(ipv4_addr);
  be.ipv6_addr = strdup(ipv6_addr);
  be.port = strdup(port);
  //be.hosthdr = strdup("drm.skudsvik.no");
  //be.connect_timeout = 2000;
  //be.first_byte_timeout = 2000;
  //be.between_bytes_timeout = 2000;
  //be.max_connections = 1024;
  //be.proxy_header = 0;

  AN(srv);
  VSLb(ctx->vsl, SLT_Debug, "Marathon URL: %s", srv->marathonurl);
  VSLb(ctx->vsl, SLT_Debug, "VCL Name: %s", srv->vcl_name);
  

  dir = VRT_new_backend(ctx, &be);
  AN(dir);

  return dir;
}*/