/*
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit vmod.vcc and run make instead
 */

struct vmod_priv;

extern const struct vmod_data Vmod_marathon_Data;

#ifdef VCL_MET_MAX
vmod_event_f event_function;
#endif
struct vmod_marathon_server;
VCL_VOID vmod_server__init(VRT_CTX,
    struct vmod_marathon_server **, const char *, VCL_STRING);
VCL_VOID vmod_server__fini(struct vmod_marathon_server **);
VCL_BOOL vmod_server_setup_application(VRT_CTX,
    struct vmod_marathon_server *, VCL_STRING, VCL_INT, VCL_PROBE,
    VCL_STRING, VCL_DURATION, VCL_DURATION, VCL_DURATION, VCL_INT,
    VCL_INT);
VCL_BACKEND vmod_server_application(VRT_CTX,
    struct vmod_marathon_server *, VCL_STRING);

