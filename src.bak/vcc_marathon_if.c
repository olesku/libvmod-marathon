/*
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit vmod.vcc and run make instead
 */

#include "config.h"
#include <stdio.h>
#include "vdef.h"
#include "vcl.h"
#include "vrt.h"
#include "vcc_marathon_if.h"
#include "vmod_abi.h"

struct vmod_marathon_server;
typedef VCL_VOID td_marathon_server__init(VRT_CTX,
    struct vmod_marathon_server **, const char *, VCL_STRING);
typedef VCL_VOID td_marathon_server__fini(
    struct vmod_marathon_server **);
typedef VCL_BOOL td_marathon_server_setup_application(VRT_CTX,
    struct vmod_marathon_server *, VCL_STRING, VCL_INT, VCL_PROBE,
    VCL_STRING, VCL_DURATION, VCL_DURATION, VCL_DURATION, VCL_INT,
    VCL_INT);
typedef VCL_BACKEND td_marathon_server_application(VRT_CTX,
    struct vmod_marathon_server *, VCL_STRING);


struct Vmod_marathon_Func {
	vmod_event_f			*_event;
	td_marathon_server__init	*server__init;
	td_marathon_server__fini	*server__fini;
	td_marathon_server_setup_application*server_setup_application;
	td_marathon_server_application	*server_application;
};

/*lint -esym(754, Vmod_debug_Func::*) */

static const struct Vmod_marathon_Func Vmod_Func = {
	event_function,
	vmod_server__init,
	vmod_server__fini,
	vmod_server_setup_application,
	vmod_server_application,

};

static const char Vmod_Proto[] =
	"struct vmod_marathon_server;\n"
	"typedef VCL_VOID td_marathon_server__init(VRT_CTX,\n"
	"    struct vmod_marathon_server **, const char *, VCL_STRING);\n"
	"typedef VCL_VOID td_marathon_server__fini(\n"
	"    struct vmod_marathon_server **);\n"
	"typedef VCL_BOOL td_marathon_server_setup_application(VRT_CTX,\n"
	"    struct vmod_marathon_server *, VCL_STRING, VCL_INT, VCL_PROBE,\n"
	"    VCL_STRING, VCL_DURATION, VCL_DURATION, VCL_DURATION, VCL_INT,\n"
	"    VCL_INT);\n"
	"typedef VCL_BACKEND td_marathon_server_application(VRT_CTX,\n"
	"    struct vmod_marathon_server *, VCL_STRING);\n"
	"\n"
	"/* Functions */\n"
	"\n"
	"struct Vmod_marathon_Func {\n"
	"	vmod_event_f			*_event;\n"
	"	td_marathon_server__init	*server__init;\n"
	"	td_marathon_server__fini	*server__fini;\n"
	"	td_marathon_server_setup_application*server_setup_application;\n"
	"	td_marathon_server_application	*server_application;\n"
	"};\n"
	"static struct Vmod_marathon_Func Vmod_marathon_Func;";

/*lint -save -e786 -e840 */
static const char * const Vmod_Spec[] = {
	"$EVENT\0"
	    "Vmod_marathon_Func._event",

	"$OBJ\0"	"marathon.server\0"

	    "struct vmod_marathon_server\0"

	    "VOID\0"
	    "Vmod_marathon_Func.server__init\0"
		"STRING\0"
		    "\2" "marathon_endpoint\0"
		    "\3" "\"\"\0"
		"\0"
	    "\0"

	    "VOID\0"
	    "Vmod_marathon_Func.server__fini\0"
		"\0"
	    "\0"

	    "marathon.server.setup_application\0"
		"BOOL\0"
		"Vmod_marathon_Func.server_setup_application\0"
		    "STRING\0"
			"\2" "id\0"
			"\3" "\"\"\0"
		    "INT\0"
			"\2" "port_index\0"
			"\3" "0\0"
		    "PROBE\0"
			"\2" "probe\0"
			"\3" "0\0"
		    "STRING\0"
			"\2" "host_header\0"
			"\3" "\"\"\0"
		    "DURATION\0"
			"\2" "connect_timeout\0"
			"\3" "0\0"
		    "DURATION\0"
			"\2" "first_byte_timeout\0"
			"\3" "0\0"
		    "DURATION\0"
			"\2" "between_bytes_timeout\0"
			"\3" "0\0"
		    "INT\0"
			"\2" "max_connections\0"
			"\3" "0\0"
		    "INT\0"
			"\2" "proxy_header\0"
			"\3" "0\0"
		    "\0"
		"\0"

	    "marathon.server.application\0"
		"BACKEND\0"
		"Vmod_marathon_Func.server_application\0"
		    "STRING\0"
			"\2" "id\0"
			"\3" "\"\"\0"
		    "\0"
		"\0"

	    "\0",

	0
};
/*lint -restore */

/*lint -esym(759, Vmod_marathon_Data) */
const struct vmod_data Vmod_marathon_Data = {
	.vrt_major =	VRT_MAJOR_VERSION,
	.vrt_minor =	VRT_MINOR_VERSION,
	.name =		"marathon",
	.func =		&Vmod_Func,
	.func_len =	sizeof(Vmod_Func),
	.proto =	Vmod_Proto,
	.spec =		Vmod_Spec,
	.abi =		VMOD_ABI_Version,
	.file_id =	"JPCDOOZAWVQJVBBHUFPACS@FPDHBYZGD",
};
