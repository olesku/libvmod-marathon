..
.. NB:  This file is machine generated, DO NOT EDIT!
..
.. Edit vmod.vcc and run make instead
..

.. role:: ref(emphasis)

.. _vmod_marathon(4):

=============
vmod_marathon
=============

-------------
Marathon VMOD
-------------

:Manual section: 4

SYNOPSIS
========

import marathon [from "path"] ;


CONTENTS
========

* server(STRING)

.. _obj_server:

server
------

::

	new OBJ = server(STRING marathon_endpoint="")

.. _func_server.setup_application:

server.setup_application
------------------------

::

	BOOL server.setup_application(STRING id="", INT port_index=0, PROBE probe=0, STRING host_header="", DURATION connect_timeout=0, DURATION first_byte_timeout=0, DURATION between_bytes_timeout=0, INT max_connections=0, INT proxy_header=0)

.. _func_server.application:

server.application
------------------

::

	BACKEND server.application(STRING id="")

