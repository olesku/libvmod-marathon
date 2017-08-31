# libvmod-marathon

### Description
---
This module dynamically fetches applications from Marathon and makes them available as backends in your Varnish VCL.

It listens on Marathon's SSE eventbus and will ensures the backends is always kept in a consistent state without requiring to reload Varnish.

### Usage
---
``` new my_marathon = marathon.server(endpoint = "http://marathon.domain.tld",[default appconfig options]) ```

###### Available options

| Parameter             | Description                 | Default                |
|-----------------------|-----------------------------|------------------------|
| endpoint              | URL to Marathon             | Null (required)        |
| connect_timeout       | connect_timeout             | Varnish default        |
| first_byte_timeout    | first_byte_timeout          | Varnish default        |
| between_bytes_timeout | between_bytes_timeout       | Varnish default        |
| max_connections       | max_connections             | Varnish default        |

### Methods
``` .set_backend_config(id="/myapp", options) ```

###### Options

| Parameter             | Description                 | Default                |
|-----------------------|-----------------------------|------------------------|
| port_index            | Port index to use           | 0                      |
| probe                 | Varnish probe               | None                   |
| connect_timeout       | connect_timeout             | Varnish default        |
| first_byte_timeout    | first_byte_timeout          | Varnish default        |
| between_bytes_timeout | between_bytes_timeout       | Varnish default        |
| max_connections       | max_connections             | Varnish default        |


Set varnish backend parameters for "/myapp".



``` .backend("/myapp") ```

Returns a round-robin backend for the application with id /myapp in Marathon.

#### Example VCL
---
```
vcl 4.0;

import marathon;

backend dummy {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_init {
  new my_marathon = marathon.server("http://marathon.domain.tld");
}

sub vcl_recv {
  set req.backend_hint = my_marathon.backend(req.http.x-mesos-id);
  return(pass);
}

......
```
---
### Installation

Dependencies:
* [libcurl](https://curl.haxx.se/libcurl/) - the multiprotocol file transfer library.
* [yajl](https://lloyd.github.io/yajl/) - Yet Another JSON Library.


The source tree is based on autotools to configure the building.

Building requires the Varnish header files and uses pkg-config to find
the necessary paths.

```
 ./autogen.sh
 ./configure
```

If you have installed Varnish to a non-standard directory, call
``autogen.sh`` and ``configure`` with ``PKG_CONFIG_PATH`` pointing to
the appropriate path. For instance, when varnishd configure was called
with ``--prefix=$PREFIX``, use

 ```
 export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
 export ACLOCAL_PATH=${PREFIX}/share/aclocal
 ```

The module will inherit its prefix from Varnish, unless you specify a
different ``--prefix`` when running the ``configure`` script for this
module.

Make targets:

* make - builds the vmod.
* make install - installs your vmod.

```
 ./configure
 make
 make install
 ```