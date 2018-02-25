# libvmod-marathon

### Description
---
This module dynamically fetches applications from Mesosphere [Marathon](https://mesosphere.github.io/marathon/) and makes them available as backends in your Varnish VCL.

It monitors Marathon's SSE eventbus and makes sure that the backends is always kept in a consistent state without requiring to reload Varnish.

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
| proxy_header          | proxy_header                | Varnish default        |

### Object methods
***``` .set_backend_config(id="/myapp", options) ```***

###### Options
| Parameter             | Description                 | Default                |
|-----------------------|-----------------------------|------------------------|
| port_index            | Port index to use           | 0                      |
| probe                 | Varnish probe               | None                   |
| connect_timeout       | connect_timeout             | Varnish default        |
| first_byte_timeout    | first_byte_timeout          | Varnish default        |
| between_bytes_timeout | between_bytes_timeout       | Varnish default        |
| max_connections       | max_connections             | Varnish default        |
| proxy_header          | proxy_header                | Varnish default        |

Set varnish backend parameters for "/myapp".


***``` .backend_by_id(<id>) ```***
Returns a round-robin backend for the application with the given id in Marathon.

***``` .backend_by_label(<labelName>, <labelValue>) ```***
Returns a round-robin backend for the application with the label <labelName> matching <labelValue> in Marathon.

***``` .json_stats() ```***
Returns JSON with current backend configuration.

***``` .reload() ```***
Reload the module.

---
#### Debug logging
Debug logging to syslog can be enable with ``` marathon.debug_log(1); ```

#### Healthchecks
If an application has healthchecks configured in Marathon the module will respect it and only send traffic to tasks marked as healthy by Marathon.

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
  // Enable debug logging.
  marathon.debug_log(1);

  // Connect to Marathon.
  new my_marathon = marathon.server("http://marathon.domain.tld");
}

sub vcl_recv {
  // Set up a endpoint to show backend information.
  if (req.url ~ "^/vmod-marathon.json$") {
    return(synth(700, "OK"));
  }

  // Route traffic to myapp.mysite.tld to application with Marathon ID /myapp.
  if (req.http.Host == "myapp.mysite.tld") {
    set req.backend_hint = my_marathon.backend_by_id("/myapp");
  }

  // Route all other traffic to application in Marathon with label loadbalancer.host matching req.http.Host
  elsif (req.http.Host) {
    set req.backend_hint = my_marathon.backend_by_label("loadbalancer.host", req.http.Host);
  }

  return(pass);
}

sub vcl_synth {
  // Handle statistics endpoint.
  if (resp.status == 700) {
    set resp.status = 200;
    set resp.http.Content-Type = "application/json; charset=utf-8";
    synthetic(vg_marathon.json_stats());
    return(deliver);
  }
}
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
