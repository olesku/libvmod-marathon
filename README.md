# libvmod-marathon

### Description
---
This module dynamically fetches backends from Marathon applications and makes them available in your Varnish VCL.

It listens on Marathon's SSE eventbus and update configured applications as their status changes without requiring to reload Varnish.

### Methods
---
``` .add_application(id = "/myapp", options) ```

Configures application settings and must be called in vcl_init() for every application you are going to use as backend.


###### Avialable options

| Parameter             | Description                 | Default                |
|-----------------------|-----------------------------|------------------------|
| id                    | Application ID in Marathon  | Null (required)        |
| port_index            | Port index to use           | 0                      |
| probe                 | Probe to assign             | none                   |
| host_header           | Host header                 | Null                   |
| connect_timeout       | connect_timeout             | Varnish default        |
| first_byte_timeout    | first_byte_timeout          | Varnish default        |
| between_bytes_timeout | between_bytes_timeout       | Varnish default        |
| max_connections       | max_connections             | Varnish default        |
| proxy_header          | proxy_header                | 0                      |

``` .backend("/myapp") ```

Returns a round-robin backend for the application /myapp.

#### Example VCL
---
```
vcl 4.0;

import marathon;

sub vcl_init {
  # Initialize marathon handler.

  new my_marathon = marathon.init("http://marathon.mydomain.tld");

  # Setup applications we are going to use.
  # A call to add_application is required for all applications you are going to use as backends.

   my_marathon.add_application("/hello-world");
   my_marathon.add_application("/myapp");
}

sub vcl_recv {
  if (req.http.Host == "hello.mydomain.tld") {
    set req.backend_hint =  my_marathon.backend("/hello-world");
  } else {
    set req.backend_hint = my_marathon.backend("/myapp");
  }
  return(pass);
}

...
```