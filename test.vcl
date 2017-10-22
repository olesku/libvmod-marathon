vcl 4.0;

import marathon;

backend dummy {
    .host = "127.0.0.1";
    .port = "8080";
}


probe whalesay_probe {
  .request =
    "GET / HTTP/1.1"
    "Host: www.vg.no"
    "User-Agent: varnish-probe"
    "Connection: close";

  .timeout = 10s;
  .interval = 5s;
  .window = 3;
  .threshold = 1;
}

sub vcl_init {
  new vg_marathon = marathon.server("http://marathon.int.vgnett.no");

  vg_marathon.set_backend_config(id = "/whalesay", probe = whalesay_probe );
}

sub vcl_recv {
  set req.backend_hint = vg_marathon.backend(req.http.x-mesos-id);
  return(hash);
}

sub vcl_backend_response {
  //set beresp.grace = 1h;
}
