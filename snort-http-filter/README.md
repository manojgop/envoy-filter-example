# Envoy snort http filter

This project demonstrates the linking of additional filters with the Envoy binary.
A new filter `envoy.filters.http.snort` is introduced.

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //snort-http-filter:envoy`

## How it works

The [Envoy repository](https://github.com/envoyproxy/envoy/) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filter and `@envoy//source/exe:envoy_main_entry_lib`. The
`envoy.filters.http.snort` filter registers itself during the static initialization phase of the
Envoy binary as a new filter.

Envoy snort http filter can be used along with Snort process configured with Snort Envoy DAQ
Snort Envoy DAQ is in this [repository](https://github.com/intel-sandbox/ysaik.envoy_daq/tree/main)

## Run Snort with Snort Envoy DAQ
Refer this [ReadMe](https://github.com/intel-sandbox/ysaik.envoy_daq/blob/main/README.md)

We can run Snort with the following custom Snort3 rules. According to this rule,
snort will block any http request which has `secretkey` as http parameter.

`drop http any any -> any any ( msg:"HTTP parameter secretkey detected on http request"; flow:to_server,established; http_uri; http_param:"secretkey",nocase; sid:10000003; metadata:policy security-ips alert; )`

## Test filter with https->http proxy

1. Run a http hello world docker container in background as http server.

   `docker run --rm -dit -p 5050:80 strm/helloworld-http`

2. After building envoy static binary, execute following command from repo root directory in Terminal 1.

   `$(bazel info bazel-genfiles)/snort-http-filter/envoy --config-path ./snort-http-filter/yaml/envoy-https-http-snort.yaml --component-log-level filter:trace`

3. Execute following commands in terminal 2.

   `curl --proxy-insecure -x https://127.0.0.1:10000 http://strata.net -v`

   `curl --proxy-insecure -x https://127.0.0.1:10000 http://strata.net?secretkey=val/ -v`

4. Based on the configured rules Snort allowed one request and denied second request which has `secretkey` as http parameter.

5. Check stats. Execute following command in terminal 2

   `curl --noproxy '*' http://127.0.0.1:10001/stats | grep "log"`

   Following logs should be seen in Terminal 2.
   ```
   log.snort.http.allowed_request: 1
   log.snort.http.allowed_response: 2
   log.snort.http.denied_request: 1
   log.snort.http.denied_response: 0
   log.snort.http.total_request: 2
   log.snort.http.total_response: 2
   ```
