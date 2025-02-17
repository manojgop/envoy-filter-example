# Envoy filter example

This project demonstrates the linking of additional filters with the Envoy binary.
A new filter `snort` is introduced.

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //snort-filter:envoy`

## How it works

The [Envoy repository](https://github.com/envoyproxy/envoy/) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filter and `@envoy//source/exe:envoy_main_entry_lib`. The
`snort` filter registers itself during the static initialization phase of the
Envoy binary as a new filter.

## Test filter with echo filter

1. Filter is configured to allow request only from IPV4 address 127.0.0.1. Any traffic
   originating from other ip addresses will be denied.

2. After building envoy static binary, execute following command from repo root directory in Terminal 1
   `$(bazel info bazel-genfiles)/snort-filter/envoy --config-path ./snort-filter/yaml/envoy-snort-echo.yaml --component-log-level filter:trace`

3. Execute following commands in terminal 2. Replace `143.182.136.128` with IP address of your
   n/w interface.
   `echo "test" | nc 143.182.136.128 10002`
   `echo "test" | nc 127.0.0.1 10002`

4. Check stats. Execute below commands in terminal 2
   `curl --noproxy '*' http://127.0.0.1:10001/stats | grep "log"`

   Following logs should be seen in Terminal 2.
   ```
   log.snort.allowed: 1
   log.snort.denied: 1
   log.snort.total: 2
   ```

## Test filter with https->http proxy

1. Filter is configured to allow request only from IPV4 address 127.0.0.1. Any traffic
   originating from other ip addresses will be denied. This network filter will execute after TLS decryption.

2. Execute following command from repo root directory in Terminal 1. Enable debug logs in
   filter and trace log in http filter.
   `$(bazel info bazel-genfiles)/snort-filter/envoy --config-path ./snort-filter/yaml/envoy-https-http-snort.yaml --component-log-level http:debug,filter:trace`

3. Run a http hello world docker container in background as http server.
   `docker run --rm -dit -p 5050:80 strm/helloworld-http`

4. Execute following commands in terminal 2. Replace `143.182.136.128` with IP address of your
   n/w interface.
   `curl --noproxy '*' -sk https://localhost:10000  -v`
   `curl --noproxy '*' -sk  https://143.182.136.128:10000 -v`

5. Check stats. Execute following commands in terminal 2
   `curl --noproxy '*' http://127.0.0.1:10001/stats | grep "log"`

   Following logs should be seen in Terminal 2.
   ```
   log.snort.allowed: 1
   log.snort.denied: 1
   log.snort.total: 2
   ```
