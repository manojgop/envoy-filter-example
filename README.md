# Envoy filter example

This project demonstrates the linking of additional filters with the Envoy binary.
A new filter `echo2` is introduced, identical modulo renaming to the existing
[`echo`](https://github.com/envoyproxy/envoy/blob/master/source/extensions/filters/network/echo/echo.h)
filter. Integration tests demonstrating the filter's end-to-end behavior are
also provided.

For an example of additional HTTP filters, see [here](http-filter-example).

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/envoyproxy/envoy-filter-example/badge)](https://securityscorecards.dev/viewer/?uri=github.com/envoyproxy/envoy-filter-example)

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //:envoy`

## Testing

To run the `echo2` integration test:

`bazel test //:echo2_integration_test`

To run the regular Envoy tests from this project:

`bazel test @envoy//test/...`

## How it works

The [Envoy repository](https://github.com/envoyproxy/envoy/) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filter and `@envoy//source/exe:envoy_main_entry_lib`. The
`echo2` filter registers itself during the static initialization phase of the
Envoy binary as a new filter.

## Test echo filter standalone

1. After building envoy static binary, execute following command from repo root directory in Terminal 1
   `$(bazel info bazel-genfiles)/envoy --config-path echo2_server.yaml --component-log-level filter:trace`

2. Execute below command in terminal 2
   `echo "test" | nc 127.0.0.1 10002`

## Test echo filter with rbac filter

1. RBAC filter is configured to allow request only from IPV4 address 127.0.0.1. Any traffic
   originating from other ip addresses will be denied.

2. Execute following command from repo root directory in Terminal 1. Enable debug logs in rbac
   filter and trace log in echo filter.
   `$(bazel info bazel-genfiles)/envoy --config-path rbac_echo2.yaml --component-log-level rbac:debug,filter:trace`

3. From Terminal 2, Try directly connecting to listener to address http://127.0.0.1:1002 via curl using
   following command
   `curl --noproxy '*' -X POST -H "Content-Type: text/plain" -d "My test" http://127.0.0.1:10002 -v`

   Following logs should be seen in Terminal 1.
   ```
   [2025-02-11 05:59:46.572][3435892][debug][rbac] [external/envoy/source/extensions/filters/network/rbac/rbac_filter.cc:191] enforced allowed, matched policy allow
   [2025-02-11 05:59:46.572][3435892][trace][filter] [echo2.cc:26] [Tags: "ConnectionId":"6"] echo: got 132 bytes
   ```

4. From Terminal 2, Try connecting to listener to address http://127.0.0.1:1002 via curl
   using a proxy (use curl -x option). Use proxy address as IP address of another interface in your system (other than 127.0.0.1).
   `curl -X POST -H "Content-Type: text/plain" -d "My test" -x http://143.182.136.128:10002 http://127.0.0.1:10002 -v`

   Envoy RBAC filter will reject the traffic originiating from proxy IP address.
   Following logs should be seen in Terminal 1.
   ```
   [2025-02-11 05:57:01.022][3435871][debug][rbac] [external/envoy/source/extensions/filters/network/rbac/rbac_filter.cc:203] enforced denied, matched policy none
   ```

5. Execute the following command from Terminal 2 to get the statistics
   `curl --noproxy '*' http://127.0.0.1:10001/stats | grep "log"`

   Following logs should be seen in Terminal 2.
   ```
   log.echo2.received: 1
   log.rbac.allowed: 1
   log.rbac.denied: 1
   log.rbac.shadow_allowed: 0
   log.rbac.shadow_denied: 0
   ```

