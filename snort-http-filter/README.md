# Envoy snort http filter

This project demonstrates the linking of additional filters with the Envoy binary.
A new filter `envoy.filters.http.snort` is introduced.

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. (Optional): Use preferred envoy version `cd envoy && git checkout v1.33.0`
3. `bazel build //snort-http-filter:envoy`

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

   `docker run --rm -d -p 5050:80 strm/helloworld-http`

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
## Run performance test

### Build Envoy with optimization
To run peformance test build envoy using clang with optimization enabled.
(Note: There are build error if we build envoy using gcc with optimization)
Refer [Build Envoy with bazel and clang](https://github.com/envoyproxy/envoy/blob/main/bazel/README.md#linux)

For example, is clang-14 is installed at path /usr/lib/llvm-14, use following commands

```
source ./envoy/bazel/setup_clang.sh /usr/lib/llvm-14
echo "build --config=clang" >> user.bazelrc
bazel build -c opt //snort-http-filter:envoy
```

### Performance test with wrk tool
To run performance test with wrk tool, we need to use lua script to connect with envoy proxy

1. Install the following packages

   ```
   sudo apt-get install luarocks
   sudo luarocks install luasocket
   sudo luarocks install luasec
   sudo luarocks install lua-cjson
   ```

2. Set LUA_PATH. Please note the last two `;;` at the end to search for   standard lua path in the system.

   `export LUA_PATH="/<path>/lua/?.lua;;"`

3. Run a http hello world docker container in background as http server.

   `docker run --rm -d -p 5050:80 strm/helloworld-http`

4. To run http POST tests, run post http server which can be found in [`httpserver`](./test/httpserver/)

   `docker run --rm -d -p 5000:80 http-post-server-img`

5. After building envoy static binary, execute following command from repo root directory in Terminal 1.

   `./bazel-bin/snort-http-filter/envoy --config-path ./snort-http-filter/yaml/envoy-post-https-http-snort.yaml --component-log-level filter:trace`

6. Set the PATH for PROXY_URL : `export PROXY_URL=https://143.182.136.143:10000`

7. Run http GET performance test using wrk tool

   `wrk -t10 -c10 -d1s -s ./lua/proxy_get.lua $PROXY_URL -- http://strata.net`

### Another approach with wrk tool and iptables rule

1. Create new user “test” (assume there is already a default user “ubuntu”):

`sudo useradd test -m -s /bin/bash -u 10000`

2. Set up iptables rule, redirect the traffic from user “test” to envoy proxy.
   In the command below, replace `143.182.136.143` with the IP address of envoy proxy.

`sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 10000 -j DNAT --to-destination 143.182.136.143:10000`

3. Copy the envoy proxy public certificate. This is the cerificate used in `yaml/envoy-post-https-http-snort.yaml`

`sudo cp test/envoy-proxy.pem /etc/ssl/certs/`

4. Run http GET performance test using wrk tool. The traffic will be redirect to envoy since we have iptables rule applied

`./wrk -t10 -c10 -d1s https://strata.net/`
