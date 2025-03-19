# Envoy snort http filter

This project demonstrates the linking of additional filters with the Envoy binary.
A new filter `snorthttp` is introduced.

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //snort-http-filter:envoy`

## How it works

The [Envoy repository](https://github.com/envoyproxy/envoy/) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filter and `@envoy//source/exe:envoy_main_entry_lib`. The
`snorthttp` filter registers itself during the static initialization phase of the
Envoy binary as a new filter.

## Test filter with https->http proxy

1. Run a http hello world docker container in background as http server.

   `docker run --rm -dit -p 5050:80 strm/helloworld-http`

2. After building envoy static binary, execute following command from repo root directory in Terminal 1.
   Snorthttp filter in yaml file is configured to allow request only from IPV4 address 127.0.0.1. Any traffic originating from other ip addresses will be denied. Note: This is a temporary configurtion used for testing. This can be removed if not required.

   `$(bazel info bazel-genfiles)/snort-http-filter/envoy --config-path ./snort-http-filter/yaml/envoy-https-http-snort.yaml --component-log-level filter:trace`

3. Execute following commands in terminal 2. Replace `143.182.136.128` with IP address of your
   n/w interface.

   `curl --proxy-insecure -x https://127.0.0.1:10000 http://strata.net?secretkey=val/ -v`

   `curl --proxy-insecure -x https://143.182.136.128:10000 http://strata.net?secretkey=val/ -v`

4. Check stats. Execute following command in terminal 2

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

5. After existing the envoy proxy in Terminal 1 (by typing ctrl-c), a file `output.pcap` will be created.
   The file can be viewed using utilitis like tcpdump (`tcpdump -r output.pcap -A`) or wireshark.

6. The pcap file can be anlayzed using [snort](https://github.com/snort3/snort3/tree/master?tab=readme-ov-file#run-snort). For example, add the following rules in snort local.rules file

```
alert tcp any any -> any 10000 ( msg:"TCP request to port 10000"; flow:to_server; sid:10000001; )
alert http any any -> any 10000 ( msg:"HTTP GET request to port 10000"; flow:to_server; http_method; content:"GET"; sid:10000002; )
alert http any any -> any any ( msg:"HTTP parameter secretkey detected on http request"; flow:to_server; http_uri; http_param:"secretkey",nocase; sid:10000003; metadata:policy security-ips alert; )
```

7. Run Snort to anlayze `output.pcap` file with configured rules. Replace `$my_path` with path of snort binary.

`$my_path/bin/snort -c ~/snort/build/etc/snort/snort.lua -R local.rules -r output.pcap -A alert_fast -s 65535 -k none`

If everything works properly, we should output similar to the following

```
03/11-08:38:09.196346 [**] [1:10000006:0] "TCP request to port 10000" [**] [Priority: 0] {TCP} 127.0.0.1:34500 -> 127.0.0.1:10000
03/11-08:38:09.196346 [**] [1:10000007:0] "HTTP GET request to port 10000" [**] [Priority: 0] {TCP} 127.0.0.1:34500 -> 127.0.0.1:10000
03/11-08:38:09.196346 [**] [1:10000003:0] "HTTP parameter secretkey detected on http request" [**] [Priority: 0] {TCP} 127.0.0.1:34500 -> 127.0.0.1:10000
``
