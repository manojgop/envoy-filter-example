package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":snort_http_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
    linkopts = ["-lpcap"],
)

api_proto_package(
    deps = [
        "@envoy_api//envoy/config/core/v3:pkg",
        "@envoy_api//envoy/type/v3:pkg",
        "@com_github_cncf_xds//udpa/annotations:pkg",
        "@com_google_googleapis//google/api/expr/v1alpha1:checked_proto",
        "@com_google_googleapis//google/api/expr/v1alpha1:syntax_proto",
    ],
)

envoy_cc_library(
    name = "pcap_lib",
    srcs = ["pcap_file_manager.cc", "daq_manager.cc"],
    hdrs = ["pcap_file_manager.h", "daq_manager.h"],
    repository = "@envoy",
    deps = [
        "//snort-http-filter/deps/libpcap:libpcap",
        "@envoy//source/common/common:logger_lib",
    ],
)

envoy_cc_library(
    name = "snort_lib",
    srcs = ["snort_http.cc", "analyzer.cc"],
    hdrs = ["snort_http.h", "analyzer.h"],
    repository = "@envoy",
    deps = [
        ":pkg_cc_proto",
        ":pcap_lib",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/http:codes_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/stats:stats_interface",
        "@envoy//envoy/stats:stats_macros",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/http:codes_lib",
        "@envoy//source/common/event:dispatcher_lib",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",

    ],
)

envoy_cc_library(
    name = "snort_http_config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    repository = "@envoy",
    deps = [
        ":snort_lib",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry:registry",
        "@envoy//envoy/server:filter_config_interface",
    ],
)
