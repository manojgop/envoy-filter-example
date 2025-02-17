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
        ":snort_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
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
    name = "snort_lib",
    srcs = ["snort.cc"],
    hdrs = ["snort.h"],
    repository = "@envoy",
    deps = [
        ":pkg_cc_proto",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/stats:stats_interface",
        "@envoy//envoy/stats:stats_macros",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:cidr_range_lib",
    ],
)

envoy_cc_library(
    name = "snort_config",
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
