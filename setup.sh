#!/bin/sh
# Downloads the two header-only libraries (cpp-httplib, nlohmann/json)
cd "$(dirname "$0")/backend/include"
curl -sSLO https://raw.githubusercontent.com/yhirose/cpp-httplib/v0.18.3/httplib.h
curl -sSL https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp -o nlohmann/json.hpp
