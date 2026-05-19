cmake_minimum_required(VERSION 4.3.2)
cmake_policy(VERSION 4.3.2)

project(quicperf VERSION 0.1.2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

option(QUICPERF_NATIVE "Build quicperf-controlled code for the local CPU" ON)
option(QUICPERF_LTO "Enable link-time optimization for release builds" ON)

if(QUICPERF_LTO)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()

option(BUILD_PICOPERF "Build picoquic benchmark" ON)
option(BUILD_LSPERF "Build LSQUIC benchmark" ON)
option(BUILD_QUICHEPERF "Build quiche benchmark" ON)
option(BUILD_NGTCP2PERF "Build ngtcp2 benchmark" ON)
option(BUILD_TCPPERF "Build TCP+TLS benchmark" ON)
option(BUILD_TQUICPERF "Build TQUIC benchmark" ON)
option(BUILD_XQUICPERF "Build XQUIC benchmark" ON)
option(BUILD_QUINNPERF "Build Quinn benchmark" ON)
option(BUILD_NOQPERF "Build noq benchmark" ON)
option(BUILD_NEQOPERF "Build Neqo benchmark" ON)
option(BUILD_S2NPERF "Build s2n-quic benchmark" ON)
option(BUILD_QUICZIGPERF "Build quic-zig benchmark" ON)
option(BUILD_MVFSTPERF "Build mvfst benchmark" ON)

add_custom_target(quicperf_audit_cpp_io_boundary ALL
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/tools/audit-cpp-io-boundary.sh"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMENT "Auditing that measured QUIC UDP I/O is owned by the shared C++ NetworkHub"
  VERBATIM
)

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND AND (BUILD_QUINNPERF OR BUILD_NOQPERF OR BUILD_NEQOPERF OR BUILD_S2NPERF))
  pkg_check_modules(NSS QUIET IMPORTED_TARGET nss)
  pkg_check_modules(NSPR QUIET IMPORTED_TARGET nspr)
endif()

if(BUILD_NEQOPERF AND (NOT TARGET PkgConfig::NSS OR NOT TARGET PkgConfig::NSPR))
  message(FATAL_ERROR "BUILD_NEQOPERF requires pkg-config modules nss and nspr")
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/.depos.cmake")

set(QUICPERF_DEPOFILES)

function(quicperf_require_depofile name)
  list(APPEND QUICPERF_DEPOFILES "${CMAKE_CURRENT_SOURCE_DIR}/depofiles/${name}.DepoFile")
  set(QUICPERF_DEPOFILES "${QUICPERF_DEPOFILES}" PARENT_SCOPE)
endfunction()

if(BUILD_PICOPERF)
  quicperf_require_depofile(openssl)
  quicperf_require_depofile(picotls)
  quicperf_require_depofile(picoquic)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_LSPERF)
  quicperf_require_depofile(boringssl)
  quicperf_require_depofile(zlib)
  quicperf_require_depofile(lsquic)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_QUICHEPERF)
  quicperf_require_depofile(quiche)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_NGTCP2PERF)
  quicperf_require_depofile(boringssl)
  quicperf_require_depofile(ngtcp2)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_TCPPERF)
  quicperf_require_depofile(boringssl)
endif()

if(BUILD_TQUICPERF)
  quicperf_require_depofile(tquic)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_XQUICPERF)
  quicperf_require_depofile(xquic)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_QUINNPERF OR BUILD_NOQPERF OR BUILD_NEQOPERF OR BUILD_S2NPERF)
  quicperf_require_depofile(boringssl)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_QUICZIGPERF)
  quicperf_require_depofile(quiczig)
  quicperf_require_depofile(boringssl)
  quicperf_require_depofile(liburing)
endif()

if(BUILD_MVFSTPERF)
  quicperf_require_depofile(mvfst)
  quicperf_require_depofile(liburing)
endif()

if(QUICPERF_DEPOFILES)
  list(REMOVE_DUPLICATES QUICPERF_DEPOFILES)
  depos_depend(FILES ${QUICPERF_DEPOFILES})
endif()

function(quicperf_target target_name compile_define)
  add_executable(${target_name} perf.cpp)
  target_compile_definitions(${target_name} PRIVATE ${compile_define})
  target_compile_features(${target_name} PRIVATE cxx_std_20)
  set(native_flags)
  if(QUICPERF_NATIVE)
    list(APPEND native_flags -march=native)
  endif()
  target_compile_options(${target_name} PRIVATE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-O3;${native_flags};-Wall;-Wextra;-Wno-unused-parameter>
  )
  target_link_libraries(${target_name} PRIVATE Threads::Threads)
endfunction()

if(BUILD_PICOPERF)
  quicperf_target(picoperf PICOPERF)
  target_sources(picoperf PRIVATE perf.picoquic_seed.c)
  target_include_directories(picoperf PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/.depos/.root/downloads/picoquic/release/master-2b1e14d/src/picoquic"
  )
  depos_link(picoperf PRIVATE picoquic liburing)
  target_link_libraries(picoperf PRIVATE dl)
endif()

if(BUILD_LSPERF)
  quicperf_target(lsperf LSPERF)
  depos_link(lsperf PRIVATE lsquic liburing)
endif()

if(BUILD_QUICHEPERF)
  quicperf_target(quicheperf QUICHEPERF)
  depos_link(quicheperf PRIVATE quiche liburing)
  target_link_libraries(quicheperf PRIVATE dl)
endif()

if(BUILD_NGTCP2PERF)
  quicperf_target(ngtcp2perf NGTCP2PERF)
  depos_link(ngtcp2perf PRIVATE ngtcp2::crypto_boringssl liburing)
endif()

if(BUILD_TCPPERF)
  quicperf_target(tcpperf TCPPERF)
  depos_link(tcpperf PRIVATE boringssl)
endif()

if(BUILD_TQUICPERF)
  quicperf_target(tquicperf TQUICPERF)
  depos_link(tquicperf PRIVATE tquic::tquic liburing)
endif()

if(BUILD_XQUICPERF)
  quicperf_target(xquicperf XQUICPERF)
  target_link_options(xquicperf PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wl,--wrap=SSL_CTX_new>)
  depos_link(xquicperf PRIVATE xquic::xquic liburing)
endif()

if(BUILD_QUINNPERF OR BUILD_NOQPERF OR BUILD_NEQOPERF OR BUILD_S2NPERF)
  find_program(CARGO_EXECUTABLE cargo REQUIRED)
  set(QUICPERF_RUST_PACKET_FFI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rust-packet-ffi")
  set(QUICPERF_RUST_PACKET_FFI_LIB "${QUICPERF_RUST_PACKET_FFI_DIR}/target/release/libquicperf_rust_packet_ffi.a")
  set(QUICPERF_RUSTFLAGS "-C opt-level=3")
  if(QUICPERF_NATIVE)
    string(APPEND QUICPERF_RUSTFLAGS " -C target-cpu=native")
  endif()
  set(QUICPERF_RUST_CARGO_ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1)
  if(QUICPERF_LTO)
    list(APPEND QUICPERF_RUST_CARGO_ENV CARGO_PROFILE_RELEASE_LTO=fat)
  endif()
  add_custom_command(
    OUTPUT "${QUICPERF_RUST_PACKET_FFI_LIB}"
    COMMAND ${CMAKE_COMMAND} -E env
      ${QUICPERF_RUST_CARGO_ENV}
      "RUSTFLAGS=${QUICPERF_RUSTFLAGS}"
      "${CARGO_EXECUTABLE}" build --release --manifest-path "${QUICPERF_RUST_PACKET_FFI_DIR}/Cargo.toml"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS
      "${QUICPERF_RUST_PACKET_FFI_DIR}/Cargo.toml"
      "${QUICPERF_RUST_PACKET_FFI_DIR}/src/lib.rs"
      "${QUICPERF_RUST_PACKET_FFI_DIR}/include/quicperf_rust_packet_ffi.h"
    VERBATIM
  )
  add_custom_target(quicperf_rust_packet_ffi_build DEPENDS "${QUICPERF_RUST_PACKET_FFI_LIB}")
  add_library(quicperf_rust_packet_ffi STATIC IMPORTED GLOBAL)
  set_target_properties(quicperf_rust_packet_ffi PROPERTIES
    IMPORTED_LOCATION "${QUICPERF_RUST_PACKET_FFI_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${QUICPERF_RUST_PACKET_FFI_DIR}/include"
  )
  add_dependencies(quicperf_rust_packet_ffi quicperf_rust_packet_ffi_build)
endif()

if(BUILD_QUICZIGPERF)
  find_program(ZIG_EXECUTABLE zig HINTS "$ENV{HOME}/.local/zig/zig-x86_64-linux-0.16.0" REQUIRED)
  get_target_property(QUICPERF_QUIC_ZIG_SOURCE_DIR quiczig::source::interface INTERFACE_INCLUDE_DIRECTORIES)
  if(NOT QUICPERF_QUIC_ZIG_SOURCE_DIR)
    message(FATAL_ERROR "BUILD_QUICZIGPERF requires quiczig::source from depofiles/quiczig.DepoFile")
  endif()
  list(GET QUICPERF_QUIC_ZIG_SOURCE_DIR 0 QUICPERF_QUIC_ZIG_SOURCE_DIR)

  set(QUICPERF_ZIG_PACKET_FFI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/zig-packet-ffi")
  set(QUICPERF_ZIG_PACKET_FFI_LIB "${QUICPERF_ZIG_PACKET_FFI_DIR}/zig-out/lib/libquicperf_zig_packet_ffi.a")
  set(QUICPERF_ZIG_OPTIMIZE ReleaseFast)
  set(QUICPERF_ZIG_NATIVE_ARGS)
  if(QUICPERF_NATIVE)
    list(APPEND QUICPERF_ZIG_NATIVE_ARGS -Dtarget=native-native -Dcpu=native)
  endif()
  add_custom_command(
    OUTPUT "${QUICPERF_ZIG_PACKET_FFI_LIB}"
    COMMAND ${CMAKE_COMMAND} -E env
      "ZIG_GLOBAL_CACHE_DIR=${QUICPERF_ZIG_PACKET_FFI_DIR}/zig-global-cache"
      "${ZIG_EXECUTABLE}" build
        -Doptimize=${QUICPERF_ZIG_OPTIMIZE}
        ${QUICPERF_ZIG_NATIVE_ARGS}
        "-Dquic-src=${QUICPERF_QUIC_ZIG_SOURCE_DIR}"
    WORKING_DIRECTORY "${QUICPERF_ZIG_PACKET_FFI_DIR}"
    DEPENDS
      "${QUICPERF_ZIG_PACKET_FFI_DIR}/build.zig"
      "${QUICPERF_ZIG_PACKET_FFI_DIR}/build.zig.zon"
      "${QUICPERF_ZIG_PACKET_FFI_DIR}/src/lib.zig"
      "${QUICPERF_ZIG_PACKET_FFI_DIR}/include/quicperf_zig_packet_ffi.h"
    VERBATIM
  )
  add_custom_target(quicperf_zig_packet_ffi_build DEPENDS "${QUICPERF_ZIG_PACKET_FFI_LIB}")
  add_library(quicperf_zig_packet_ffi STATIC IMPORTED GLOBAL)
  set_target_properties(quicperf_zig_packet_ffi PROPERTIES
    IMPORTED_LOCATION "${QUICPERF_ZIG_PACKET_FFI_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${QUICPERF_ZIG_PACKET_FFI_DIR}/include"
  )
  add_dependencies(quicperf_zig_packet_ffi quicperf_zig_packet_ffi_build)
endif()

function(quicperf_rust_packet_target target_name compile_define)
  quicperf_target(${target_name} ${compile_define})
  add_dependencies(${target_name} quicperf_rust_packet_ffi_build)
  target_link_libraries(${target_name} PRIVATE quicperf_rust_packet_ffi dl pthread m)
  if(TARGET PkgConfig::NSS)
    target_link_libraries(${target_name} PRIVATE PkgConfig::NSS)
  endif()
  if(TARGET PkgConfig::NSPR)
    target_link_libraries(${target_name} PRIVATE PkgConfig::NSPR)
  endif()
  depos_link(${target_name} PRIVATE boringssl liburing)
endfunction()

if(BUILD_QUINNPERF)
  quicperf_rust_packet_target(quinnperf QUINNPERF)
endif()

if(BUILD_NOQPERF)
  quicperf_rust_packet_target(noqperf NOQPERF)
endif()

if(BUILD_NEQOPERF)
  quicperf_rust_packet_target(neqoperf NEQOPERF)
endif()

if(BUILD_S2NPERF)
  quicperf_rust_packet_target(s2nperf S2NPERF)
endif()

if(BUILD_QUICZIGPERF)
  quicperf_target(quiczigperf QUICZIGPERF)
  add_dependencies(quiczigperf quicperf_zig_packet_ffi_build)
  target_link_libraries(quiczigperf PRIVATE quicperf_zig_packet_ffi dl pthread m)
  depos_link(quiczigperf PRIVATE boringssl liburing)
endif()

if(BUILD_MVFSTPERF)
  quicperf_target(mvfstperf MVFSTPERF)
  target_compile_definitions(mvfstperf PRIVATE GLOG_USE_GLOG_EXPORT)
  depos_link(mvfstperf PRIVATE mvfst::mvfst liburing)
  target_link_libraries(mvfstperf PRIVATE iberty unwind unwind-x86_64 aio stdc++)
endif()

set(QUICPERF_PRIMARY_BENCHMARK_TARGETS)
foreach(QUICPERF_PRIMARY_TARGET IN ITEMS
  ngtcp2perf
  lsperf
  tquicperf
  quicheperf
  picoperf
  xquicperf
  quinnperf
  s2nperf
  neqoperf
  noqperf
  quiczigperf
  mvfstperf
)
  if(TARGET "${QUICPERF_PRIMARY_TARGET}")
    list(APPEND QUICPERF_PRIMARY_BENCHMARK_TARGETS "${QUICPERF_PRIMARY_TARGET}")
  endif()
endforeach()

if(QUICPERF_PRIMARY_BENCHMARK_TARGETS)
  string(REPLACE ";" " " QUICPERF_PRIMARY_BENCHMARK_BINARIES "${QUICPERF_PRIMARY_BENCHMARK_TARGETS}")
  add_custom_target(quicperf_mechanism_smoke
    COMMAND ${CMAKE_COMMAND} -E env
      "QUICPERF_BIN_DIR=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
      "QUICPERF_MECHANISM_SMOKE_BINARIES=${QUICPERF_PRIMARY_BENCHMARK_BINARIES}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tools/run-mechanism-workload-smoke.sh"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS ${QUICPERF_PRIMARY_BENCHMARK_TARGETS}
    COMMENT "Smoke testing the ten all-primary QUIC mechanism workloads"
    VERBATIM
  )
endif()
