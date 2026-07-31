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

find_package(Threads REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
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
  quicperf_require_depofile(quinnsource)
  quicperf_require_depofile(noqsource)
  quicperf_require_depofile(neqosource)
  quicperf_require_depofile(s2nsource)
  quicperf_require_depofile(nssrssource)
  quicperf_require_depofile(nssquicperf)
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
  _depos_ensure_registry_ready()
endif()

set(QUICPERF_QUIC_ZIG_AUDIT_SOURCE DISABLED)
if(BUILD_QUICZIGPERF)
  get_target_property(QUICPERF_QUIC_ZIG_AUDIT_SOURCE
    quiczig::source::interface INTERFACE_INCLUDE_DIRECTORIES)
  list(GET QUICPERF_QUIC_ZIG_AUDIT_SOURCE 0 QUICPERF_QUIC_ZIG_AUDIT_SOURCE)
endif()
add_custom_target(quicperf_audit_cpp_io_boundary ALL
  COMMAND ${CMAKE_COMMAND} -E env
    "QUICPERF_QUIC_ZIG_EFFECTIVE_SOURCE=${QUICPERF_QUIC_ZIG_AUDIT_SOURCE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/audit-cpp-io-boundary.sh"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMENT "Auditing that measured QUIC UDP I/O is owned by the shared C++ NetworkHub"
  VERBATIM
)

add_executable(quicperf-amd-stability-probe src/amd_stability_probe.cpp)
target_compile_features(quicperf-amd-stability-probe PRIVATE cxx_std_20)
target_compile_options(quicperf-amd-stability-probe PRIVATE
  $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-O3;-Wall;-Wextra>
  $<$<AND:$<CONFIG:Release>,$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>>:-DNDEBUG>
)

add_library(quicperf-monitor-spin SHARED src/monitor_spin.c)
set_target_properties(quicperf-monitor-spin PROPERTIES
  PREFIX ""
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
target_compile_options(quicperf-monitor-spin PRIVATE
  $<$<COMPILE_LANG_AND_ID:C,GNU,Clang>:-O3;-Wall;-Wextra>
  $<$<AND:$<CONFIG:Release>,$<COMPILE_LANG_AND_ID:C,GNU,Clang>>:-DNDEBUG>
)

add_executable(quicperf-runtime-monitor src/runtime_boundary_monitor.cpp)
target_compile_features(quicperf-runtime-monitor PRIVATE cxx_std_20)
target_include_directories(quicperf-runtime-monitor PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_options(quicperf-runtime-monitor PRIVATE
  $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-O2;-Wall;-Wextra>
  $<$<AND:$<CONFIG:Release>,$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>>:-DNDEBUG>
)
depos_link(quicperf-runtime-monitor PRIVATE openssl)

add_library(quicperf_core STATIC
  src/core/control_protocol.cpp
  src/core/event_loop.cpp
  src/core/measurement.cpp
  src/core/negotiated_settings.cpp
  src/core/path_loss.cpp
  src/core/packet_io.cpp
  src/core/packet_io_syscall.cpp
  src/core/packet_io_uring.cpp
  src/core/result.cpp
  src/core/runtime_ownership.cpp
  src/core/strict_config.cpp
  src/core/timer_queue.cpp
  src/core/workload_engine.cpp
  src/core/workload_protocol.cpp
  src/workloads/connection_lifecycle.cpp
  src/workloads/datagram.cpp
  src/workloads/idle_memory.cpp
  src/workloads/request_response.cpp
  src/workloads/stream_lifecycle.cpp
  src/workloads/transfer.cpp
)
target_compile_features(quicperf_core PUBLIC cxx_std_20)
target_include_directories(quicperf_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_options(quicperf_core PRIVATE
  $<$<AND:$<CONFIG:Release>,$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>>:-O3;-DNDEBUG;-march=native;-mtune=native;-flto=auto;-Wall;-Wextra>
)
target_link_libraries(quicperf_core PUBLIC Threads::Threads)
depos_link(quicperf_core PRIVATE liburing)

function(quicperf_runtime_audit_link target_name)
  target_link_options(${target_name} PRIVATE
    $<$<PLATFORM_ID:Linux>:-Wl,--wrap=clock_gettime,--wrap=gettimeofday,--wrap=time,--wrap=dlsym,--wrap=_ZNSt6chrono3_V212system_clock3nowEv>)
  target_link_libraries(${target_name} PRIVATE dl)
endfunction()

function(quicperf_target target_name compile_define adapter_source)
  add_executable(${target_name} perf.cpp src/main.cpp "src/adapters/${adapter_source}")
  target_compile_definitions(${target_name} PRIVATE ${compile_define})
  target_compile_features(${target_name} PRIVATE cxx_std_20)
  set(native_flags)
  if(QUICPERF_NATIVE)
    list(APPEND native_flags -march=native)
  endif()
  target_compile_options(${target_name} PRIVATE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-O3;${native_flags};-mtune=native;-Wall;-Wextra;-Wno-unused-parameter>
    $<$<AND:$<CONFIG:Release>,$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>>:-DNDEBUG;-flto=auto>
  )
  target_link_libraries(${target_name} PRIVATE quicperf_core Threads::Threads)
  quicperf_runtime_audit_link(${target_name})
endfunction()

if(BUILD_PICOPERF)
  quicperf_target(picoperf PICOPERF picoquic_adapter.cpp)
  target_sources(picoperf PRIVATE perf.picoquic_seed.c)
  target_link_libraries(picoperf PRIVATE dl)
  depos_link(picoperf PRIVATE picoquic::picoquic liburing)
endif()

if(BUILD_LSPERF)
  quicperf_target(lsperf LSPERF lsquic_adapter.cpp)
  depos_link(lsperf PRIVATE lsquic::lsquic liburing)
endif()

if(BUILD_QUICHEPERF)
  quicperf_target(quicheperf QUICHEPERF quiche_adapter.cpp)
  depos_link(quicheperf PRIVATE quiche liburing)
  target_link_libraries(quicheperf PRIVATE dl)
endif()

if(BUILD_NGTCP2PERF)
  quicperf_target(ngtcp2perf NGTCP2PERF ngtcp2_adapter.cpp)
  depos_link(ngtcp2perf PRIVATE ngtcp2::crypto_boringssl liburing)
endif()

if(BUILD_TCPPERF)
  quicperf_target(tcpperf TCPPERF tcp_adapter.cpp)
  depos_link(tcpperf PRIVATE boringssl)
endif()

if(BUILD_TQUICPERF)
  quicperf_target(tquicperf TQUICPERF tquic_adapter.cpp)
  depos_link(tquicperf PRIVATE tquic::tquic liburing)
endif()

if(BUILD_XQUICPERF)
  quicperf_target(xquicperf XQUICPERF xquic_adapter.cpp)
  target_link_options(xquicperf PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wl,--wrap=SSL_CTX_new>)
  depos_link(xquicperf PRIVATE xquic::xquic liburing)
endif()

if(BUILD_QUINNPERF OR BUILD_NOQPERF OR BUILD_NEQOPERF OR BUILD_S2NPERF)
  find_program(CARGO_EXECUTABLE cargo REQUIRED)
  set(QUICPERF_RUST_PACKET_FFI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rust-packet-ffi")

  function(quicperf_depofile_source output target)
    if(NOT TARGET "${target}")
      message(FATAL_ERROR "Rust packet build requires Depofile target ${target}")
    endif()
    get_target_property(paths "${target}" INTERFACE_INCLUDE_DIRECTORIES)
    if(NOT paths)
      message(FATAL_ERROR "Depofile source target ${target} has no exported path")
    endif()
    list(GET paths 0 path)
    set("${output}" "${path}" PARENT_SCOPE)
  endfunction()

  quicperf_depofile_source(
    QUICPERF_QUINN_SOURCE_DIR quinnsource::source::interface)
  quicperf_depofile_source(
    QUICPERF_NOQ_SOURCE_DIR noqsource::source::interface)
  quicperf_depofile_source(
    QUICPERF_NEQO_SOURCE_DIR neqosource::source::interface)
  quicperf_depofile_source(
    QUICPERF_S2N_SOURCE_DIR s2nsource::source::interface)
  quicperf_depofile_source(
    QUICPERF_NSS_RS_SOURCE_DIR nssrssource::source::interface)
  quicperf_depofile_source(
    QUICPERF_NSS_SOURCE_DIR nssquicperf::source::interface)

  get_filename_component(QUICPERF_NSS_TREE_DIR
    "${QUICPERF_NSS_SOURCE_DIR}" DIRECTORY)
  set(QUICPERF_NSS_LIB_DIR "${QUICPERF_NSS_TREE_DIR}/dist/Release/lib")
  set(QUICPERF_NSPR_INCLUDE_DIR
    "${QUICPERF_NSS_SOURCE_DIR}/quicperf-nspr-headers")

  add_library(quicperf_nss_runtime INTERFACE)
  target_link_libraries(quicperf_nss_runtime INTERFACE
    nssquicperf::ssl
    nssquicperf::softokn
    nssquicperf::freeblpriv
    nssquicperf::sqlite)

  set(QUICPERF_RUST_PATCH_CONFIG
    "${CMAKE_CURRENT_BINARY_DIR}/rust-packet-patches.toml")
  file(WRITE "${QUICPERF_RUST_PATCH_CONFIG}"
    "[patch.\"https://github.com/victorstewart/quinn.git\"]\n"
    "quinn-proto = { path = \"${QUICPERF_QUINN_SOURCE_DIR}/quinn-proto\" }\n"
    "[patch.\"https://github.com/victorstewart/noq.git\"]\n"
    "noq-proto = { path = \"${QUICPERF_NOQ_SOURCE_DIR}/noq-proto\" }\n"
    "[patch.\"https://github.com/victorstewart/neqo.git\"]\n"
    "neqo-common = { path = \"${QUICPERF_NEQO_SOURCE_DIR}/neqo-common\" }\n"
    "neqo-transport = { path = \"${QUICPERF_NEQO_SOURCE_DIR}/neqo-transport\" }\n"
    "[patch.\"https://github.com/victorstewart/s2n-quic.git\"]\n"
    "s2n-quic = { path = \"${QUICPERF_S2N_SOURCE_DIR}/quic/s2n-quic\" }\n"
    "s2n-quic-core = { path = \"${QUICPERF_S2N_SOURCE_DIR}/quic/s2n-quic-core\" }\n"
    "[patch.\"https://github.com/mozilla/nss-rs\"]\n"
    "nss-rs = { path = \"${QUICPERF_NSS_RS_SOURCE_DIR}\" }\n")

  set(QUICPERF_RUST_PACKET_FFI_LIB
    "${QUICPERF_RUST_PACKET_FFI_DIR}/target/release/libquicperf_rust_packet_ffi.a")
  set(QUICPERF_RUSTFLAGS "-C opt-level=3")
  if(QUICPERF_NATIVE)
    string(APPEND QUICPERF_RUSTFLAGS " -C target-cpu=native")
  endif()
  set(QUICPERF_RUST_CARGO_ENV
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    CARGO_PROFILE_RELEASE_OPT_LEVEL=3
    CARGO_PROFILE_RELEASE_PANIC=abort
    CARGO_PROFILE_RELEASE_DEBUG=0
    CARGO_INCREMENTAL=0
    "NSS_DIR=${QUICPERF_NSS_SOURCE_DIR}"
    "BINDGEN_EXTRA_CLANG_ARGS=-I${QUICPERF_NSPR_INCLUDE_DIR}"
    NSS_PREBUILT=1)
  if(QUICPERF_LTO)
    list(APPEND QUICPERF_RUST_CARGO_ENV CARGO_PROFILE_RELEASE_LTO=fat)
  endif()

  file(GLOB_RECURSE QUICPERF_RUST_PACKET_FFI_INPUTS CONFIGURE_DEPENDS
    "${QUICPERF_RUST_PACKET_FFI_DIR}/src/*.rs"
    "${QUICPERF_RUST_PACKET_FFI_DIR}/include/*.h"
    "${QUICPERF_RUST_PACKET_FFI_DIR}/build.rs"
    "${QUICPERF_QUINN_SOURCE_DIR}/quinn-proto/*.rs"
    "${QUICPERF_NOQ_SOURCE_DIR}/noq-proto/*.rs"
    "${QUICPERF_NEQO_SOURCE_DIR}/neqo-common/*.rs"
    "${QUICPERF_NEQO_SOURCE_DIR}/neqo-transport/*.rs"
    "${QUICPERF_S2N_SOURCE_DIR}/quic/s2n-quic/*.rs"
    "${QUICPERF_S2N_SOURCE_DIR}/quic/s2n-quic-core/*.rs"
    "${QUICPERF_NSS_RS_SOURCE_DIR}/*.rs")
  add_custom_command(
    OUTPUT "${QUICPERF_RUST_PACKET_FFI_LIB}"
    COMMAND ${CMAKE_COMMAND} -E env
      ${QUICPERF_RUST_CARGO_ENV}
      "RUSTFLAGS=${QUICPERF_RUSTFLAGS}"
      "${CARGO_EXECUTABLE}" build --release
        --config "${QUICPERF_RUST_PATCH_CONFIG}"
        --manifest-path "${QUICPERF_RUST_PACKET_FFI_DIR}/Cargo.toml"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS
      "${QUICPERF_RUST_PACKET_FFI_DIR}/Cargo.toml"
      "${QUICPERF_RUST_PACKET_FFI_DIR}/Cargo.lock"
      ${QUICPERF_RUST_PACKET_FFI_INPUTS}
      "${QUICPERF_RUST_PATCH_CONFIG}"
    VERBATIM)
  add_custom_target(quicperf_rust_packet_ffi_build
    DEPENDS "${QUICPERF_RUST_PACKET_FFI_LIB}")
  add_library(quicperf_rust_packet_ffi STATIC IMPORTED GLOBAL)
  set_target_properties(quicperf_rust_packet_ffi PROPERTIES
    IMPORTED_LOCATION "${QUICPERF_RUST_PACKET_FFI_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${QUICPERF_RUST_PACKET_FFI_DIR}/include"
    INTERFACE_LINK_LIBRARIES quicperf_nss_runtime)
  add_dependencies(quicperf_rust_packet_ffi quicperf_rust_packet_ffi_build)
endif()

include(CTest)
if(BUILD_TESTING)
  add_executable(runtime_boundary_violation_fixture
    tests/runtime_boundary_violation_fixture.cpp)
  target_compile_features(runtime_boundary_violation_fixture PRIVATE cxx_std_20)
  target_link_libraries(runtime_boundary_violation_fixture PRIVATE
    quicperf_core Threads::Threads)
  depos_link(runtime_boundary_violation_fixture PRIVATE liburing)
  quicperf_runtime_audit_link(runtime_boundary_violation_fixture)
  add_test(
    NAME runtime_boundary_monitor_contract
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime_boundary_monitor_contract.py"
      --monitor "$<TARGET_FILE:quicperf-runtime-monitor>"
      --fixture "$<TARGET_FILE:runtime_boundary_violation_fixture>")

  add_executable(runtime_ownership_contract tests/runtime_ownership_contract.cpp)
  target_compile_features(runtime_ownership_contract PRIVATE cxx_std_20)
  target_link_libraries(runtime_ownership_contract PRIVATE quicperf_core Threads::Threads)
  quicperf_runtime_audit_link(runtime_ownership_contract)
  add_test(NAME runtime_ownership_contract COMMAND runtime_ownership_contract)

  add_executable(quicperf_control_protocol_contract tests/control_protocol_contract.cpp)
  target_link_libraries(quicperf_control_protocol_contract PRIVATE quicperf_core)
  add_test(NAME quicperf_control_protocol_contract COMMAND quicperf_control_protocol_contract)

  add_executable(quicperf_workload_protocol_contract tests/workload_protocol_contract.cpp)
  target_link_libraries(quicperf_workload_protocol_contract PRIVATE quicperf_core)
  add_test(NAME quicperf_workload_protocol_contract COMMAND quicperf_workload_protocol_contract)

  add_executable(quicperf_workload_barrier_contract tests/workload_barrier_contract.cpp)
  target_link_libraries(quicperf_workload_barrier_contract PRIVATE quicperf_core)
  add_test(NAME quicperf_workload_barrier_contract COMMAND quicperf_workload_barrier_contract)

  add_executable(quicperf_strict_config_contract tests/strict_config_contract.cpp)
  target_link_libraries(quicperf_strict_config_contract PRIVATE quicperf_core)
  add_test(NAME quicperf_strict_config_contract COMMAND quicperf_strict_config_contract)

  add_executable(quicperf_negotiated_settings_contract tests/negotiated_settings_contract.cpp)
  target_link_libraries(quicperf_negotiated_settings_contract PRIVATE quicperf_core)
  add_test(NAME quicperf_negotiated_settings_contract COMMAND quicperf_negotiated_settings_contract)

  add_executable(quicperf_packet_io_contract tests/packet_io_contract.cpp)
  target_link_libraries(quicperf_packet_io_contract PRIVATE quicperf_core)
  add_test(NAME quicperf_packet_io_contract COMMAND quicperf_packet_io_contract)
  set_tests_properties(quicperf_packet_io_contract PROPERTIES SKIP_RETURN_CODE 77)

  add_executable(quicperf_event_loop_contract tests/event_loop_contract.cpp)
  target_link_libraries(quicperf_event_loop_contract PRIVATE quicperf_core)
  add_test(NAME quicperf_event_loop_contract COMMAND quicperf_event_loop_contract)

  if(BUILD_NGTCP2PERF)
    add_executable(quicperf_ngtcp2_adapter_contract
      tests/ngtcp2_adapter_contract.cpp
      src/adapters/ngtcp2_adapter.cpp)
    target_compile_definitions(quicperf_ngtcp2_adapter_contract PRIVATE
      "QUICPERF_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
    target_compile_options(quicperf_ngtcp2_adapter_contract PRIVATE
      $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-UNDEBUG>)
    target_link_libraries(quicperf_ngtcp2_adapter_contract PRIVATE quicperf_core)
    depos_link(quicperf_ngtcp2_adapter_contract PRIVATE ngtcp2::crypto_boringssl)
    add_test(NAME quicperf_ngtcp2_adapter_contract COMMAND quicperf_ngtcp2_adapter_contract)
  endif()

  function(quicperf_native_packet_adapter_contract target_name library_name adapter_source)
    add_executable(${target_name}
      tests/native_packet_adapter_contract.cpp
      src/adapters/${adapter_source})
    target_compile_definitions(${target_name} PRIVATE
      "EXPECTED_LIBRARY=\"${library_name}\""
      "QUICPERF_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
    target_compile_options(${target_name} PRIVATE
      $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-UNDEBUG>)
    target_link_libraries(${target_name} PRIVATE quicperf_core)
    quicperf_runtime_audit_link(${target_name})
    add_test(NAME ${target_name} COMMAND ${target_name})
  endfunction()

  if(BUILD_PICOPERF)
    quicperf_native_packet_adapter_contract(
      quicperf_picoquic_adapter_contract picoquic picoquic_adapter.cpp)
    target_compile_definitions(quicperf_picoquic_adapter_contract PRIVATE
      EXPECT_PEER_TERMINAL_FACTS=1)
    depos_link(quicperf_picoquic_adapter_contract PRIVATE picoquic::picoquic)
  endif()

  if(BUILD_QUICHEPERF)
    quicperf_native_packet_adapter_contract(
      quicperf_quiche_adapter_contract quiche quiche_adapter.cpp)
    target_compile_definitions(quicperf_quiche_adapter_contract PRIVATE
      EXPECT_NEGOTIATED_EVIDENCE=1
      EXPECT_PENDING_ADMISSION_EVIDENCE=1
      EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
      EXPECT_PEER_TERMINAL_FACTS=1)
    depos_link(quicperf_quiche_adapter_contract PRIVATE quiche)
  endif()

  if(BUILD_TQUICPERF)
    quicperf_native_packet_adapter_contract(
      quicperf_tquic_adapter_contract tquic tquic_adapter.cpp)
    target_compile_definitions(quicperf_tquic_adapter_contract PRIVATE
      EXPECT_NEGOTIATED_EVIDENCE=1
      EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
      EXPECT_PEER_TERMINAL_FACTS=1
      EXPECT_RECOVERY_WAKEUP_COUNTER=1)
    depos_link(quicperf_tquic_adapter_contract PRIVATE tquic::tquic)
  endif()

  if(BUILD_LSPERF)
    quicperf_native_packet_adapter_contract(
      quicperf_lsquic_adapter_contract lsquic lsquic_adapter.cpp)
    target_compile_definitions(quicperf_lsquic_adapter_contract PRIVATE
      EXPECT_NEGOTIATED_EVIDENCE=1
      EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
      EXPECT_UNIDIRECTIONAL_STREAMS=0
      EXPECT_PEER_TERMINAL_FACTS=1)
    depos_link(quicperf_lsquic_adapter_contract PRIVATE lsquic::lsquic)
  endif()

  if(BUILD_XQUICPERF)
    quicperf_native_packet_adapter_contract(
      quicperf_xquic_adapter_contract xquic xquic_adapter.cpp)
    target_sources(quicperf_xquic_adapter_contract PRIVATE tests/xquic_ssl_wrapper.cpp)
    target_compile_definitions(quicperf_xquic_adapter_contract PRIVATE
      EXPECT_CONNECTION_ADMISSION_LIMIT=1
      EXPECT_EFFECTIVE_EARLY_DATA_CAP=1
      EXPECT_NEGOTIATED_EVIDENCE=1
      EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
      EXPECT_PEER_TERMINAL_FACTS=1)
    target_link_options(quicperf_xquic_adapter_contract PRIVATE
      $<$<CXX_COMPILER_ID:GNU,Clang>:-Wl,--wrap=SSL_CTX_new>)
    depos_link(quicperf_xquic_adapter_contract PRIVATE xquic::xquic)
  endif()

  if(BUILD_MVFSTPERF)
    add_executable(quicperf_mvfst_adapter_contract
      tests/native_packet_adapter_contract.cpp
      src/adapters/mvfst_adapter.cpp)
    target_compile_definitions(quicperf_mvfst_adapter_contract PRIVATE
      "EXPECTED_LIBRARY=\"mvfst\""
      EXPECT_EARLY_DATA=1
      EXPECT_NEGOTIATED_EVIDENCE=1
      EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
      EXPECT_PEER_TERMINAL_FACTS=1
      EXPECT_RECOVERY_WAKEUP_COUNTER=1
      GLOG_USE_GLOG_EXPORT
      "QUICPERF_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
    target_compile_options(quicperf_mvfst_adapter_contract PRIVATE
      $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-UNDEBUG>)
    target_link_libraries(quicperf_mvfst_adapter_contract PRIVATE quicperf_core)
    depos_link(quicperf_mvfst_adapter_contract PRIVATE
      mvfst::mvfst fizz::fizz folly::folly fmt::fmt gflags::gflags glog::glog openssl)
    target_link_libraries(quicperf_mvfst_adapter_contract PRIVATE
      iberty unwind unwind-x86_64 aio stdc++)
    add_test(NAME quicperf_mvfst_adapter_contract COMMAND quicperf_mvfst_adapter_contract)
  endif()
endif()

if(BUILD_QUICZIGPERF)
  find_program(ZIG_EXECUTABLE zig
    HINTS "$ENV{HOME}/.local/zig/zig-x86_64-linux-0.16.0" REQUIRED)
  get_target_property(QUICPERF_QUIC_ZIG_SOURCE_DIR
    quiczig::source::interface INTERFACE_INCLUDE_DIRECTORIES)
  if(NOT QUICPERF_QUIC_ZIG_SOURCE_DIR)
    message(FATAL_ERROR
      "BUILD_QUICZIGPERF requires patched quiczig::source from its Depofile")
  endif()
  list(GET QUICPERF_QUIC_ZIG_SOURCE_DIR 0 QUICPERF_QUIC_ZIG_SOURCE_DIR)

  set(QUICPERF_ZIG_PACKET_FFI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/zig-packet-ffi")
  set(QUICPERF_ZIG_PACKET_FFI_LIB
    "${QUICPERF_ZIG_PACKET_FFI_DIR}/zig-out/lib/libquicperf_zig_packet_ffi.a")
  set(QUICPERF_ZIG_OPTIMIZE ReleaseFast)
  set(QUICPERF_ZIG_NATIVE_ARGS)
  if(QUICPERF_NATIVE)
    list(APPEND QUICPERF_ZIG_NATIVE_ARGS -Dtarget=native-native -Dcpu=native)
  endif()
  file(GLOB_RECURSE QUICPERF_QUIC_ZIG_SOURCES CONFIGURE_DEPENDS
    "${QUICPERF_QUIC_ZIG_SOURCE_DIR}/*.zig")
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
      ${QUICPERF_QUIC_ZIG_SOURCES}
    VERBATIM)
  add_custom_target(quicperf_zig_packet_ffi_build
    DEPENDS "${QUICPERF_ZIG_PACKET_FFI_LIB}")
  add_library(quicperf_zig_packet_ffi STATIC IMPORTED GLOBAL)
  set_target_properties(quicperf_zig_packet_ffi PROPERTIES
    IMPORTED_LOCATION "${QUICPERF_ZIG_PACKET_FFI_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${QUICPERF_ZIG_PACKET_FFI_DIR}/include")
  add_dependencies(quicperf_zig_packet_ffi quicperf_zig_packet_ffi_build)
endif()

if(BUILD_TESTING AND TARGET quicperf_rust_packet_ffi AND TARGET quicperf_zig_packet_ffi)
  add_executable(quicperf_packet_ffi_abi_contract tests/packet_ffi_abi_contract.cpp)
  target_compile_definitions(quicperf_packet_ffi_abi_contract PRIVATE
    "QUICPERF_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
  target_link_libraries(quicperf_packet_ffi_abi_contract PRIVATE
    quicperf_rust_packet_ffi quicperf_zig_packet_ffi dl pthread m)
  depos_link(quicperf_packet_ffi_abi_contract PRIVATE boringssl)
  add_test(NAME quicperf_packet_ffi_abi_contract COMMAND quicperf_packet_ffi_abi_contract)
endif()

function(quicperf_rust_packet_target target_name compile_define adapter_source)
  quicperf_target(${target_name} ${compile_define} ${adapter_source})
  target_sources(${target_name} PRIVATE src/adapters/rust_packet_adapter.cpp)
  add_dependencies(${target_name} quicperf_rust_packet_ffi_build)
  target_link_libraries(${target_name} PRIVATE quicperf_rust_packet_ffi dl pthread m)
  depos_link(${target_name} PRIVATE boringssl liburing)
endfunction()

function(quicperf_rust_packet_adapter_contract target_name library_name adapter_source supported)
  if(NOT BUILD_TESTING)
    return()
  endif()
  if(supported)
    set(contract_source tests/native_packet_adapter_contract.cpp)
  else()
    set(contract_source tests/limited_native_adapter_contract.cpp)
  endif()
  add_executable(${target_name}
    ${contract_source}
    src/adapters/rust_packet_adapter.cpp
    src/adapters/${adapter_source})
  target_compile_definitions(${target_name} PRIVATE
    "EXPECTED_LIBRARY=\"${library_name}\""
    "EXPECT_SUPPORTED=${supported}"
    "EXPECT_UNIDIRECTIONAL_STREAMS=${supported}"
    "EXPECT_EARLY_DATA=${supported}"
    "EXPECT_RESET_STOP=${supported}"
    "EXPECT_PEER_TERMINAL_FACTS=${supported}"
    "QUICPERF_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
  target_compile_options(${target_name} PRIVATE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-UNDEBUG>)
  add_dependencies(${target_name} quicperf_rust_packet_ffi_build)
  target_link_libraries(${target_name} PRIVATE
    quicperf_core quicperf_rust_packet_ffi dl pthread m)
  depos_link(${target_name} PRIVATE boringssl)
  add_test(NAME ${target_name} COMMAND ${target_name})
endfunction()

if(BUILD_QUINNPERF)
  quicperf_rust_packet_target(quinnperf QUINNPERF quinn_adapter.cpp)
  quicperf_rust_packet_adapter_contract(
    quicperf_quinn_adapter_contract quinn quinn_adapter.cpp 1)
  target_compile_definitions(quicperf_quinn_adapter_contract PRIVATE
    EXPECT_NEGOTIATED_EVIDENCE=1
    EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
    EXPECT_RECOVERY_WAKEUP_COUNTER=1)
endif()

if(BUILD_NOQPERF)
  quicperf_rust_packet_target(noqperf NOQPERF noq_adapter.cpp)
  quicperf_rust_packet_adapter_contract(
    quicperf_noq_adapter_contract noq noq_adapter.cpp 1)
  target_compile_definitions(quicperf_noq_adapter_contract PRIVATE
    EXPECT_NEGOTIATED_EVIDENCE=1
    EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
    EXPECT_RECOVERY_WAKEUP_COUNTER=1)
endif()

if(BUILD_NEQOPERF)
  quicperf_rust_packet_target(neqoperf NEQOPERF neqo_adapter.cpp)
  quicperf_rust_packet_adapter_contract(
    quicperf_neqo_adapter_contract neqo neqo_adapter.cpp 1)
  target_compile_definitions(quicperf_neqo_adapter_contract PRIVATE
    EXPECT_NEGOTIATED_EVIDENCE=1
    EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
    EXPECT_RECOVERY_WAKEUP_COUNTER=1
    EXPECT_PRE_READY_FILE_FDS=0)
endif()

if(BUILD_S2NPERF)
  quicperf_rust_packet_target(s2nperf S2NPERF s2n_adapter.cpp)
  quicperf_rust_packet_adapter_contract(
    quicperf_s2n_adapter_contract s2n_quic s2n_adapter.cpp 1)
  target_compile_definitions(quicperf_s2n_adapter_contract PRIVATE
    EXPECT_NEGOTIATED_EVIDENCE=1
    EXPECT_ONE_USE_TICKET_ENFORCEMENT=1
    "EXPECT_PEER_TERMINAL_FACTS=1")
endif()

if(BUILD_QUICZIGPERF)
  quicperf_target(quiczigperf QUICZIGPERF quiczig_adapter.cpp)
  target_sources(quiczigperf PRIVATE src/adapters/zig_packet_adapter.cpp)
  add_dependencies(quiczigperf quicperf_zig_packet_ffi_build)
  target_link_libraries(quiczigperf PRIVATE quicperf_zig_packet_ffi dl pthread m)
  depos_link(quiczigperf PRIVATE boringssl liburing)
  if(BUILD_TESTING)
    add_executable(quicperf_quiczig_adapter_contract
      tests/native_packet_adapter_contract.cpp
      src/adapters/zig_packet_adapter.cpp
      src/adapters/quiczig_adapter.cpp)
    target_compile_definitions(quicperf_quiczig_adapter_contract PRIVATE
      "EXPECTED_LIBRARY=\"quic_zig\""
      "EXPECT_EARLY_DATA=1"
      "EXPECT_SUCCESSOR_TICKET=1"
      "EXPECT_ONE_USE_TICKET_ENFORCEMENT=1"
      "EXPECT_PEER_TERMINAL_FACTS=1"
      "EXPECT_NEGOTIATED_EVIDENCE=1"
      "QUICPERF_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
    target_compile_options(quicperf_quiczig_adapter_contract PRIVATE
      $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-UNDEBUG>)
    add_dependencies(quicperf_quiczig_adapter_contract quicperf_zig_packet_ffi_build)
    target_link_libraries(quicperf_quiczig_adapter_contract PRIVATE
      quicperf_core quicperf_zig_packet_ffi dl pthread m)
    depos_link(quicperf_quiczig_adapter_contract PRIVATE boringssl)
    add_test(NAME quicperf_quiczig_adapter_contract COMMAND quicperf_quiczig_adapter_contract)
  endif()
endif()

if(BUILD_MVFSTPERF)
  quicperf_target(mvfstperf MVFSTPERF mvfst_adapter.cpp)
  target_compile_definitions(mvfstperf PRIVATE GLOG_USE_GLOG_EXPORT)
  depos_link(mvfstperf PRIVATE
    mvfst::mvfst fizz::fizz folly::folly fmt::fmt gflags::gflags glog::glog openssl liburing)
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
