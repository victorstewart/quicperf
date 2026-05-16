# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

include_guard(GLOBAL)

include(CMakeParseArguments)

function(_depos_module_dir out_var)
  get_filename_component(_depos_module_dir "${CMAKE_CURRENT_FUNCTION_LIST_FILE}" DIRECTORY)
  set(${out_var} "${_depos_module_dir}" PARENT_SCOPE)
endfunction()

function(_depos_repo_root out_var)
  _depos_module_dir(_depos_module_dir)
  get_filename_component(_depos_module_name "${_depos_module_dir}" NAME)
  if (_depos_module_name STREQUAL ".depos")
    get_filename_component(_depos_repo_root "${_depos_module_dir}/.." ABSOLUTE)
  else()
    set(_depos_repo_root "${_depos_module_dir}")
  endif()
  set(${out_var} "${_depos_repo_root}" PARENT_SCOPE)
endfunction()

function(_depos_project_defaults_file out_var)
  _depos_repo_root(_depos_project_root)
  set(${out_var} "${_depos_project_root}/depos.project.cmake" PARENT_SCOPE)
endfunction()

function(_depos_default_bootstrap_dir out_var)
  _depos_module_dir(_depos_module_dir)
  get_filename_component(_depos_module_name "${_depos_module_dir}" NAME)
  if (_depos_module_name STREQUAL ".depos")
    set(${out_var} "${_depos_module_dir}" PARENT_SCOPE)
  else()
    set(${out_var} "${_depos_module_dir}/.depos" PARENT_SCOPE)
  endif()
endfunction()

function(_depos_make_absolute out_var path_value)
  if ("${path_value}" STREQUAL "")
    set(${out_var} "" PARENT_SCOPE)
    return()
  endif()

  if (IS_ABSOLUTE "${path_value}")
    set(${out_var} "${path_value}" PARENT_SCOPE)
    return()
  endif()

  get_filename_component(_depos_absolute "${path_value}" ABSOLUTE BASE_DIR "${CMAKE_BINARY_DIR}")
  set(${out_var} "${_depos_absolute}" PARENT_SCOPE)
endfunction()

_depos_project_defaults_file(_depos_project_defaults)
if (EXISTS "${_depos_project_defaults}")
  include("${_depos_project_defaults}" OPTIONAL)
endif()

function(_depos_make_absolute_from_base out_var path_value base_dir)
  if ("${path_value}" STREQUAL "")
    set(${out_var} "" PARENT_SCOPE)
    return()
  endif()

  if (IS_ABSOLUTE "${path_value}")
    set(${out_var} "${path_value}" PARENT_SCOPE)
    return()
  endif()

  get_filename_component(_depos_absolute "${path_value}" ABSOLUTE BASE_DIR "${base_dir}")
  set(${out_var} "${_depos_absolute}" PARENT_SCOPE)
endfunction()

function(_depos_assert_single_token label value)
  if ("${value}" MATCHES "[ \t\r\n;()\"]")
    message(FATAL_ERROR "${label} must be a single token without spaces, semicolons, parentheses, or quotes.")
  endif()
endfunction()

function(_depos_status message_text)
  message(STATUS "depos: ${message_text}")
endfunction()

function(_depos_runtime_mode_label out_var local_mode)
  if (${local_mode})
    set(${out_var} "project-local" PARENT_SCOPE)
  else()
    set(${out_var} "system" PARENT_SCOPE)
  endif()
endfunction()

function(_depos_global_property_length out_var property_name)
  get_property(_depos_items GLOBAL PROPERTY ${property_name})
  if (NOT _depos_items)
    set(${out_var} 0 PARENT_SCOPE)
    return()
  endif()

  list(LENGTH _depos_items _depos_items_count)
  set(${out_var} "${_depos_items_count}" PARENT_SCOPE)
endfunction()

function(_depos_cache_property_name out_var prefix key)
  string(SHA256 _depos_cache_hash "${prefix}|${key}")
  set(${out_var} "${prefix}_${_depos_cache_hash}" PARENT_SCOPE)
endfunction()

function(_depos_mark_sync_dirty)
  set_property(GLOBAL PROPERTY DEPOS_SYNC_DIRTY TRUE)
endfunction()

function(_depos_clear_sync_dirty)
  set_property(GLOBAL PROPERTY DEPOS_SYNC_DIRTY FALSE)
endfunction()

function(_depos_ensure_registry_ready)
  get_property(_depos_lines GLOBAL PROPERTY DEPOS_REQUEST_LINES)
  if (NOT _depos_lines)
    return()
  endif()

  get_property(_depos_dirty GLOBAL PROPERTY DEPOS_SYNC_DIRTY)
  get_property(_depos_registry_dir GLOBAL PROPERTY DEPOS_ACTIVE_REGISTRY_DIR)
  if ("${_depos_dirty}" STREQUAL "TRUE" OR "${_depos_registry_dir}" STREQUAL "")
    _depos_sync_current_requests()
  endif()
endfunction()

function(_depos_default_project_namespace out_var)
  if (DEFINED PROJECT_NAME AND NOT "${PROJECT_NAME}" STREQUAL "")
    set(_depos_namespace "${PROJECT_NAME}")
  else()
    get_filename_component(_depos_namespace "${CMAKE_SOURCE_DIR}" NAME)
  endif()

  string(TOLOWER "${_depos_namespace}" _depos_namespace)
  string(REGEX REPLACE "[^a-z0-9_.-]+" "-" _depos_namespace "${_depos_namespace}")
  string(REGEX REPLACE "^-+" "" _depos_namespace "${_depos_namespace}")
  string(REGEX REPLACE "-+$" "" _depos_namespace "${_depos_namespace}")
  if (_depos_namespace STREQUAL "")
    set(_depos_namespace "project")
  endif()

  set(${out_var} "${_depos_namespace}" PARENT_SCOPE)
endfunction()

if (NOT DEFINED DEPOS_BOOTSTRAP_VERSION OR DEPOS_BOOTSTRAP_VERSION STREQUAL "")
  set(
    DEPOS_BOOTSTRAP_VERSION
    "0.5.0"
    CACHE STRING
    "Pinned depos version used when bootstrapping locally with Cargo"
  )
endif()

if (NOT DEFINED DEPOS_BOOTSTRAP_DIR OR DEPOS_BOOTSTRAP_DIR STREQUAL "")
  _depos_default_bootstrap_dir(_depos_default_bootstrap_dir)
  set(
    DEPOS_BOOTSTRAP_DIR
    "${_depos_default_bootstrap_dir}"
    CACHE PATH
    "Hidden project-local depos directory for the bootstrap tool, registry root, manifest, and state"
  )
endif()

if (NOT DEFINED DEPOS_MANIFEST_FILE OR DEPOS_MANIFEST_FILE STREQUAL "")
  set(
    DEPOS_MANIFEST_FILE
    "${DEPOS_BOOTSTRAP_DIR}/.manifest.cmake"
    CACHE FILEPATH
    "Generated manifest file used by .depos.cmake"
  )
endif()

if (NOT DEFINED DEPOS_ALLOW_CARGO_BOOTSTRAP)
  set(
    DEPOS_ALLOW_CARGO_BOOTSTRAP
    ON
    CACHE BOOL
    "Allow bootstrapping depos locally with cargo install"
  )
endif()

if (NOT DEFINED DEPOS_CARGO_EXECUTABLE)
  set(
    DEPOS_CARGO_EXECUTABLE
    ""
    CACHE FILEPATH
    "Explicit cargo executable used for local bootstrap instead of PATH lookup"
  )
endif()

if (NOT DEFINED DEPOS_ALLOW_SYSTEM_EXECUTABLE)
  set(
    DEPOS_ALLOW_SYSTEM_EXECUTABLE
    OFF
    CACHE BOOL
    "Allow falling back to a system depos from PATH when no explicit executable is provided"
  )
endif()

if (NOT DEFINED DEPOS_PROJECT_NAMESPACE OR DEPOS_PROJECT_NAMESPACE STREQUAL "")
  _depos_default_project_namespace(_depos_default_namespace)
  set(
    DEPOS_PROJECT_NAMESPACE
    "${_depos_default_namespace}"
    CACHE STRING
    "Namespace used when registering project depofiles into a shared depos root"
  )
endif()

function(depos_default_root out_var)
  if (DEFINED DEPOS_ROOT AND NOT "${DEPOS_ROOT}" STREQUAL "")
    set(_depos_runtime_root "${DEPOS_ROOT}")
  elseif (DEFINED ENV{DEPOS_ROOT} AND NOT "$ENV{DEPOS_ROOT}" STREQUAL "")
    set(_depos_runtime_root "$ENV{DEPOS_ROOT}")
  elseif (DEFINED ENV{HOME} AND NOT "$ENV{HOME}" STREQUAL "")
    set(_depos_runtime_root "$ENV{HOME}/.depos")
  elseif (WIN32 AND DEFINED ENV{USERPROFILE} AND NOT "$ENV{USERPROFILE}" STREQUAL "")
    set(_depos_runtime_root "$ENV{USERPROFILE}/.depos")
  elseif (
    WIN32
    AND DEFINED ENV{HOMEDRIVE}
    AND NOT "$ENV{HOMEDRIVE}" STREQUAL ""
    AND DEFINED ENV{HOMEPATH}
    AND NOT "$ENV{HOMEPATH}" STREQUAL ""
  )
    set(_depos_runtime_root "$ENV{HOMEDRIVE}$ENV{HOMEPATH}/.depos")
  else()
    message(FATAL_ERROR "Unable to determine DEPOS_ROOT.")
  endif()

  _depos_make_absolute(_depos_runtime_root "${_depos_runtime_root}")
  set(${out_var} "${_depos_runtime_root}" PARENT_SCOPE)
endfunction()

function(depos_default_variant out_var)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _depos_arch)
  if (_depos_arch STREQUAL "")
    string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}" _depos_arch)
  endif()
  if (_depos_arch STREQUAL "")
    execute_process(
      COMMAND uname -m
      OUTPUT_VARIABLE _depos_arch
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    string(TOLOWER "${_depos_arch}" _depos_arch)
  endif()
  if (_depos_arch STREQUAL "")
    set(_depos_arch "unknown")
  endif()
  if (_depos_arch STREQUAL "amd64")
    set(_depos_arch "x86_64")
  endif()
  if (_depos_arch STREQUAL "arm64")
    set(_depos_arch "aarch64")
  endif()
  set(${out_var} "${_depos_arch}-${_depos_arch}_v1" PARENT_SCOPE)
endfunction()

function(depos_manifest_profile out_var manifest_path)
  _depos_make_absolute(_depos_manifest_path "${manifest_path}")
  file(SHA256 "${_depos_manifest_path}" _depos_hash)
  string(SUBSTRING "${_depos_hash}" 0 16 _depos_short_hash)
  set(${out_var} "manifest-${_depos_short_hash}" PARENT_SCOPE)
endfunction()

function(depos_registry_dir out_var manifest_path)
  _depos_make_absolute(_depos_manifest_path "${manifest_path}")
  depos_default_root(_depos_root)
  depos_default_variant(_depos_variant)
  depos_manifest_profile(_depos_profile "${_depos_manifest_path}")
  set(${out_var} "${_depos_root}/registry/${_depos_variant}/${_depos_profile}" PARENT_SCOPE)
endfunction()

function(_depos_state_file out_var)
  set(${out_var} "${DEPOS_BOOTSTRAP_DIR}/.state.cmake" PARENT_SCOPE)
endfunction()

function(_depos_bootstrap_binary_path out_var)
  set(${out_var} "${DEPOS_BOOTSTRAP_DIR}/.tool/bin/depos${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
endfunction()

function(_depos_internal_namespace out_var local_mode)
  if (${local_mode})
    set(${out_var} "release" PARENT_SCOPE)
  else()
    set(${out_var} "${DEPOS_PROJECT_NAMESPACE}" PARENT_SCOPE)
  endif()
endfunction()

function(_depos_visible_namespace out_var local_mode)
  if (${local_mode})
    set(${out_var} "" PARENT_SCOPE)
  else()
    set(${out_var} "${DEPOS_PROJECT_NAMESPACE}" PARENT_SCOPE)
  endif()
endfunction()

function(_depos_effective_root out_var local_mode)
  if (DEFINED DEPOS_ROOT AND NOT "${DEPOS_ROOT}" STREQUAL "")
    set(_depos_root "${DEPOS_ROOT}")
  elseif (${local_mode})
    set(_depos_root "${DEPOS_BOOTSTRAP_DIR}/.root")
  else()
    depos_default_root(_depos_root)
  endif()

  _depos_make_absolute(_depos_root "${_depos_root}")
  set(${out_var} "${_depos_root}" PARENT_SCOPE)
endfunction()

function(_depos_write_state executable root local_mode)
  _depos_state_file(_depos_state_file)
  file(MAKE_DIRECTORY "${DEPOS_BOOTSTRAP_DIR}")
  if (${local_mode})
    set(_depos_mode "LOCAL")
    set(_depos_namespace "")
  else()
    set(_depos_mode "SYSTEM")
    set(_depos_namespace "${DEPOS_PROJECT_NAMESPACE}")
  endif()

  file(WRITE "${_depos_state_file}" "# Generated by .depos.cmake.\n")
  file(APPEND "${_depos_state_file}" "set(DEPOS_STATE_MODE [==[${_depos_mode}]==])\n")
  file(APPEND "${_depos_state_file}" "set(DEPOS_STATE_EXECUTABLE [==[${executable}]==])\n")
  file(APPEND "${_depos_state_file}" "set(DEPOS_STATE_ROOT [==[${root}]==])\n")
  file(APPEND "${_depos_state_file}" "set(DEPOS_STATE_NAMESPACE [==[${_depos_namespace}]==])\n")
  file(APPEND "${_depos_state_file}" "set(DEPOS_STATE_VERSION [==[${DEPOS_BOOTSTRAP_VERSION}]==])\n")
endfunction()

function(_depos_load_state out_mode out_executable out_root out_namespace out_version)
  _depos_state_file(_depos_state_file)
  if (NOT EXISTS "${_depos_state_file}")
    set(${out_mode} "" PARENT_SCOPE)
    set(${out_executable} "" PARENT_SCOPE)
    set(${out_root} "" PARENT_SCOPE)
    set(${out_namespace} "" PARENT_SCOPE)
    set(${out_version} "" PARENT_SCOPE)
    return()
  endif()

  unset(DEPOS_STATE_MODE)
  unset(DEPOS_STATE_EXECUTABLE)
  unset(DEPOS_STATE_ROOT)
  unset(DEPOS_STATE_NAMESPACE)
  unset(DEPOS_STATE_VERSION)
  include("${_depos_state_file}" OPTIONAL)

  set(${out_mode} "${DEPOS_STATE_MODE}" PARENT_SCOPE)
  set(${out_executable} "${DEPOS_STATE_EXECUTABLE}" PARENT_SCOPE)
  set(${out_root} "${DEPOS_STATE_ROOT}" PARENT_SCOPE)
  set(${out_namespace} "${DEPOS_STATE_NAMESPACE}" PARENT_SCOPE)
  set(${out_version} "${DEPOS_STATE_VERSION}" PARENT_SCOPE)
endfunction()

function(_depos_cache_runtime executable root local_mode namespace)
  set_property(GLOBAL PROPERTY DEPOS_RESOLVED_EXECUTABLE "${executable}")
  set_property(GLOBAL PROPERTY DEPOS_RESOLVED_ROOT "${root}")
  set_property(GLOBAL PROPERTY DEPOS_RESOLVED_LOCAL_MODE "${local_mode}")
  set_property(GLOBAL PROPERTY DEPOS_RESOLVED_NAMESPACE "${namespace}")
endfunction()

function(_depos_copy_interface_locally)
  file(
    COPY_FILE
    "${CMAKE_CURRENT_FUNCTION_LIST_FILE}"
    "${DEPOS_BOOTSTRAP_DIR}/.depos.cmake"
    ONLY_IF_DIFFERENT
  )
endfunction()

function(_depos_bootstrap_with_cargo out_var)
  if (DEFINED DEPOS_CARGO_EXECUTABLE AND NOT "${DEPOS_CARGO_EXECUTABLE}" STREQUAL "")
    set(_depos_cargo_executable "${DEPOS_CARGO_EXECUTABLE}")
  else()
    find_program(_depos_cargo_executable cargo)
  endif()
  if (NOT _depos_cargo_executable)
    message(FATAL_ERROR "cargo was not found; cannot bootstrap depos from crates.io.")
  endif()

  cmake_host_system_information(RESULT _depos_jobs QUERY NUMBER_OF_LOGICAL_CORES)
  if (NOT _depos_jobs OR _depos_jobs LESS 1)
    set(_depos_jobs 1)
  endif()

  _depos_bootstrap_binary_path(_depos_bootstrap_binary)
  file(MAKE_DIRECTORY "${DEPOS_BOOTSTRAP_DIR}/.tool")
  set(_depos_cargo_command "${_depos_cargo_executable}")
  if (WIN32 AND "${_depos_cargo_executable}" MATCHES "\\.(cmd|bat)$")
    if (DEFINED ENV{COMSPEC} AND NOT "$ENV{COMSPEC}" STREQUAL "")
      set(_depos_cmd_executable "$ENV{COMSPEC}")
    else()
      find_program(_depos_cmd_executable cmd.exe)
    endif()
    if (NOT _depos_cmd_executable)
      message(FATAL_ERROR "cmd.exe was not found; cannot run batch-based cargo bootstrap on Windows.")
    endif()
    file(TO_NATIVE_PATH "${_depos_cargo_executable}" _depos_cargo_executable_native)
    set(_depos_cargo_command "${_depos_cmd_executable}" /c call "${_depos_cargo_executable_native}")
  endif()

  execute_process(
    COMMAND
      ${_depos_cargo_command}
      install
      --locked
      --root
      "${DEPOS_BOOTSTRAP_DIR}/.tool"
      --version
      "${DEPOS_BOOTSTRAP_VERSION}"
      -j
      "${_depos_jobs}"
      depos
    RESULT_VARIABLE _depos_cargo_result
    OUTPUT_VARIABLE _depos_cargo_stdout
    ERROR_VARIABLE _depos_cargo_stderr
  )
  if (NOT _depos_cargo_result EQUAL 0)
    message(
      FATAL_ERROR
      "Failed to bootstrap depos ${DEPOS_BOOTSTRAP_VERSION} with cargo install.\n"
      "stdout:\n${_depos_cargo_stdout}\n"
      "stderr:\n${_depos_cargo_stderr}"
    )
  endif()

  if (NOT EXISTS "${_depos_bootstrap_binary}")
    message(FATAL_ERROR "cargo install completed but did not produce ${_depos_bootstrap_binary}")
  endif()

  _depos_copy_interface_locally()
  set(${out_var} "${_depos_bootstrap_binary}" PARENT_SCOPE)
endfunction()

function(_depos_resolve_runtime out_executable out_root out_local_mode out_namespace)
  get_property(_depos_cached_executable GLOBAL PROPERTY DEPOS_RESOLVED_EXECUTABLE)
  get_property(_depos_cached_root GLOBAL PROPERTY DEPOS_RESOLVED_ROOT)
  get_property(_depos_cached_local_mode GLOBAL PROPERTY DEPOS_RESOLVED_LOCAL_MODE)
  get_property(_depos_cached_namespace GLOBAL PROPERTY DEPOS_RESOLVED_NAMESPACE)
  if (NOT "${_depos_cached_executable}" STREQUAL "" AND EXISTS "${_depos_cached_executable}")
    set(${out_executable} "${_depos_cached_executable}" PARENT_SCOPE)
    set(${out_root} "${_depos_cached_root}" PARENT_SCOPE)
    set(${out_local_mode} "${_depos_cached_local_mode}" PARENT_SCOPE)
    set(${out_namespace} "${_depos_cached_namespace}" PARENT_SCOPE)
    return()
  endif()

  if (DEFINED DEPOS_EXECUTABLE AND NOT "${DEPOS_EXECUTABLE}" STREQUAL "")
    _depos_make_absolute(_depos_executable "${DEPOS_EXECUTABLE}")
    if (NOT EXISTS "${_depos_executable}" OR IS_DIRECTORY "${_depos_executable}")
      message(FATAL_ERROR "DEPOS_EXECUTABLE must point to an existing depos binary: ${_depos_executable}")
    endif()
    _depos_effective_root(_depos_root FALSE)
    _depos_visible_namespace(_depos_namespace FALSE)
    _depos_write_state("${_depos_executable}" "${_depos_root}" FALSE)
    _depos_cache_runtime("${_depos_executable}" "${_depos_root}" FALSE "${_depos_namespace}")
    _depos_status("using system depos at ${_depos_executable}")
    set(${out_executable} "${_depos_executable}" PARENT_SCOPE)
    set(${out_root} "${_depos_root}" PARENT_SCOPE)
    set(${out_local_mode} FALSE PARENT_SCOPE)
    set(${out_namespace} "${_depos_namespace}" PARENT_SCOPE)
    return()
  endif()

  if (DEFINED DEPOS_ROOT AND NOT "${DEPOS_ROOT}" STREQUAL "" AND DEPOS_ALLOW_SYSTEM_EXECUTABLE)
    find_program(_depos_from_path depos)
    if (_depos_from_path)
      _depos_effective_root(_depos_root FALSE)
      _depos_visible_namespace(_depos_namespace FALSE)
      _depos_write_state("${_depos_from_path}" "${_depos_root}" FALSE)
      _depos_cache_runtime("${_depos_from_path}" "${_depos_root}" FALSE "${_depos_namespace}")
      _depos_status("using system depos from PATH at ${_depos_from_path}")
      set(${out_executable} "${_depos_from_path}" PARENT_SCOPE)
      set(${out_root} "${_depos_root}" PARENT_SCOPE)
      set(${out_local_mode} FALSE PARENT_SCOPE)
      set(${out_namespace} "${_depos_namespace}" PARENT_SCOPE)
      return()
    endif()
  endif()

  _depos_load_state(
    _depos_state_mode
    _depos_state_executable
    _depos_state_root
    _depos_state_namespace
    _depos_state_version
  )
  if ("${_depos_state_mode}" STREQUAL "LOCAL"
      AND "${_depos_state_version}" STREQUAL "${DEPOS_BOOTSTRAP_VERSION}"
      AND EXISTS "${_depos_state_executable}")
    _depos_cache_runtime(
      "${_depos_state_executable}"
      "${_depos_state_root}"
      TRUE
      "${_depos_state_namespace}"
    )
    _depos_status("using project-local depos at ${_depos_state_executable}")
    set(${out_executable} "${_depos_state_executable}" PARENT_SCOPE)
    set(${out_root} "${_depos_state_root}" PARENT_SCOPE)
    set(${out_local_mode} TRUE PARENT_SCOPE)
    set(${out_namespace} "${_depos_state_namespace}" PARENT_SCOPE)
    return()
  endif()

  _depos_bootstrap_binary_path(_depos_bootstrap_binary)
  if (EXISTS "${_depos_bootstrap_binary}")
    _depos_effective_root(_depos_root TRUE)
    _depos_visible_namespace(_depos_namespace TRUE)
    _depos_write_state("${_depos_bootstrap_binary}" "${_depos_root}" TRUE)
    _depos_cache_runtime("${_depos_bootstrap_binary}" "${_depos_root}" TRUE "${_depos_namespace}")
    _depos_status("using project-local depos at ${_depos_bootstrap_binary}")
    set(${out_executable} "${_depos_bootstrap_binary}" PARENT_SCOPE)
    set(${out_root} "${_depos_root}" PARENT_SCOPE)
    set(${out_local_mode} TRUE PARENT_SCOPE)
    set(${out_namespace} "${_depos_namespace}" PARENT_SCOPE)
    return()
  endif()

  if (NOT DEPOS_ALLOW_CARGO_BOOTSTRAP)
    message(
      FATAL_ERROR
      "Unable to resolve depos. Set DEPOS_EXECUTABLE for a system install or enable cargo bootstrap for a local install."
    )
  endif()

  _depos_status("bootstrapping depos ${DEPOS_BOOTSTRAP_VERSION} locally with cargo install")
  _depos_bootstrap_with_cargo(_depos_bootstrap_binary)
  _depos_effective_root(_depos_root TRUE)
  _depos_visible_namespace(_depos_namespace TRUE)
  _depos_write_state("${_depos_bootstrap_binary}" "${_depos_root}" TRUE)
  _depos_cache_runtime("${_depos_bootstrap_binary}" "${_depos_root}" TRUE "${_depos_namespace}")
  _depos_status("using project-local depos at ${_depos_bootstrap_binary}")
  set(${out_executable} "${_depos_bootstrap_binary}" PARENT_SCOPE)
  set(${out_root} "${_depos_root}" PARENT_SCOPE)
  set(${out_local_mode} TRUE PARENT_SCOPE)
  set(${out_namespace} "${_depos_namespace}" PARENT_SCOPE)
endfunction()

function(_depos_default_depofiles_dir out_var)
  if (DEFINED DEPOS_DEPOFILES_DIR AND NOT "${DEPOS_DEPOFILES_DIR}" STREQUAL "")
    _depos_make_absolute(_depos_depofiles_dir "${DEPOS_DEPOFILES_DIR}")
    set(${out_var} "${_depos_depofiles_dir}" PARENT_SCOPE)
    return()
  endif()

  _depos_module_dir(_depos_module_dir)
  get_filename_component(_depos_module_name "${_depos_module_dir}" NAME)
  if (_depos_module_name STREQUAL ".depos")
    get_filename_component(_depos_repo_root "${_depos_module_dir}" DIRECTORY)
    if (IS_DIRECTORY "${_depos_repo_root}/depofiles")
      set(${out_var} "${_depos_repo_root}/depofiles" PARENT_SCOPE)
      return()
    endif()
  endif()

  if (IS_DIRECTORY "${_depos_module_dir}/depofiles")
    set(${out_var} "${_depos_module_dir}/depofiles" PARENT_SCOPE)
    return()
  endif()

  if (_depos_module_name STREQUAL "depofiles")
    set(${out_var} "${_depos_module_dir}" PARENT_SCOPE)
    return()
  endif()

  if (IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/depofiles")
    set(${out_var} "${CMAKE_CURRENT_SOURCE_DIR}/depofiles" PARENT_SCOPE)
    return()
  endif()

  file(
    GLOB_RECURSE _depos_module_depofiles
    LIST_DIRECTORIES false
    "${_depos_module_dir}/*.DepoFile"
  )
  if (_depos_module_depofiles)
    set(${out_var} "${_depos_module_dir}" PARENT_SCOPE)
    return()
  endif()

  set(${out_var} "${_depos_module_dir}/depofiles" PARENT_SCOPE)
endfunction()

function(_depos_parse_depofile_metadata out_name out_version out_target depofile)
  _depos_make_absolute_from_base(_depos_cached_depofile "${depofile}" "${CMAKE_CURRENT_SOURCE_DIR}")
  _depos_cache_property_name(_depos_metadata_property "DEPOS_DEPOFILE_METADATA" "${_depos_cached_depofile}")
  get_property(_depos_metadata_cached GLOBAL PROPERTY "${_depos_metadata_property}_NAME" SET)
  if (_depos_metadata_cached)
    get_property(_depos_name GLOBAL PROPERTY "${_depos_metadata_property}_NAME")
    get_property(_depos_version GLOBAL PROPERTY "${_depos_metadata_property}_VERSION")
    get_property(_depos_target GLOBAL PROPERTY "${_depos_metadata_property}_TARGET")
    set(${out_name} "${_depos_name}" PARENT_SCOPE)
    set(${out_version} "${_depos_version}" PARENT_SCOPE)
    set(${out_target} "${_depos_target}" PARENT_SCOPE)
    return()
  endif()

  file(STRINGS "${depofile}" _depos_name_line REGEX "^NAME[ \t]+[^ \t\r\n]+$" LIMIT_COUNT 1)
  file(STRINGS "${depofile}" _depos_version_line REGEX "^VERSION[ \t]+[^ \t\r\n]+$" LIMIT_COUNT 1)
  file(STRINGS "${depofile}" _depos_primary_line REGEX "^PRIMARY_TARGET[ \t]+[^ \t\r\n]+$" LIMIT_COUNT 1)
  file(STRINGS "${depofile}" _depos_target_line REGEX "^TARGET[ \t]+[^ \t\r\n]+.*$" LIMIT_COUNT 1)

  if ("${_depos_name_line}" STREQUAL "" OR "${_depos_version_line}" STREQUAL "")
    message(FATAL_ERROR "Failed to read NAME/VERSION from DepoFile ${depofile}")
  endif()

  string(REGEX REPLACE "^NAME[ \t]+([^ \t\r\n]+)$" "\\1" _depos_name "${_depos_name_line}")
  string(REGEX REPLACE "^VERSION[ \t]+([^ \t\r\n]+)$" "\\1" _depos_version "${_depos_version_line}")

  if (NOT "${_depos_primary_line}" STREQUAL "")
    string(REGEX REPLACE "^PRIMARY_TARGET[ \t]+([^ \t\r\n]+)$" "\\1" _depos_target "${_depos_primary_line}")
  elseif (NOT "${_depos_target_line}" STREQUAL "")
    string(REGEX REPLACE "^TARGET[ \t]+([^ \t\r\n]+).*$" "\\1" _depos_target "${_depos_target_line}")
  else()
    set(_depos_target "")
  endif()

  set_property(GLOBAL PROPERTY "${_depos_metadata_property}_NAME" "${_depos_name}")
  set_property(GLOBAL PROPERTY "${_depos_metadata_property}_VERSION" "${_depos_version}")
  set_property(GLOBAL PROPERTY "${_depos_metadata_property}_TARGET" "${_depos_target}")
  set(${out_name} "${_depos_name}" PARENT_SCOPE)
  set(${out_version} "${_depos_version}" PARENT_SCOPE)
  set(${out_target} "${_depos_target}" PARENT_SCOPE)
endfunction()

function(_depos_depofile_entries out_var search_root)
  if ("${search_root}" STREQUAL "")
    _depos_default_depofiles_dir(_depos_search_root)
  else()
    _depos_make_absolute_from_base(_depos_search_root "${search_root}" "${CMAKE_CURRENT_SOURCE_DIR}")
  endif()

  if (NOT IS_DIRECTORY "${_depos_search_root}")
    set(${out_var} "" PARENT_SCOPE)
    return()
  endif()

  _depos_cache_property_name(_depos_entries_property "DEPOS_DEPOFILE_ENTRIES" "${_depos_search_root}")
  get_property(_depos_entries_cached GLOBAL PROPERTY "${_depos_entries_property}" SET)
  if (_depos_entries_cached)
    get_property(_depos_cached_entries GLOBAL PROPERTY "${_depos_entries_property}")
    set(${out_var} "${_depos_cached_entries}" PARENT_SCOPE)
    return()
  endif()

  file(
    GLOB_RECURSE _depos_depofiles
    LIST_DIRECTORIES false
    "${_depos_search_root}/*.DepoFile"
  )
  list(SORT _depos_depofiles)

  set(_depos_entries "")
  foreach(_depos_depofile IN LISTS _depos_depofiles)
    _depos_parse_depofile_metadata(_depos_name _depos_version _depos_target "${_depos_depofile}")
    list(APPEND _depos_entries "${_depos_name}|${_depos_version}|${_depos_target}|${_depos_depofile}")
  endforeach()

  set_property(GLOBAL PROPERTY "${_depos_entries_property}" "${_depos_entries}")
  set(${out_var} "${_depos_entries}" PARENT_SCOPE)
endfunction()

function(_depos_find_local_depofile out_entry search_root name exact_version)
  _depos_depofile_entries(_depos_entries "${search_root}")
  set(_depos_matches "")

  foreach(_depos_entry IN LISTS _depos_entries)
    string(REPLACE "|" ";" _depos_parts "${_depos_entry}")
    list(GET _depos_parts 0 _depos_name)
    list(GET _depos_parts 1 _depos_version)

    if (NOT "${_depos_name}" STREQUAL "${name}")
      continue()
    endif()
    if (NOT "${exact_version}" STREQUAL "" AND NOT "${_depos_version}" STREQUAL "${exact_version}")
      continue()
    endif()

    list(APPEND _depos_matches "${_depos_entry}")
  endforeach()

  if (NOT _depos_matches)
    set(${out_entry} "" PARENT_SCOPE)
    return()
  endif()

  list(LENGTH _depos_matches _depos_match_count)
  if (_depos_match_count GREATER 1 AND "${exact_version}" STREQUAL "")
    message(
      FATAL_ERROR
      "Multiple DepoFiles named ${name} were found. Pass VERSION explicitly or use depos_depend_all()."
    )
  endif()

  list(GET _depos_matches 0 _depos_entry)
  set(${out_entry} "${_depos_entry}" PARENT_SCOPE)
endfunction()

function(_depos_record_package_target package_name target_name)
  if ("${target_name}" STREQUAL "")
    return()
  endif()

  get_property(_depos_target_map GLOBAL PROPERTY DEPOS_PACKAGE_TARGET_MAP)
  if (NOT _depos_target_map)
    set(_depos_target_map "")
  endif()
  set(_depos_new_entry "${package_name}|${target_name}")
  list(FIND _depos_target_map "${_depos_new_entry}" _depos_target_index)
  if (_depos_target_index EQUAL -1)
    set_property(GLOBAL APPEND PROPERTY DEPOS_PACKAGE_TARGET_MAP "${_depos_new_entry}")
  endif()

  get_property(_depos_all_targets GLOBAL PROPERTY DEPOS_ALL_PRIMARY_TARGETS)
  if (NOT _depos_all_targets)
    set(_depos_all_targets "")
  endif()
  list(FIND _depos_all_targets "${target_name}" _depos_all_target_index)
  if (_depos_all_target_index EQUAL -1)
    set_property(GLOBAL APPEND PROPERTY DEPOS_ALL_PRIMARY_TARGETS "${target_name}")
  endif()
endfunction()

function(_depos_lookup_package_target out_var package_name)
  get_property(_depos_target_map GLOBAL PROPERTY DEPOS_PACKAGE_TARGET_MAP)
  if (NOT _depos_target_map)
    set(${out_var} "" PARENT_SCOPE)
    return()
  endif()

  foreach(_depos_entry IN LISTS _depos_target_map)
    string(REPLACE "|" ";" _depos_parts "${_depos_entry}")
    list(GET _depos_parts 0 _depos_package_name)
    if (NOT "${_depos_package_name}" STREQUAL "${package_name}")
      continue()
    endif()
    list(GET _depos_parts 1 _depos_target_name)
    set(${out_var} "${_depos_target_name}" PARENT_SCOPE)
    return()
  endforeach()

  set(${out_var} "" PARENT_SCOPE)
endfunction()

function(_depos_registered_depofile_path out_var name version root local_mode)
  _depos_internal_namespace(_depos_namespace ${local_mode})
  set(
    ${out_var}
    "${root}/depofiles/local/${name}/${_depos_namespace}/${version}/main.DepoFile"
    PARENT_SCOPE
  )
endfunction()

function(_depos_depofile_needs_register out_var depofile name version root local_mode)
  _depos_registered_depofile_path(_depos_registered_path "${name}" "${version}" "${root}" ${local_mode})
  if (NOT EXISTS "${_depos_registered_path}")
    set(${out_var} TRUE PARENT_SCOPE)
    return()
  endif()

  file(SHA256 "${depofile}" _depos_source_hash)
  file(SHA256 "${_depos_registered_path}" _depos_registered_hash)
  if (NOT "${_depos_source_hash}" STREQUAL "${_depos_registered_hash}")
    set(${out_var} TRUE PARENT_SCOPE)
  else()
    set(${out_var} FALSE PARENT_SCOPE)
  endif()
endfunction()

function(_depos_depofile_search_root_from_path out_var depofile)
  get_filename_component(_depos_cursor "${depofile}" DIRECTORY)
  while(TRUE)
    get_filename_component(_depos_cursor_name "${_depos_cursor}" NAME)
    if (_depos_cursor_name STREQUAL "depofiles")
      set(${out_var} "${_depos_cursor}" PARENT_SCOPE)
      return()
    endif()

    if (IS_DIRECTORY "${_depos_cursor}/depofiles")
      set(${out_var} "${_depos_cursor}/depofiles" PARENT_SCOPE)
      return()
    endif()

    get_filename_component(_depos_parent "${_depos_cursor}" DIRECTORY)
    if ("${_depos_parent}" STREQUAL "${_depos_cursor}")
      break()
    endif()
    set(_depos_cursor "${_depos_parent}")
  endwhile()

  set(${out_var} "" PARENT_SCOPE)
endfunction()

function(_depos_depofile_dependency_entries out_var depofile)
  _depos_make_absolute_from_base(_depos_cached_depofile "${depofile}" "${CMAKE_CURRENT_SOURCE_DIR}")
  _depos_cache_property_name(_depos_dependencies_property "DEPOS_DEPOFILE_DEPENDENCIES" "${_depos_cached_depofile}")
  get_property(_depos_dependencies_cached GLOBAL PROPERTY "${_depos_dependencies_property}" SET)
  if (_depos_dependencies_cached)
    get_property(_depos_cached_dependencies GLOBAL PROPERTY "${_depos_dependencies_property}")
    set(${out_var} "${_depos_cached_dependencies}" PARENT_SCOPE)
    return()
  endif()

  file(STRINGS "${depofile}" _depos_dependency_lines REGEX "^DEPENDS[ \t]+")
  set(_depos_dependency_entries "")
  foreach(_depos_dependency_line IN LISTS _depos_dependency_lines)
    string(REGEX REPLACE "^DEPENDS[ \t]+([^ \t\r\n]+).*$" "\\1" _depos_dependency_name "${_depos_dependency_line}")
    set(_depos_dependency_version "")
    if (_depos_dependency_line MATCHES "(^|[ \t])VERSION[ \t]+([^ \t\r\n]+)")
      set(_depos_dependency_version "${CMAKE_MATCH_2}")
    endif()
    list(APPEND _depos_dependency_entries "${_depos_dependency_name}|${_depos_dependency_version}")
  endforeach()

  set_property(GLOBAL PROPERTY "${_depos_dependencies_property}" "${_depos_dependency_entries}")
  set(${out_var} "${_depos_dependency_entries}" PARENT_SCOPE)
endfunction()

function(_depos_add_pending_depofile depofile name version target root local_mode)
  set(_depos_search_root "")
  if (ARGC GREATER 6)
    set(_depos_search_root "${ARGV6}")
  else()
    _depos_depofile_search_root_from_path(_depos_search_root "${depofile}")
  endif()

  _depos_depofile_needs_register(_depos_needs_register "${depofile}" "${name}" "${version}" "${root}" ${local_mode})
  if (_depos_needs_register)
    get_property(_depos_pending GLOBAL PROPERTY DEPOS_PENDING_DEPOFILES)
    if (NOT _depos_pending)
      set(_depos_pending "")
    endif()
    set(_depos_entry "${name}|${version}|${target}|${depofile}")
    list(FIND _depos_pending "${_depos_entry}" _depos_pending_index)
    if (_depos_pending_index EQUAL -1)
      set_property(GLOBAL APPEND PROPERTY DEPOS_PENDING_DEPOFILES "${_depos_entry}")
      _depos_mark_sync_dirty()
    endif()
  endif()

  _depos_record_package_target("${name}" "${target}")

  get_property(_depos_seen GLOBAL PROPERTY DEPOS_PENDING_DEPOFILES_SEEN)
  if (NOT _depos_seen)
    set(_depos_seen "")
  endif()
  list(FIND _depos_seen "${depofile}" _depos_seen_index)
  if (_depos_seen_index GREATER -1)
    return()
  endif()
  set_property(GLOBAL APPEND PROPERTY DEPOS_PENDING_DEPOFILES_SEEN "${depofile}")

  if ("${_depos_search_root}" STREQUAL "")
    return()
  endif()

  _depos_depofile_dependency_entries(_depos_dependency_entries "${depofile}")
  foreach(_depos_dependency_entry IN LISTS _depos_dependency_entries)
    string(REPLACE "|" ";" _depos_dependency_parts "${_depos_dependency_entry}")
    list(GET _depos_dependency_parts 0 _depos_dependency_name)
    list(GET _depos_dependency_parts 1 _depos_dependency_version)
    _depos_find_local_depofile(
      _depos_local_dependency
      "${_depos_search_root}"
      "${_depos_dependency_name}"
      "${_depos_dependency_version}"
    )
    if ("${_depos_local_dependency}" STREQUAL "")
      continue()
    endif()

    string(REPLACE "|" ";" _depos_local_parts "${_depos_local_dependency}")
    list(GET _depos_local_parts 0 _depos_local_name)
    list(GET _depos_local_parts 1 _depos_local_version)
    list(GET _depos_local_parts 2 _depos_local_target)
    list(GET _depos_local_parts 3 _depos_local_depofile)
    _depos_add_pending_depofile(
      "${_depos_local_depofile}"
      "${_depos_local_name}"
      "${_depos_local_version}"
      "${_depos_local_target}"
      "${root}"
      ${local_mode}
      "${_depos_search_root}"
    )
  endforeach()
endfunction()

function(_depos_append_request_line line)
  get_property(_depos_lines GLOBAL PROPERTY DEPOS_REQUEST_LINES)
  if (NOT _depos_lines)
    set(_depos_lines "")
  endif()
  list(FIND _depos_lines "${line}" _depos_line_index)
  if (_depos_line_index EQUAL -1)
    set_property(GLOBAL APPEND PROPERTY DEPOS_REQUEST_LINES "${line}")
    _depos_mark_sync_dirty()
  endif()
endfunction()

function(_depos_write_generated_manifest out_var)
  get_property(_depos_lines GLOBAL PROPERTY DEPOS_REQUEST_LINES)
  if (NOT _depos_lines)
    message(FATAL_ERROR "No depos dependencies have been declared.")
  endif()

  _depos_make_absolute(_depos_manifest_path "${DEPOS_MANIFEST_FILE}")
  get_filename_component(_depos_manifest_dir "${_depos_manifest_path}" DIRECTORY)
  file(MAKE_DIRECTORY "${_depos_manifest_dir}")
  file(WRITE "${_depos_manifest_path}" "# Generated by .depos.cmake.\n")
  foreach(_depos_line IN LISTS _depos_lines)
    file(APPEND "${_depos_manifest_path}" "${_depos_line}\n")
  endforeach()
  set(${out_var} "${_depos_manifest_path}" PARENT_SCOPE)
endfunction()

function(_depos_registry_dir_from_sync_stdout out_var sync_stdout)
  string(REPLACE "\r\n" "\n" _depos_sync_stdout "${sync_stdout}")
  string(REPLACE "\r" "\n" _depos_sync_stdout "${_depos_sync_stdout}")
  string(REPLACE "\n" ";" _depos_sync_lines "${_depos_sync_stdout}")
  foreach(_depos_line IN LISTS _depos_sync_lines)
    string(STRIP "${_depos_line}" _depos_line)
    if (NOT "${_depos_line}" STREQUAL "")
      set(${out_var} "${_depos_line}" PARENT_SCOPE)
      return()
    endif()
  endforeach()

  message(FATAL_ERROR "depos sync did not print a registry directory.")
endfunction()

function(_depos_include_registry registry_dir)
  set(_depos_targets_file "${registry_dir}/targets.cmake")
  if (NOT EXISTS "${_depos_targets_file}")
    message(FATAL_ERROR "Depo registry file is missing: ${_depos_targets_file}")
  endif()

  include("${_depos_targets_file}")
endfunction()

function(_depos_register_pending_depofiles executable_path depos_root local_mode)
  get_property(_depos_pending GLOBAL PROPERTY DEPOS_PENDING_DEPOFILES)
  if (NOT _depos_pending)
    return()
  endif()

  _depos_internal_namespace(_depos_namespace ${local_mode})
  list(LENGTH _depos_pending _depos_pending_count)
  _depos_status("registering ${_depos_pending_count} local DepoFile(s) under namespace ${_depos_namespace}")
  file(MAKE_DIRECTORY "${depos_root}")
  foreach(_depos_entry IN LISTS _depos_pending)
    string(REPLACE "|" ";" _depos_parts "${_depos_entry}")
    list(GET _depos_parts 3 _depos_depofile)
    execute_process(
      COMMAND
        "${executable_path}"
        register
        --depos-root
        "${depos_root}"
        --file
        "${_depos_depofile}"
        --namespace
        "${_depos_namespace}"
      RESULT_VARIABLE _depos_register_result
      OUTPUT_VARIABLE _depos_register_stdout
      ERROR_VARIABLE _depos_register_stderr
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT _depos_register_result EQUAL 0)
      message(
        FATAL_ERROR
        "depos register failed for ${_depos_depofile}\n"
        "stdout:\n${_depos_register_stdout}\n"
        "stderr:\n${_depos_register_stderr}"
      )
    endif()
  endforeach()

  set_property(GLOBAL PROPERTY DEPOS_PENDING_DEPOFILES "")
endfunction()

function(_depos_sync_current_requests)
  _depos_write_generated_manifest(_depos_manifest_path)
  _depos_resolve_runtime(_depos_executable _depos_root _depos_local_mode _depos_namespace)
  _depos_global_property_length(_depos_request_count DEPOS_REQUEST_LINES)
  _depos_runtime_mode_label(_depos_runtime_label ${_depos_local_mode})
  _depos_status("syncing ${_depos_request_count} dependency request(s) with ${_depos_runtime_label} depos")
  _depos_register_pending_depofiles("${_depos_executable}" "${_depos_root}" ${_depos_local_mode})

  execute_process(
    COMMAND
      "${_depos_executable}"
      sync
      --depos-root
      "${_depos_root}"
      --manifest
      "${_depos_manifest_path}"
    RESULT_VARIABLE _depos_sync_result
    OUTPUT_VARIABLE _depos_sync_stdout
    ERROR_VARIABLE _depos_sync_stderr
  )
  if (NOT _depos_sync_result EQUAL 0)
    message(
      FATAL_ERROR
      "depos sync failed for ${_depos_manifest_path}\n"
      "stdout:\n${_depos_sync_stdout}\n"
      "stderr:\n${_depos_sync_stderr}"
    )
  endif()

  _depos_registry_dir_from_sync_stdout(_depos_registry_dir "${_depos_sync_stdout}")
  _depos_include_registry("${_depos_registry_dir}")
  set_property(GLOBAL PROPERTY DEPOS_ACTIVE_REGISTRY_DIR "${_depos_registry_dir}")
  _depos_clear_sync_dirty()
  _depos_status("loaded registry targets from ${_depos_registry_dir}")
endfunction()

function(_depos_manifest_line_from_depofile out_var name version visible_namespace)
  set(_depos_line "depos_require(${name} VERSION ${version}")
  if (NOT "${visible_namespace}" STREQUAL "")
    string(APPEND _depos_line " NAMESPACE ${visible_namespace}")
  endif()
  string(APPEND _depos_line ")")
  set(${out_var} "${_depos_line}" PARENT_SCOPE)
endfunction()

function(_depos_depend_single dep)
  if ("${dep}" STREQUAL "")
    message(FATAL_ERROR "depos_depend requires a package name or DepoFile path.")
  endif()

  set(options)
  set(oneValueArgs PATH NAMESPACE VERSION MIN_VERSION SOURCE AS)
  cmake_parse_arguments(DEPOS_DEPEND "${options}" "${oneValueArgs}" "" ${ARGN})
  set(_depos_explicit_depofile_input FALSE)

  if (NOT "${DEPOS_DEPEND_VERSION}" STREQUAL "" AND NOT "${DEPOS_DEPEND_MIN_VERSION}" STREQUAL "")
    message(FATAL_ERROR "depos_depend cannot use VERSION and MIN_VERSION together.")
  endif()

  if (NOT "${DEPOS_DEPEND_PATH}" STREQUAL "")
    _depos_make_absolute_from_base(_depos_depofile "${DEPOS_DEPEND_PATH}" "${CMAKE_CURRENT_SOURCE_DIR}")
    set(_depos_explicit_depofile_input TRUE)
    if (IS_DIRECTORY "${_depos_depofile}")
      message(FATAL_ERROR "depos_depend PATH must point to a DepoFile, not a directory: ${_depos_depofile}")
    endif()
  elseif (EXISTS "${dep}" OR "${dep}" MATCHES "\\.DepoFile$")
    _depos_make_absolute_from_base(_depos_depofile "${dep}" "${CMAKE_CURRENT_SOURCE_DIR}")
    set(_depos_explicit_depofile_input TRUE)
  else()
    set(_depos_depofile "")
  endif()

  _depos_resolve_runtime(_depos_executable _depos_root _depos_local_mode _depos_visible_namespace)

  if (NOT "${_depos_depofile}" STREQUAL "")
    if (NOT EXISTS "${_depos_depofile}")
      message(FATAL_ERROR "depos_depend path does not exist: ${_depos_depofile}")
    endif()
    _depos_parse_depofile_metadata(_depos_name _depos_version _depos_target "${_depos_depofile}")
    if (NOT "${DEPOS_DEPEND_VERSION}" STREQUAL ""
        AND NOT "${DEPOS_DEPEND_VERSION}" STREQUAL "${_depos_version}")
      message(
        FATAL_ERROR
        "depos_depend(${dep}) requested VERSION ${DEPOS_DEPEND_VERSION}, but the DepoFile declares VERSION ${_depos_version}."
      )
    endif()
    set(_depos_name_token "${_depos_name}")
    set(_depos_version_token "${_depos_version}")
    _depos_add_pending_depofile(
      "${_depos_depofile}"
      "${_depos_name}"
      "${_depos_version}"
      "${_depos_target}"
      "${_depos_root}"
      ${_depos_local_mode}
    )
    if ("${DEPOS_DEPEND_NAMESPACE}" STREQUAL "")
      set(DEPOS_DEPEND_NAMESPACE "${_depos_visible_namespace}")
    endif()
    set(DEPOS_DEPEND_VERSION "${_depos_version}")
  else()
    _depos_find_local_depofile(_depos_entry "" "${dep}" "${DEPOS_DEPEND_VERSION}")
    if (NOT "${_depos_entry}" STREQUAL "")
      string(REPLACE "|" ";" _depos_parts "${_depos_entry}")
      list(GET _depos_parts 0 _depos_name)
      list(GET _depos_parts 1 _depos_version)
      list(GET _depos_parts 2 _depos_target)
      list(GET _depos_parts 3 _depos_depofile)
      _depos_add_pending_depofile(
        "${_depos_depofile}"
        "${_depos_name}"
        "${_depos_version}"
        "${_depos_target}"
        "${_depos_root}"
        ${_depos_local_mode}
      )
      if ("${DEPOS_DEPEND_NAMESPACE}" STREQUAL "")
        set(DEPOS_DEPEND_NAMESPACE "${_depos_visible_namespace}")
      endif()
      if ("${DEPOS_DEPEND_VERSION}" STREQUAL "" AND "${DEPOS_DEPEND_MIN_VERSION}" STREQUAL "")
        set(DEPOS_DEPEND_VERSION "${_depos_version}")
      endif()
    endif()
    set(_depos_name_token "${dep}")
  endif()

  _depos_assert_single_token("depos_depend package name" "${_depos_name_token}")
  set(_depos_line "depos_require(${_depos_name_token}")
  foreach(_depos_key IN ITEMS NAMESPACE VERSION MIN_VERSION SOURCE AS)
    if (NOT "${DEPOS_DEPEND_${_depos_key}}" STREQUAL "")
      _depos_assert_single_token("${_depos_key}" "${DEPOS_DEPEND_${_depos_key}}")
      string(APPEND _depos_line " ${_depos_key} ${DEPOS_DEPEND_${_depos_key}}")
    endif()
  endforeach()
  string(APPEND _depos_line ")")

  set(_depos_status_request "${_depos_name_token}")
  if (NOT "${DEPOS_DEPEND_VERSION}" STREQUAL "")
    string(APPEND _depos_status_request " VERSION ${DEPOS_DEPEND_VERSION}")
  elseif (NOT "${DEPOS_DEPEND_MIN_VERSION}" STREQUAL "")
    string(APPEND _depos_status_request " MIN_VERSION ${DEPOS_DEPEND_MIN_VERSION}")
  endif()
  if (_depos_explicit_depofile_input)
    string(APPEND _depos_status_request " from ${_depos_depofile}")
  endif()

  _depos_status("requesting ${_depos_status_request}")
  _depos_append_request_line("${_depos_line}")
endfunction()

function(depos_depend)
  if (ARGC EQUAL 0)
    message(FATAL_ERROR "depos_depend requires a package name, DepoFile path, FILE, or FILES.")
  endif()

  set(options)
  set(oneValueArgs PATH NAMESPACE VERSION MIN_VERSION SOURCE AS FILE)
  set(multiValueArgs FILES)
  cmake_parse_arguments(DEPOS_DEPEND "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  set(_depos_files "")
  if (NOT "${DEPOS_DEPEND_FILE}" STREQUAL "")
    list(APPEND _depos_files "${DEPOS_DEPEND_FILE}")
  endif()
  if (DEPOS_DEPEND_FILES)
    list(APPEND _depos_files ${DEPOS_DEPEND_FILES})
  endif()

  if (_depos_files)
    if (DEPOS_DEPEND_UNPARSED_ARGUMENTS)
      message(FATAL_ERROR "depos_depend(FILE/FILES ...) does not accept positional package names or DepoFile paths.")
    endif()
    foreach(_depos_key IN ITEMS PATH NAMESPACE VERSION MIN_VERSION SOURCE AS)
      if (NOT "${DEPOS_DEPEND_${_depos_key}}" STREQUAL "")
        message(FATAL_ERROR "depos_depend(FILE/FILES ...) only accepts DepoFile paths.")
      endif()
    endforeach()
    foreach(_depos_file IN LISTS _depos_files)
      _depos_depend_single("${_depos_file}")
    endforeach()
    return()
  endif()

  list(LENGTH DEPOS_DEPEND_UNPARSED_ARGUMENTS _depos_unparsed_count)
  if (_depos_unparsed_count EQUAL 0)
    message(FATAL_ERROR "depos_depend requires a package name or DepoFile path.")
  endif()
  if (_depos_unparsed_count GREATER 1)
    message(FATAL_ERROR "depos_depend accepts one package name or DepoFile path unless FILES is used.")
  endif()

  set(_depos_forward_args "")
  foreach(_depos_key IN ITEMS PATH NAMESPACE VERSION MIN_VERSION SOURCE AS)
    if (NOT "${DEPOS_DEPEND_${_depos_key}}" STREQUAL "")
      list(APPEND _depos_forward_args "${_depos_key}" "${DEPOS_DEPEND_${_depos_key}}")
    endif()
  endforeach()

  list(GET DEPOS_DEPEND_UNPARSED_ARGUMENTS 0 _depos_dep)
  _depos_depend_single("${_depos_dep}" ${_depos_forward_args})
endfunction()

function(depos_depend_all)
  set(_depos_search_root "")
  if (ARGC GREATER 1)
    message(FATAL_ERROR "depos_depend_all accepts zero arguments or one depofiles directory path.")
  elseif (ARGC EQUAL 1)
    _depos_make_absolute_from_base(_depos_search_root "${ARGV0}" "${CMAKE_CURRENT_SOURCE_DIR}")
    if (NOT EXISTS "${_depos_search_root}")
      message(
        FATAL_ERROR
        "depos_depend_all expects an existing depofiles directory path, but it does not exist: ${_depos_search_root}"
      )
    endif()
    if (NOT IS_DIRECTORY "${_depos_search_root}")
      message(
        FATAL_ERROR
        "depos_depend_all expects a depofiles directory path, but received a file path: ${_depos_search_root}"
      )
    endif()
  endif()

  if ("${_depos_search_root}" STREQUAL "")
    _depos_default_depofiles_dir(_depos_depofiles_dir)
  else()
    _depos_make_absolute_from_base(_depos_depofiles_dir "${_depos_search_root}" "${CMAKE_CURRENT_SOURCE_DIR}")
  endif()

  _depos_depofile_entries(_depos_entries "${_depos_depofiles_dir}")
  if (NOT _depos_entries)
    message(FATAL_ERROR "depos_depend_all found no .DepoFile files under ${_depos_depofiles_dir}")
  endif()

  list(LENGTH _depos_entries _depos_entry_count)
  _depos_status("requesting all ${_depos_entry_count} DepoFile(s) under ${_depos_depofiles_dir}")
  _depos_resolve_runtime(_depos_executable _depos_root _depos_local_mode _depos_visible_namespace)
  foreach(_depos_entry IN LISTS _depos_entries)
    string(REPLACE "|" ";" _depos_parts "${_depos_entry}")
    list(GET _depos_parts 0 _depos_name)
    list(GET _depos_parts 1 _depos_version)
    list(GET _depos_parts 2 _depos_target)
    list(GET _depos_parts 3 _depos_depofile)
    _depos_add_pending_depofile(
      "${_depos_depofile}"
      "${_depos_name}"
      "${_depos_version}"
      "${_depos_target}"
      "${_depos_root}"
      ${_depos_local_mode}
    )
    _depos_manifest_line_from_depofile(_depos_line "${_depos_name}" "${_depos_version}" "${_depos_visible_namespace}")
    _depos_append_request_line("${_depos_line}")
  endforeach()
endfunction()

function(depos_link target_name)
  if ("${target_name}" STREQUAL "")
    message(FATAL_ERROR "depos_link requires a CMake target name.")
  endif()
  if (NOT TARGET "${target_name}")
    message(FATAL_ERROR "depos_link target does not exist: ${target_name}")
  endif()
  if (ARGC LESS 2)
    message(FATAL_ERROR "depos_link requires at least one dependency or imported target.")
  endif()

  set(_depos_visibility "PUBLIC")
  set(_depos_items ${ARGN})
  if (_depos_items)
    list(GET _depos_items 0 _depos_first_item)
    if (_depos_first_item STREQUAL "PUBLIC" OR _depos_first_item STREQUAL "PRIVATE")
      set(_depos_visibility "${_depos_first_item}")
      list(REMOVE_AT _depos_items 0)
    endif()
  endif()
  if (NOT _depos_items)
    message(FATAL_ERROR "depos_link requires at least one dependency or imported target.")
  endif()

  _depos_ensure_registry_ready()

  set(_depos_targets "")
  foreach(_depos_item IN LISTS _depos_items)
    if ("${_depos_item}" STREQUAL "${target_name}")
      continue()
    endif()
    _depos_lookup_package_target(_depos_mapped_target "${_depos_item}")
    if ("${_depos_mapped_target}" STREQUAL "")
      list(APPEND _depos_targets "${_depos_item}")
    else()
      list(APPEND _depos_targets "${_depos_mapped_target}")
    endif()
  endforeach()

  if (NOT _depos_targets)
    message(FATAL_ERROR "depos_link did not receive any link targets after resolving package names.")
  endif()

  target_link_libraries("${target_name}" ${_depos_visibility} ${_depos_targets})
endfunction()

function(depos_link_all target_name)
  if ("${target_name}" STREQUAL "")
    message(FATAL_ERROR "depos_link_all requires a CMake target name.")
  endif()
  if (NOT TARGET "${target_name}")
    message(FATAL_ERROR "depos_link_all target does not exist: ${target_name}")
  endif()
  if (ARGC GREATER 2)
    message(FATAL_ERROR "depos_link_all accepts a target name and an optional PUBLIC or PRIVATE visibility.")
  endif()

  set(_depos_visibility "PUBLIC")
  if (ARGC EQUAL 2)
    if (NOT ("${ARGV1}" STREQUAL "PUBLIC" OR "${ARGV1}" STREQUAL "PRIVATE"))
      message(FATAL_ERROR "depos_link_all visibility must be PUBLIC or PRIVATE.")
    endif()
    set(_depos_visibility "${ARGV1}")
  endif()

  get_property(_depos_targets GLOBAL PROPERTY DEPOS_ALL_PRIMARY_TARGETS)
  if (NOT _depos_targets)
    message(FATAL_ERROR "depos_link_all requires at least one known DepoFile primary target.")
  endif()

  _depos_ensure_registry_ready()

  target_link_libraries("${target_name}" ${_depos_visibility} ${_depos_targets})
endfunction()

function(depos_use)
  set(options)
  set(oneValueArgs MANIFEST REGISTRY_DIR)
  cmake_parse_arguments(DEPOS_USE "${options}" "${oneValueArgs}" "" ${ARGN})

  if ("${DEPOS_USE_MANIFEST}" STREQUAL "" AND "${DEPOS_USE_REGISTRY_DIR}" STREQUAL "")
    message(FATAL_ERROR "depos_use requires MANIFEST or REGISTRY_DIR.")
  endif()

  if (NOT "${DEPOS_USE_MANIFEST}" STREQUAL "" AND NOT "${DEPOS_USE_REGISTRY_DIR}" STREQUAL "")
    message(FATAL_ERROR "depos_use accepts MANIFEST or REGISTRY_DIR, not both.")
  endif()

  if (NOT "${DEPOS_USE_REGISTRY_DIR}" STREQUAL "")
    _depos_make_absolute(_depos_registry_dir "${DEPOS_USE_REGISTRY_DIR}")
    _depos_include_registry("${_depos_registry_dir}")
    return()
  endif()

  _depos_make_absolute_from_base(_depos_manifest "${DEPOS_USE_MANIFEST}" "${CMAKE_CURRENT_SOURCE_DIR}")
  _depos_resolve_runtime(_depos_executable _depos_root _depos_local_mode _depos_namespace)
  execute_process(
    COMMAND
      "${_depos_executable}"
      sync
      --depos-root
      "${_depos_root}"
      --manifest
      "${_depos_manifest}"
    RESULT_VARIABLE _depos_sync_result
    OUTPUT_VARIABLE _depos_sync_stdout
    ERROR_VARIABLE _depos_sync_stderr
  )
  if (NOT _depos_sync_result EQUAL 0)
    message(
      FATAL_ERROR
      "depos sync failed for ${_depos_manifest}\n"
      "stdout:\n${_depos_sync_stdout}\n"
      "stderr:\n${_depos_sync_stderr}"
    )
  endif()

  _depos_registry_dir_from_sync_stdout(_depos_registry_dir "${_depos_sync_stdout}")
  _depos_include_registry("${_depos_registry_dir}")
endfunction()
