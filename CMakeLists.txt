cmake_minimum_required (VERSION 3.18)

project(quicperf LANGUAGES C CXX)

set(VERBOSE ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON) # gnu

add_executable(lsperf perf.cpp)
add_executable(picoperf perf.cpp)

include(ExternalProject)

set_directory_properties(PROPERTIES EP_BASE "${CMAKE_BINARY_DIR}/3rdparty")
set(3rdParty_SDIR ${CMAKE_BINARY_DIR}/3rdparty/Source)
set(3rdParty_BDIR ${CMAKE_BINARY_DIR}/3rdparty/Build)

ExternalProject_Add(zlib
	GIT_REPOSITORY https://github.com/madler/zlib.git
	GIT_TAG "cacf7f1d4e3d44d871b605da3b647f07d718623f"
	GIT_SHALLOW ON
	CMAKE_ARGS
		-DBUILD_EXAMPLES:BOOL=OFF
		-DBUILD_SHARED_LIBS:BOOL=OFF
		-DSKIP_INSTALL_FILES:BOOL=ON
	INSTALL_COMMAND ""
)

# you'll need to have the go executable on your system
find_program(GO_EXECUTABLE go REQUIRED)
find_package(OpenSSL REQUIRED)

ExternalProject_Add(boringssl
	DEPENDS zlib 
  	GIT_REPOSITORY https://github.com/google/boringssl.git
  	GIT_TAG master
  	GIT_SHALLOW ON
 #  	DOWNLOAD_COMMAND ""
	# SOURCE_DIR ${3rdParty_SDIR}/boringssl
  	BUILD_COMMAND cmake --build . --config Release -- -j 4
  	UPDATE_COMMAND ""
  	CMAKE_ARGS
		-DCMAKE_BUILD_TYPE=Release
		-DGO_EXECUTABLE:FILEPATH=${GO_EXECUTABLE}
	INSTALL_COMMAND ""
)
ExternalProject_Add(lsquic
	DEPENDS boringssl 
	GIT_REPOSITORY https://github.com/litespeedtech/lsquic.git
	GIT_TAG master
	GIT_SHALLOW ON
	# DOWNLOAD_COMMAND ""
	# SOURCE_DIR ${3rdParty_SDIR}/lsquic
	BUILD_IN_SOURCE ON
	CMAKE_ARGS
		-DCMAKE_BUILD_TYPE=Release
		-DBORINGSSL_INCLUDE=${3rdParty_SDIR}/boringssl/include
	INSTALL_COMMAND ""
)
add_dependencies(lsperf lsquic)

ExternalProject_Add(liburing
	GIT_REPOSITORY https://github.com/axboe/liburing.git
	GIT_TAG master
	BUILD_IN_SOURCE ON
	GIT_SHALLOW ON
	CONFIGURE_COMMAND ${3rdParty_SDIR}/liburing/configure
	BUILD_COMMAND make -j4 
	INSTALL_COMMAND ""
)
add_dependencies(lsperf liburing)
add_dependencies(picoperf liburing)

# ExternalProject_Add(openssl
# 	URL https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1k.tar.gz
# 	DOWNLOAD_NAME openssl.tar.gz
# 	CONFIGURE_COMMAND ${3rdParty_SDIR}/openssl/config
# 	BUILD_COMMAND make -j4 
# 	INSTALL_COMMAND ""
# )

# at the moment picotls is still finding the system openssl...
ExternalProject_Add(picotls
	#DEPENDS openssl 

	GIT_REPOSITORY https://github.com/h2o/picotls.git
	GIT_TAG master
	GIT_SHALLOW ON

	# SOURCE_DIR /root/dev/picotls
	# BUILD_ALWAYS ON

	BUILD_COMMAND make -j4 
	INSTALL_COMMAND ""
)

ExternalProject_Add(picoquic
	DEPENDS picotls 

	GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
	GIT_TAG master
	GIT_SHALLOW ON

	# SOURCE_DIR /root/dev/picoquic
	# BUILD_ALWAYS ON

	CMAKE_ARGS
		-DPTLS_INCLUDE_DIR=/root/picotls/include
		-DPTLS_LIBRARIES=${3rdParty_BDIR}/picotls
	INSTALL_COMMAND ""
)
add_dependencies(picoperf picoquic)

target_compile_options(lsperf PUBLIC -DLSPERF -w -mavx2 -flto -Ofast -frename-registers -fno-signed-zeros -fno-trapping-math)
target_compile_options(picoperf PUBLIC -DPICOPERF -w -mavx2 -flto -Ofast -frename-registers -fno-signed-zeros -fno-trapping-math)


target_include_directories(lsperf PUBLIC  ${3rdParty_SDIR}/boringssl/include
														${3rdParty_SDIR}/liburing/src/include
														${3rdParty_SDIR}/lsquic/include
													)

target_include_directories(picoperf PUBLIC ${3rdParty_SDIR}/liburing/src/include
														 ${3rdParty_SDIR}/picoquic/picoquic
														 ${3rdParty_SDIR}/picotls/include
													)

target_link_libraries(lsperf 	pthread
										${3rdParty_BDIR}/boringssl/crypto/libcrypto.a
										${3rdParty_BDIR}/boringssl/ssl/libssl.a
										${3rdParty_BDIR}/zlib/libz.a
										${3rdParty_SDIR}/lsquic/src/liblsquic/liblsquic.a 
										${3rdParty_SDIR}/liburing/src/liburing.a
									)

target_link_libraries(picoperf 	pthread
											dl
											OpenSSL::Crypto
											OpenSSL::SSL
											${3rdParty_BDIR}/picotls/libpicotls-core.a
											${3rdParty_BDIR}/picotls/libpicotls-fusion.a
											${3rdParty_BDIR}/picotls/libpicotls-openssl.a
											${3rdParty_BDIR}/picoquic/libpicoquic-core.a
											${3rdParty_SDIR}/liburing/src/liburing.a
										)

add_custom_command(TARGET lsperf 
                   POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lsperf> ..)

add_custom_command(TARGET picoperf 
                   POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:picoperf> ..)