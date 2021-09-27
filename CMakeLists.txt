cmake_minimum_required (VERSION 3.16)

project(quicperf LANGUAGES C CXX)

set(VERBOSE ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON) # gnu

if(NOT DEFINED BUILD_PICOPERF OR BUILD_LSPERF OR BUILD_QUICHEPERF OR BUILD_NGTCP2PERF OR BUILD_TCPPERF)
	if(NOT DEFINED BUILD_PICOPERF)
		set(BUILD_PICOPERF 1)
		add_executable(picoperf perf.cpp)
	endif()

	if(NOT DEFINED BUILD_LSPERF)
		set(BUILD_LSPERF 1)
		add_executable(lsperf perf.cpp)
	endif()

	if(NOT DEFINED BUILD_QUICHEPERF)
		set(BUILD_QUICHEPERF 1)
		add_executable(quicheperf perf.cpp)
	endif()

	set(BUILD_NGTCP2PERF 0) # main is broken right now 

	if(NOT DEFINED BUILD_NGTCP2PERF)
		set(BUILD_NGTCP2PERF 1)
		add_executable(ngtcp2perf perf.cpp)
	endif()

	if(NOT DEFINED BUILD_TCPPERF)
		set(BUILD_TCPPERF 1)
		add_executable(tcpperf perf.cpp)
	endif()
else()

	if(BUILD_PICOPERF)
		add_executable(picoperf perf.cpp)
	endif()

	if(BUILD_LSPERF)
		add_executable(lsperf perf.cpp)
	endif()

	if(BUILD_QUICHEPERF)
		add_executable(quicheperf perf.cpp)
	endif()

	set(BUILD_NGTCP2PERF 0) # main is broken right now 

	if(BUILD_NGTCP2PERF)
		add_executable(ngtcp2perf perf.cpp)
	endif()

	if(BUILD_TCPPERF)
		add_executable(tcpperf perf.cpp)
	endif()
endif()

include(ExternalProject)

set_directory_properties(PROPERTIES EP_BASE "${CMAKE_BINARY_DIR}/3rdparty")
set(3rdParty_SDIR ${CMAKE_BINARY_DIR}/3rdparty/Source)
set(3rdParty_BDIR ${CMAKE_BINARY_DIR}/3rdparty/Build)

ExternalProject_Add(liburing
	GIT_REPOSITORY https://github.com/axboe/liburing.git
	GIT_TAG master
	BUILD_IN_SOURCE ON
	GIT_SHALLOW ON
	CONFIGURE_COMMAND ${3rdParty_SDIR}/liburing/configure
	BUILD_COMMAND make -j4 
	INSTALL_COMMAND ""
)

if (BUILD_LSPERF OR BUILD_NGTCP2PERF OR BUILD_TCPPERF)

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

	ExternalProject_Add(boringssl
		DEPENDS zlib 
	  	GIT_REPOSITORY https://github.com/google/boringssl.git
	  	GIT_TAG master
	  	GIT_SHALLOW ON
	  	BUILD_COMMAND cmake --build . --config Release -- -j 4
	  	UPDATE_COMMAND ""
	  	CMAKE_ARGS
	  		-DCMAKE_C_FLAGS="-w"
			-DCMAKE_BUILD_TYPE=Release
			-DGO_EXECUTABLE:FILEPATH=${GO_EXECUTABLE}
		INSTALL_COMMAND ""
	)
	add_dependencies(tcpperf boringssl)

	if (BUILD_LSPERF)

		add_dependencies(lsperf liburing)

		ExternalProject_Add(lsquic
			DEPENDS boringssl 
			#GIT_REPOSITORY https://github.com/litespeedtech/lsquic.git
			GIT_REPOSITORY https://github.com/victorstewart/lsquic.git
			GIT_TAG master
			GIT_SHALLOW ON
			BUILD_IN_SOURCE ON
			CMAKE_ARGS
				-DCMAKE_BUILD_TYPE=Release
				-DBORINGSSL_INCLUDE=${3rdParty_SDIR}/boringssl/include
				-DBORINGSSL_DIR=${3rdParty_BDIR}/boringssl
			INSTALL_COMMAND ""
		)
		add_dependencies(lsperf lsquic)
		target_compile_options(lsperf PUBLIC -DLSPERF -w -mavx2 -flto -Ofast -frename-registers -fno-signed-zeros -fno-trapping-math)

		target_include_directories(lsperf PUBLIC  ${3rdParty_SDIR}/boringssl/include
																${3rdParty_SDIR}/liburing/src/include
																${3rdParty_SDIR}/lsquic/include
																)

		target_link_libraries(lsperf 	pthread
												${3rdParty_BDIR}/boringssl/crypto/libcrypto.a
												${3rdParty_BDIR}/boringssl/ssl/libssl.a
												${3rdParty_BDIR}/zlib/libz.a
												${3rdParty_SDIR}/lsquic/src/liblsquic/liblsquic.a 
												${3rdParty_SDIR}/liburing/src/liburing.a
												)

		add_custom_command(TARGET lsperf 
                   		 POST_BUILD
                   		 COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lsperf> ..)
	endif()

	if (BUILD_NGTCP2PERF)

		add_dependencies(ngtcp2perf liburing)
		set(boringssl_libs "-L${3rdParty_BDIR}/boringssl/ssl -lssl -L${3rdParty_BDIR}/boringssl/crypto -lcrypto -pthread")
		ExternalProject_Add(ngtcp2
			DEPENDS boringssl
			GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
			GIT_TAG main
			GIT_SHALLOW OFF

			CMAKE_ARGS
				-DBORINGSSL_LIBRARIES=${boringssl_libs}
				-DBORINGSSL_INCLUDE_DIR=${3rdParty_SDIR}/boringssl/include
			INSTALL_COMMAND ""
		)
		add_dependencies(ngtcp2perf ngtcp2)
		target_compile_options(ngtcp2perf PUBLIC -DNGTCP2PERF -w -mavx2 -flto -Ofast -frename-registers -fno-signed-zeros -fno-trapping-math)

		target_include_directories(ngtcp2perf PUBLIC ${3rdParty_SDIR}/boringssl/include
														 ${3rdParty_SDIR}/liburing/src/include
														 ${3rdParty_SDIR}/ngtcp2/lib/includes
														 ${3rdParty_BDIR}/ngtcp2/lib/includes
														 ${3rdParty_SDIR}/ngtcp2/crypto/includes
													)

		target_link_libraries(ngtcp2perf pthread
													${3rdParty_BDIR}/boringssl/crypto/libcrypto.a
													${3rdParty_BDIR}/boringssl/ssl/libssl.a
													${3rdParty_BDIR}/zlib/libz.a
													${3rdParty_BDIR}/ngtcp2/lib/libngtcp2.a
													${3rdParty_BDIR}/ngtcp2/crypto/boringssl/libngtcp2_crypto_boringssl.a
													${3rdParty_SDIR}/liburing/src/liburing.a
													)
		add_custom_command(TARGET ngtcp2perf
                   		 POST_BUILD
                   		 COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ngtcp2perf> ..)
	endif()

	if (BUILD_TCPPERF)

		target_compile_options(tcpperf PUBLIC -DTCPPERF -w -mavx2 -flto -Ofast -frename-registers -fno-signed-zeros -fno-trapping-math)
		target_include_directories(tcpperf PUBLIC ${3rdParty_SDIR}/boringssl/include )

		target_link_libraries(tcpperf pthread
												${3rdParty_BDIR}/boringssl/crypto/libcrypto.a
												${3rdParty_BDIR}/boringssl/ssl/libssl.a
									)
		add_custom_command(TARGET tcpperf
                   	 	 POST_BUILD
                   		 COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:tcpperf> ..)
	endif()
	
endif()

if (BUILD_QUICHEPERF)

	add_dependencies(quicheperf liburing)
	ExternalProject_Add(rust
		URL https://static.rust-lang.org/dist/rust-1.51.0-x86_64-unknown-linux-gnu.tar.gz 
		DOWNLOAD_NAME rust
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND ""
	)

	ExternalProject_Add(quiche
		DEPENDS rust 
	   GIT_REPOSITORY https://github.com/cloudflare/quiche.git
		GIT_TAG 0.8.1
		GIT_SHALLOW ON
		CONFIGURE_COMMAND ""
		BUILD_IN_SOURCE ON
	   BUILD_COMMAND ${CMAKE_COMMAND} -E env RUSTC=${3rdParty_SDIR}/rust/rustc/bin/rustc ${CMAKE_COMMAND} -E env RUSTFLAGS=-L${3rdParty_SDIR}/rust/rust-std-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib ${3rdParty_SDIR}/rust/cargo/bin/cargo build --features ffi --release
	   INSTALL_COMMAND ""
	)

	add_dependencies(quicheperf quiche)
	target_compile_options(quicheperf PUBLIC -DQUICHEPERF -w -mavx2 -flto -Ofast -frename-registers -fno-signed-zeros -fno-trapping-math)

	target_include_directories(quicheperf PUBLIC ${3rdParty_SDIR}/liburing/src/include
														   	${3rdParty_SDIR}/boringssl/include
														 		${3rdParty_SDIR}/quiche/include
																)

	target_link_libraries(quicheperf 	pthread
													dl
													${3rdParty_SDIR}/quiche/target/release/libquiche.a
													${3rdParty_SDIR}/liburing/src/liburing.a
													)
	add_custom_command(TARGET quicheperf 
                   POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:quicheperf> ..)
endif()

if (BUILD_PICOPERF)

	find_package(OpenSSL REQUIRED)
	add_dependencies(picoperf liburing)

	# at the moment picotls is still finding the system openssl...
	ExternalProject_Add(picotls

		GIT_REPOSITORY https://github.com/h2o/picotls.git
		GIT_TAG master
		GIT_SHALLOW ON
		BUILD_COMMAND make -j4 
		INSTALL_COMMAND ""
	)

	ExternalProject_Add(picoquic
		DEPENDS picotls 

		GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
		GIT_TAG master
		GIT_SHALLOW ON
		CMAKE_ARGS
			-DPTLS_INCLUDE_DIR=${3rdParty_SDIR}/picotls/include
			-DPTLS_LIBRARIES=${3rdParty_BDIR}/picotls
		INSTALL_COMMAND ""
	)
	add_dependencies(picoperf picoquic)
	target_compile_options(picoperf PUBLIC -DPICOPERF -w -mavx2 -flto -Ofast -frename-registers -fno-signed-zeros -fno-trapping-math)

	target_include_directories(picoperf PUBLIC 	${3rdParty_SDIR}/liburing/src/include
														 		${3rdParty_SDIR}/picoquic/picoquic
														 		${3rdParty_SDIR}/picotls/include
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

	add_custom_command(TARGET picoperf 
                   POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:picoperf> ..)
endif()
