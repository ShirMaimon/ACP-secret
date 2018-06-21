cmake_minimum_required(VERSION 2.8)
project(cointoss)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++14 -maes -mpclmul -mbmi2 -fext-numeric-literals")

INCLUDE_DIRECTORIES(
		$ENV{HOME}/ACP
		$ENV{HOME}/libscapi/install/include/
		$ENV{HOME}/
		$ENV{HOME}/libscapi/
		$ENV{HOME}/libscapi/install/include/boost
	$ENV{HOME}/ACP/comm_client
)

set(SOURCE_FILES
	cc_coin_toss.cpp
	cc_udp_test.cpp
	coin_toss_test.cpp
	coin_toss_tester.cpp
		ProtocolParty.h TemplateField.h TemplateField.cpp
		GF2_8LookupTable.cpp GF2_8LookupTable.h
)

link_directories(
	$ENV{HOME}/ACP/comm_client
        /usr/local/opt $ENV{HOME}/libscapi/install/lib
)

add_executable(cointoss ${SOURCE_FILES} ProtocolParty.h TemplateField.h TemplateField.cpp GF2_8LookupTable.cpp GF2_8LookupTable.h)

TARGET_LINK_LIBRARIES( cointoss
	commclient
	log4cpp
	event
		libntl.a
		$ENV{HOME}/libscapi/libscapi.a gmp
		libboost_system.a libboost_thread.a pthread crypto dl ssl z
)


