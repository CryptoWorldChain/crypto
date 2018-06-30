cmake_minimum_required(VERSION 3.11.3)



project(icrypto)


set (ICRYPTO_VERSION_MAJOR 1)
set (ICRYPTO_VERSION_MINOR 0)
set(CMAKE_BUILD_TYPE Release)


include_directories( /opt/intel/ipp/include)
LINK_DIRECTORIES(/opt/intel/ippcp/lib)

include_directories( /opt/intel/ippcp/include)

include_directories(/Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include)
include_directories(/Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include/darwin)
#LINK_DIRECTORIES(/Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include_directories)


add_executable(test 
	src/test.cpp 
	src/utils.cpp 
	src/IppEnc.cpp 
	src/icrypto_impl.cpp
	src/utils.cpp
	src/icrypto_impl.cpp
	src/test.cpp
	src/IppEnc.cpp
	#src/hash-library/digest.cpp
	src/hash-library/md5.cpp
	src/hash-library/crc32.cpp
	#src/hash-library/tests/tests.cpp
	src/hash-library/sha1.cpp
	src/hash-library/sha3.cpp
	src/hash-library/sha256.cpp
	src/hash-library/keccak.cpp
)

set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-all_load")
set(LINK_FLAGS ${LINK_FLAGS} "-Wl,-all_load")
set(LINK_FLAGS ${LINK_FLAGS} "-WL,-rpath,./libippcwv.dylib")

TARGET_LINK_LIBRARIES(test libippcp.a)


add_library(ippcwv SHARED src/utils.cpp 
	src/IppEnc.cpp 
	src/icrypto_impl.cpp
	src/utils.cpp
	src/icrypto_impl.cpp
	src/test.cpp
	src/IppEnc.cpp
	#src/hash-library/digest.cpp
	src/hash-library/md5.cpp
	src/hash-library/crc32.cpp
	#src/hash-library/tests/tests.cpp
	src/hash-library/sha1.cpp
	src/hash-library/sha3.cpp
	src/hash-library/sha256.cpp
	src/hash-library/keccak.cpp

	)


TARGET_LINK_LIBRARIES(ippcwv libippcp.a)

