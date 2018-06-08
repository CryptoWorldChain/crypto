cmake_minimum_required(VERSION 3.11.3)



project(icrypto)


set (ICRYPTO_VERSION_MAJOR 1)
set (ICRYPTO_VERSION_MINOR 0)

include_directories( /opt/intel/ipp/include)
LINK_DIRECTORIES(/opt/intel/ipp/lib)

include_directories( /opt/intel/ippcp/include)
LINK_DIRECTORIES(/opt/intel/ippcp/lib)

include_directories(/Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include)
include_directories(/Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include/darwin)
#LINK_DIRECTORIES(/Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk/Contents/Home/include_directories)


add_executable(test 
	src/test.cpp 
	src/utils.cpp 
	src/IppEnc.cpp 
	src/icrypto_impl.cpp
)


TARGET_LINK_LIBRARIES(test libippcp.a)


add_library(ippcwv SHARED src/utils.cpp 
	src/IppEnc.cpp 
	src/icrypto_impl.cpp)


TARGET_LINK_LIBRARIES(ippcwv libippcp.a)

