# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.11

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.11.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.11.3/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build

# Include any dependencies generated for this target.
include CMakeFiles/ippcwv.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ippcwv.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ippcwv.dir/flags.make

CMakeFiles/ippcwv.dir/src/utils.cpp.o: CMakeFiles/ippcwv.dir/flags.make
CMakeFiles/ippcwv.dir/src/utils.cpp.o: ../src/utils.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ippcwv.dir/src/utils.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ippcwv.dir/src/utils.cpp.o -c /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/utils.cpp

CMakeFiles/ippcwv.dir/src/utils.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ippcwv.dir/src/utils.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/utils.cpp > CMakeFiles/ippcwv.dir/src/utils.cpp.i

CMakeFiles/ippcwv.dir/src/utils.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ippcwv.dir/src/utils.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/utils.cpp -o CMakeFiles/ippcwv.dir/src/utils.cpp.s

CMakeFiles/ippcwv.dir/src/IppEnc.cpp.o: CMakeFiles/ippcwv.dir/flags.make
CMakeFiles/ippcwv.dir/src/IppEnc.cpp.o: ../src/IppEnc.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/ippcwv.dir/src/IppEnc.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ippcwv.dir/src/IppEnc.cpp.o -c /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/IppEnc.cpp

CMakeFiles/ippcwv.dir/src/IppEnc.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ippcwv.dir/src/IppEnc.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/IppEnc.cpp > CMakeFiles/ippcwv.dir/src/IppEnc.cpp.i

CMakeFiles/ippcwv.dir/src/IppEnc.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ippcwv.dir/src/IppEnc.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/IppEnc.cpp -o CMakeFiles/ippcwv.dir/src/IppEnc.cpp.s

CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.o: CMakeFiles/ippcwv.dir/flags.make
CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.o: ../src/icrypto_impl.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.o -c /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/icrypto_impl.cpp

CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/icrypto_impl.cpp > CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.i

CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/src/icrypto_impl.cpp -o CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.s

# Object files for target ippcwv
ippcwv_OBJECTS = \
"CMakeFiles/ippcwv.dir/src/utils.cpp.o" \
"CMakeFiles/ippcwv.dir/src/IppEnc.cpp.o" \
"CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.o"

# External object files for target ippcwv
ippcwv_EXTERNAL_OBJECTS =

libippcwv.dylib: CMakeFiles/ippcwv.dir/src/utils.cpp.o
libippcwv.dylib: CMakeFiles/ippcwv.dir/src/IppEnc.cpp.o
libippcwv.dylib: CMakeFiles/ippcwv.dir/src/icrypto_impl.cpp.o
libippcwv.dylib: CMakeFiles/ippcwv.dir/build.make
libippcwv.dylib: CMakeFiles/ippcwv.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX shared library libippcwv.dylib"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ippcwv.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ippcwv.dir/build: libippcwv.dylib

.PHONY : CMakeFiles/ippcwv.dir/build

CMakeFiles/ippcwv.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ippcwv.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ippcwv.dir/clean

CMakeFiles/ippcwv.dir/depend:
	cd /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build /Users/brew/Documents/BC/codes/tl/chaincore/crypto/brewchain-crypto/icrypto/build/CMakeFiles/ippcwv.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ippcwv.dir/depend
