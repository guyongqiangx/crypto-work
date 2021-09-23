cmake_minimum_required(VERSION 3.14)
project(gtestlib)

# GoogleTest requires at least C++11
set(CMAKE_CXX_STANDARD 11)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# #
# # 1. Fetch source via git
# #
# FetchContent_Declare(
#   googletest
#   GIT_REPOSITORY https://github.com/google/googletest.git
#   GIT_TAG        703bd9caab50b139428cea1aaff9974ebee5742e # release-1.10.0
# )

# #
# # 2. Fetch source via file (with md5sum check)
# #
# FetchContent_Declare(
#   googletest
#   URL      https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
#   URL_HASH MD5=0a912f72cbe9d4e2c976e49219433cb1
# )
