cmake_minimum_required(VERSION 3.8)
project(rsa_demo_cpp)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
endif()

# find dependencies
find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(include)

add_library(crypto_utils
  src/crypto_utils.cpp
)
target_link_libraries(crypto_utils OpenSSL::Crypto)
target_include_directories(crypto_utils PUBLIC include)

add_executable(key_directory_node src/key_directory_node.cpp)
target_link_libraries(key_directory_node crypto_utils)
ament_target_dependencies(key_directory_node rclcpp std_msgs)

add_executable(alice_node src/alice_node.cpp)
target_link_libraries(alice_node crypto_utils)
ament_target_dependencies(alice_node rclcpp std_msgs)

add_executable(bob_node src/bob_node.cpp)
target_link_libraries(bob_node crypto_utils)
ament_target_dependencies(bob_node rclcpp std_msgs)

add_executable(eve_node src/eve_node.cpp)
target_link_libraries(eve_node crypto_utils)
ament_target_dependencies(eve_node rclcpp std_msgs)

install(TARGETS
  key_directory_node
  alice_node
  bob_node
  eve_node
  crypto_utils
  DESTINATION lib/${PROJECT_NAME})

if(BUILD_TESTING)
  find_package(ament_cmake_gtest REQUIRED)

  ament_add_gtest(test_dummy test/test_dummy.cpp)
  target_link_libraries(test_dummy crypto_utils)
endif()

ament_package()
