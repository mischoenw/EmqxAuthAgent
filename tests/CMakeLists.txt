find_package(GTest REQUIRED)

add_executable(run_tests
    test_cert_parser.cpp
    test_topic_matcher.cpp
    test_rules_engine.cpp
    # Include the modules under test directly (no separate library target needed)
    ${CMAKE_SOURCE_DIR}/src/cert_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/topic_matcher.cpp
    ${CMAKE_SOURCE_DIR}/src/rules_engine.cpp
)

target_include_directories(run_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(run_tests PRIVATE
    GTest::gtest_main
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
)

add_test(NAME AllTests COMMAND run_tests)
