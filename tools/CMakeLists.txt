add_executable(OpenSSH-bcrypt_pbkdf-benchmark OpenSSH-bcrypt_pbkdf-benchmark.cpp)

target_link_libraries(OpenSSH-bcrypt_pbkdf-benchmark PRIVATE bcrypt_pbkdf)
