cmake_minimum_required(VERSION 3.31)
Project(BDS-LoginHook)

set(SRC
    "src/BDSLoginHook.cpp"
)

add_subdirectory(third_party/minhook)

add_library(BDS-LoginHook SHARED ${SRC})

target_link_libraries(BDS-LoginHook PRIVATE minhook)