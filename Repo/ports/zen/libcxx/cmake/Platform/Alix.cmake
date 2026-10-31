# Alix uses ELF64. These describe compiler output, not a dynamic loader claim.
# libc++ declares excluded shared targets even in a static-only build; allowing
# their distinct ELF .so output avoids Generic converting them to colliding .a's.
set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)
set(UNIX 1)
set(CMAKE_EXECUTABLE_SUFFIX ".elf")
set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
set(CMAKE_STATIC_LIBRARY_PREFIX "lib")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".a")
set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "-shared")
set(CMAKE_SHARED_LIBRARY_CREATE_CXX_FLAGS "-shared")
set(CMAKE_DL_LIBS "")
