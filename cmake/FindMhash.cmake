# FindMhash.cmake
find_path(MHASH_INCLUDE_DIR mhash.h)
find_library(MHASH_LIBRARY NAMES mhash)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Mhash DEFAULT_MSG MHASH_LIBRARY MHASH_INCLUDE_DIR)

if(MHASH_FOUND)
    set(MHASH_LIBRARIES ${MHASH_LIBRARY})
    set(MHASH_INCLUDE_DIRS ${MHASH_INCLUDE_DIR})
else()
    set(MHASH_LIBRARIES)
    set(MHASH_INCLUDE_DIRS)
endif()

mark_as_advanced(MHASH_INCLUDE_DIR MHASH_LIBRARY)
