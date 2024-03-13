cmake_minimum_required(VERSION 3.5)

project(sshout-server)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Mhash REQUIRED)
find_package(Readline REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-switch -Wno-pointer-to-int-cast -fno-common")

set(BUILD_INFO ${CMAKE_CURRENT_BINARY_DIR}/build-info.h)

add_custom_command(OUTPUT ${BUILD_INFO}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build-info.sh ${BUILD_INFO}
    COMMENT "Generating build-info.h"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set(SSHOUTCFG_OBJCTS
    src/base64.c
    src/file-helpers.c
    src/misc.c
    src/sshoutcfg.c
    src/syncrw.c)

set(SSHOUTD_OBJECTS
    src/api-packet.c
    src/client.c
    src/client-api.c
    src/client-cli.c
    src/client-irc.c
    src/file-helpers.c
    src/local-packet.c
    src/main.c
    src/misc.c
    src/server.c
    src/syncrw.c)

add_executable(sshoutcfg ${BUILD_INFO} ${SSHOUTCFG_OBJCTS})
target_include_directories(sshoutcfg PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(sshoutcfg PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(sshoutcfg ${MHASH_LIBRARIES})

add_executable(sshoutd ${BUILD_INFO} ${SSHOUTD_OBJECTS})
target_include_directories(sshoutd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(sshoutd PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(sshoutd PRIVATE ${Readline_INCLUDE_DIRS})
target_link_libraries(sshoutd ${Readline_LIBRARY})

set(PREFIX "/usr")
set(LIBEXECDIR "${PREFIX}/lib/sshout")
set(SBINDIR "${PREFIX}/sbin")
set(DATADIR "${PREFIX}/share")
set(MANDIR "${DATADIR}/man")
set(LOCALEDIR "${DATADIR}/locale")

install(TARGETS sshoutcfg sshoutd
        RUNTIME DESTINATION ${SBINDIR})

install(FILES sshoutcfg.8
        DESTINATION ${MANDIR}/man8)

install(TARGETS sshoutd
        RUNTIME DESTINATION ${LIBEXECDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(TARGETS sshoutcfg
        RUNTIME DESTINATION ${SBINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(FILES deploy/systemd/sshout.service
        DESTINATION /etc/systemd/system
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(FILES sshoutcfg.8
        DESTINATION ${MANDIR}/man8
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
