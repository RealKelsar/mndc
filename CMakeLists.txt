cmake_minimum_required(VERSION 2.8.12)

project(mndc)

# Find the QtWidgets library
find_package(Qt5Widgets REQUIRED)

# Find the QtNetwork library
find_package(Qt5Network REQUIRED)

set(mndc_srcdir src/)

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)

set(mndc_SOURCES
	${mndc_srcdir}main.cpp
	${mndc_srcdir}mainwindow.cpp
	${mndc_srcdir}mainwindow.h
	${mndc_srcdir}preferences.cpp
	${mndc_srcdir}preferences.h
	)

set(mndc_UI
	${mndc_srcdir}ui/mainwindow.ui
	${mndc_srcdir}ui/preferences.ui
	)

qt5_wrap_ui(mndc_UI_SOURCES ${mndc_UI})

# Tell CMake to create the helloworld executable
add_executable(mndc ${mndc_SOURCES} ${mndc_UI_SOURCES})

# Use the Widgets module from Qt 5.
target_link_libraries(mndc Qt5::Widgets Qt5::Network)

install(TARGETS mndc
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)

INCLUDE(InstallRequiredSystemLibraries)

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "My Network Diagnostic Center")
SET(CPACK_PACKAGE_VENDOR "Tetja Rediske")
#SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ReadMe.txt")
#SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/Copyright.txt")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "5")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
SET(CPACK_PACKAGE_EXECUTABLES "mndc" "mndc")
INCLUDE(CPack)

# Generate some files for youcompleteme
SET(CMAKE_EXPORT_COMPILE_COMMANDS 1 )


