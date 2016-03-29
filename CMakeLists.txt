cmake_minimum_required(VERSION 2.8.11)

project(mndc)

# Find the QtWidgets library
find_package(Qt5Widgets REQUIRED)

# Find the QtNetwork library
find_package(Qt5Network REQUIRED)

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)

set(mndc_SOURCES
	main.cpp
	mainwindow.cpp
	mainwindow.h
	preferences.cpp
	preferences.h
	)

set(mndc_UI
	ui/mainwindow.ui
	ui/preferences.ui
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
