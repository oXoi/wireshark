# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# We should use CPack to generate the NSIS package. Even better,
# we should use CPack to create a .msi using WiX.

set(WIRESHARK_NSIS_GENERATED_FILES
	${CMAKE_CURRENT_BINARY_DIR}/wireshark-manifest.nsh
	${CMAKE_CURRENT_BINARY_DIR}/wireshark-config.nsh
)
if(NOT SKIP_NSIS_QT_DLLS)
	list(APPEND WIRESHARK_NSIS_GENERATED_FILES ${CMAKE_CURRENT_BINARY_DIR}/wireshark-qt-manifest.nsh)
endif()
set(WIRESHARK_NSIS_GENERATED_FILES ${WIRESHARK_NSIS_GENERATED_FILES} PARENT_SCOPE)

set(WIRESHARK_NSIS_FILES
	${CMAKE_CURRENT_SOURCE_DIR}/wireshark.nsi
	${CMAKE_CURRENT_SOURCE_DIR}/wireshark-common.nsh
	${CMAKE_CURRENT_SOURCE_DIR}/servicelib.nsh
	${CMAKE_CURRENT_SOURCE_DIR}/NpcapPage.ini
	${CMAKE_CURRENT_SOURCE_DIR}/USBPcapPage.ini
	${WIRESHARK_NSIS_GENERATED_FILES}
	PARENT_SCOPE
)

set(STRATOSHARK_NSIS_GENERATED_FILES
	${CMAKE_CURRENT_BINARY_DIR}/stratoshark-manifest.nsh
	${CMAKE_CURRENT_BINARY_DIR}/stratoshark-config.nsh
	${CMAKE_CURRENT_BINARY_DIR}/stratoshark-qt-manifest.nsh
)
set(STRATOSHARK_NSIS_GENERATED_FILES ${STRATOSHARK_NSIS_GENERATED_FILES} PARENT_SCOPE)

set(STRATOSHARK_NSIS_FILES
	stratoshark.nsi
	stratoshark-common.nsh
	servicelib.nsh
	NpcapPage.ini
	USBPcapPage.ini
	${STRATOSHARK_NSIS_GENERATED_FILES}
	PARENT_SCOPE
)

# Variables required for config.nsh
set(PROGRAM_NAME ${CMAKE_PROJECT_NAME})
file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}" TOP_SRC_DIR)
# STAGING_DIR depends on the build configuration so we pass it
# on the command line below.
file(TO_NATIVE_PATH "${CMAKE_BINARY_DIR}/doc" DOC_DIR)
set (MMDBRESOLVE_EXE ${MAXMINDDB_FOUND})

# To do:
# - Sync the various version names between CMake and NSIS.
# - Set CMakeLists.txt version strings in tools/make-version.py
# - Add a VERSION_EXTRA cmake option
set (PRODUCT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}.${PROJECT_BUILD_VERSION})
set (STRATOSHARK_PRODUCT_VERSION ${STRATOSHARK_MAJOR_VERSION}.${STRATOSHARK_MINOR_VERSION}.${STRATOSHARK_PATCH_VERSION}.${STRATOSHARK_BUILD_VERSION})

if((BUILD_wireshark OR BUILD_stratoshark) AND QT_FOUND)
	set (QT_DIR "\${STAGING_DIR}")
endif()

# Look for the Visual C++ Redistributable packages in the following locations:
# - _PROJECT_LIB_DIR
# - _PROJECT_LIB_DIR/vcredist_MSVCxx
# - %VCINSTALLDIR%
# - %VCINSTALLDIR%/redist/1033 (<= Visual Studio 2015)
# - %VCINSTALLDIR%/Redist/MSVC/* (>= Visual Studio 2017)
# MSVC_VERSION (_MSC_VER) = Visual Studio Version / MSVC Toolset Version
# 1900 = VS2015 14.0        / 14.00
# 1910 = VS2017 15.1, 15.2  / 14.10
# 1911 = VS2017 15.3, 15.4  / 14.11
# 1912 = VS2017 15.5        / 14.12
# 1913 = VS2017 15.6        / 14.13
# 1914 = VS2017 15.7        / 14.14
if(MSVC_VERSION GREATER_EQUAL 1930)
	set(_ws_vcredist_subdir "vcredist_MSVC2022")
elseif(MSVC_VERSION GREATER_EQUAL 1920)
	set(_ws_vcredist_subdir "vcredist_MSVC2019")
	set(_msvs_version 15.0) # Doesn't appear to be set
elseif(MSVC_VERSION GREATER_EQUAL 1910)
	set(_ws_vcredist_subdir "vcredist_MSVC2017")
	set(_msvs_version 15.0)
elseif(MSVC_VERSION GREATER_EQUAL 1900)
	set(_ws_vcredist_subdir "vcredist_MSVC2015")
	set(_ms_vcredist_subdir "redist/1033")
	set(_msvs_version 14.0)
endif()

# Try to find the Redist folder in VCINSTALLDIR which is set by vcvarsall.bat.
# If it is not set, query it within the registry. VS2015 looks for the "VC7" key
# in two locations (four if you count HKCU instead of HKLM). However, VS2017
# does not use "VC7" (it sets a directory relative to vsdevcmd_start.bat). As
# both versions do set "VS7", use that instead.
find_path(VCINSTALLDIR Redist PATHS
	"$ENV{VCINSTALLDIR}"
	"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7;${_msvs_version}]\\VC"
	"[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\VisualStudio\\SxS\\VS7;${_msvs_version}]\\VC"
	NO_DEFAULT_PATH
)
file(TO_NATIVE_PATH "${VCINSTALLDIR}" VCINSTALLDIR_NATIVE)
message(STATUS "Using VCINSTALLDIR: ${VCINSTALLDIR_NATIVE}")

# Visual Studio Community 2017 version 15.7.5 uses VCRT 14.14.26405, but an
# earlier version used 14.10.25008. Let's just glob for the right value.
if(MSVC_VERSION GREATER_EQUAL 1910 AND VCINSTALLDIR)
	file(GLOB _ms_vcredist_subdir RELATIVE "${VCINSTALLDIR}"
		"${VCINSTALLDIR}/Redist/MSVC/14.*.*")
endif()

find_program(_vcredist
	NAMES
		"vc_redist.${WIRESHARK_TARGET_PLATFORM}.exe" # Visual Studio 2022 and later
		"vcredist_${WIRESHARK_TARGET_PLATFORM}.exe" # Visual Studio 2019 and earlier
	PATHS "${_PROJECT_LIB_DIR}" $ENV{VCToolsRedistDir} "${VCINSTALLDIR}"
	PATH_SUFFIXES ${_ws_vcredist_subdir} ${_ms_vcredist_subdir}
	NO_DEFAULT_PATH
)
if(_vcredist)
	file(TO_NATIVE_PATH "${_vcredist}" _vcredist)
	message(STATUS "Using ${_vcredist} for the NSIS installer.")
	get_filename_component(VCREDIST_DIR ${_vcredist} DIRECTORY)
	get_filename_component(VCREDIST_EXE ${_vcredist} NAME)
endif()

if (BUILD_wireshark)
	# Ideally we would generate this at compile time using a separate cmake
	# module, e.g. cmake/modules/configure_nsis_file.cmake. However we would
	# have to figure out a clean way to pass in the variables above.
	file(READ "${CMAKE_CURRENT_SOURCE_DIR}/wireshark-config.nsh.in" _config_nsh_contents)
	string(CONFIGURE "${_config_nsh_contents}" _config_nsh_contents)
	string(REPLACE "#define" "!define" _config_nsh_contents "${_config_nsh_contents}")
	string(REPLACE "#undef" "!undef" _config_nsh_contents "${_config_nsh_contents}")
	file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wireshark-config.nsh" "${_config_nsh_contents}")

	# wireshark-manifest.nsh. Can be created at configure time.
	set(_all_manifest "${CMAKE_CURRENT_BINARY_DIR}/wireshark-manifest.nsh")
	set(_all_manifest_contents "# Files required for all sections. Generated by CMake.\n")
	if(USE_REPOSITORY)
		set(_all_manifest_contents "${_all_manifest_contents}!ifdef BUNDLE_DEBUG_DLLS\n")
		foreach(_dll ${GLIB2_DLLS_DEBUG})
			set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
		endforeach()
		set(_all_manifest_contents "${_all_manifest_contents}!else\n")
		foreach(_dll ${GLIB2_DLLS_RELEASE})
			set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
		endforeach()
		set(_all_manifest_contents "${_all_manifest_contents}!endif\n")
		foreach(_dll ${AMRNB_DLL} ${CARES_DLL} ${PCRE2_RELEASE_DLL} ${GCRYPT_DLLS}
				${GNUTLS_DLLS} ${KERBEROS_DLLS} ${LIBSSH_DLLS} ${LUA_DLL}
				${LZ4_DLL} ${MINIZIP_DLL} ${MINIZIPNG_DLLS} ${NGHTTP2_DLL} ${NGHTTP3_DLL} ${SBC_DLL} ${SMI_DLL}
				${SNAPPY_DLL} ${SPANDSP_DLL} ${BCG729_DLL} ${LIBXML2_DLLS} ${WINSPARKLE_DLL}
				${XXHASH_DLL} ${ZLIB_DLL} ${ZLIBNG_DLL} ${BROTLI_DLLS} ${ZSTD_DLL} ${ILBC_DLL} ${OPUS_DLL}
				${SPEEXDSP_DLL}
				# Needed for mmdbresolve
				${MAXMINDDB_DLL}
			)
			set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
		endforeach()
	elseif(USE_MSYSTEM)
		include(${CMAKE_CURRENT_SOURCE_DIR}/InstallMSYS2.cmake)
		foreach(_dll ${MINGW_DLLS})
			file(TO_NATIVE_PATH ${_dll} _path)
			set(_all_manifest_contents "${_all_manifest_contents}File \"${_path}\"\n")
		endforeach()
	else()
		include(${CMAKE_CURRENT_SOURCE_DIR}/InstallMinGW.cmake)
		foreach(_dll ${MINGW_DLLS})
			file(TO_NATIVE_PATH ${_dll} _path)
			set(_all_manifest_contents "${_all_manifest_contents}File \"${_path}\"\n")
		endforeach()
	endif()
	file(WRITE "${_all_manifest}" "${_all_manifest_contents}")
endif()

if (BUILD_stratoshark)
	# Ideally we would generate this at compile time using a separate cmake
	# module, e.g. cmake/modules/configure_nsis_file.cmake. However we would
	# have to figure out a clean way to pass in the variables above.
	file(READ "${CMAKE_CURRENT_SOURCE_DIR}/stratoshark-config.nsh.in" _config_nsh_contents)
	string(CONFIGURE "${_config_nsh_contents}" _config_nsh_contents)
	string(REPLACE "#define" "!define" _config_nsh_contents "${_config_nsh_contents}")
	string(REPLACE "#undef" "!undef" _config_nsh_contents "${_config_nsh_contents}")
	file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/stratoshark-config.nsh" "${_config_nsh_contents}")

	# stratoshark-manifest.nsh. Can be created at configure time.
	set(_all_manifest "${CMAKE_CURRENT_BINARY_DIR}/stratoshark-manifest.nsh")
	set(_all_manifest_contents "# Files required for all sections. Generated by CMake.\n")
	set(_all_manifest_contents "${_all_manifest_contents}!ifdef BUNDLE_DEBUG_DLLS\n")
	foreach(_dll ${GLIB2_DLLS_DEBUG})
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	set(_all_manifest_contents "${_all_manifest_contents}!else\n")
	foreach(_dll ${GLIB2_DLLS_RELEASE})
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	set(_all_manifest_contents "${_all_manifest_contents}!endif\n")
	foreach(_dll ${AMRNB_DLL} ${CARES_DLL} ${PCRE2_RELEASE_DLL} ${GCRYPT_DLLS}
			${GNUTLS_DLLS} ${KERBEROS_DLLS} ${LIBSSH_DLLS} ${LUA_DLL}
			${LZ4_DLL} ${MINIZIP_DLL} ${MINIZIPNG_DLLS} ${NGHTTP2_DLL} ${NGHTTP3_DLL} ${SBC_DLL} ${SMI_DLL}
			${SNAPPY_DLL} ${SPANDSP_DLL} ${BCG729_DLL} ${LIBXML2_DLLS} ${WINSPARKLE_DLL}
			${XXHASH_DLL} ${ZLIB_DLL} ${ZLIBNG_DLL} ${BROTLI_DLLS} ${ZSTD_DLL} ${ILBC_DLL} ${OPUS_DLL}
			${SPEEXDSP_DLL}
			# Needed for mmdbresolve
			${MAXMINDDB_DLL}
		)
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	file(WRITE "${_all_manifest}" "${_all_manifest_contents}")
endif()

file(TO_NATIVE_PATH "${DATAFILE_DIR}" _staging_dir)
file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}" _outfile_dir)
file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}" _nsis_include_dir)

# Variables we can't set via config.nsh.
set(NSIS_OPTIONS
	-DSTAGING_DIR=${_staging_dir}
	-DOUTFILE_DIR=${_outfile_dir}
	-DNSIS_INCLUDE_DIR=${_nsis_include_dir}
	-V2
	PARENT_SCOPE
)

macro( ADD_NSIS_PACKAGE_TARGETS )
	set (_nsis_source_dir ${CMAKE_SOURCE_DIR}/packaging/nsis )
	set (_nsis_binary_dir ${CMAKE_BINARY_DIR}/packaging/nsis )
	#
	# XXX - if we're not building Wireshark, we can't build the
	# manifest below.  On the other hand, if we're not building
	# Wireshark, we have no need to include Qt in the installer,
	# so it's not clear we need this manifest.
	#
	# This should probably be fixed, so that people can produce
	# command-line-only installer packages.
	if(BUILD_wireshark)
		# wireshark-qt-manifest.nsh. Created using Wireshark.exe.
		if(NOT SKIP_NSIS_QT_DLLS)
			if (USE_REPOSITORY)
				add_custom_command(OUTPUT ${_nsis_binary_dir}/wireshark-qt-manifest.nsh
					COMMAND set "PATH=${QT_BIN_PATH};%PATH%"
					COMMAND ${POWERSHELL_COMMAND} "${_nsis_source_dir}/windeployqt-to-nsis.ps1"
						-Executable $<TARGET_FILE:wireshark>
						-FilePath ${_nsis_binary_dir}/wireshark-qt-manifest.nsh
						$<$<CONFIG:Debug>:-DebugConfig>
					DEPENDS
						"${_nsis_source_dir}/windeployqt-to-nsis.ps1"
						$<TARGET_FILE:wireshark>
				)
			elseif(HAVE_MSYSTEM)
				add_custom_command(OUTPUT ${_nsis_binary_dir}/wireshark-qt-manifest.nsh
					COMMAND ${Python3_EXECUTABLE} "${_nsis_source_dir}/windeployqt-to-nsis.py"
						--executable $<TARGET_FILE:wireshark>
						${_nsis_binary_dir}/wireshark-qt-manifest.nsh
						#$<$<CONFIG:Debug>:-DebugConfig>
					DEPENDS
						"${_nsis_source_dir}/windeployqt-to-nsis.py"
						$<TARGET_FILE:wireshark>
				)
			elseif(MINGW AND CMAKE_CROSSCOMPILING)
				add_custom_command(OUTPUT ${_nsis_binary_dir}/wireshark-qt-manifest.nsh
					COMMAND ${Python3_EXECUTABLE} "${_nsis_source_dir}/windeployqt-to-nsis.py"
						--sysroot "${MINGW_SYSROOT}"
						--mapping "${_nsis_source_dir}/mingw64-qt-mapping.txt"
						${_nsis_binary_dir}/wireshark-qt-manifest.nsh
						#$<$<CONFIG:Debug>:-DebugConfig>
					DEPENDS
						"${_nsis_source_dir}/windeployqt-to-nsis.py"
						"${_nsis_source_dir}/mingw64-qt-mapping.txt"
				)
			else()
				message(FATAL_ERROR "Unknown Qt deployment method")
			endif()
		endif()

		# Build NSIS package dependencies. We build the package in
		# two stages so that wireshark_nsis below doesn't trigger
		# any dependencies that might clobber any signed executables.
		add_custom_target(wireshark_nsis_prep
			DEPENDS
				${WIRESHARK_NSIS_FILES}
				copy_data_files
				user_guide_html
				release_notes_html
		)
		set_target_properties(wireshark_nsis_prep PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)

		# Make sure required blobs are available
		FetchContent_MakeAvailable(Npcap USBPcap)

		# Dump the installer into
		# ${CMAKE_CURRENT_SOURCE_DIR}/packaging/nsis
		# Note that executables and DLLs *must* be built separately
		add_custom_target(wireshark_nsis
			COMMAND ${MAKENSIS_EXECUTABLE} ${NSIS_OPTIONS}
				$<$<CONFIG:Debug>:-DBUNDLE_DEBUG_DLLS>
				$<$<BOOL:${MSVC}>:-DUSE_VCREDIST>
				wireshark.nsi
			WORKING_DIRECTORY ${_nsis_source_dir}
		)
		set_target_properties(wireshark_nsis PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)
	endif()

	if(BUILD_stratoshark)
		# stratoshark-qt-manifest.nsh. Created using Wireshark.exe.
		add_custom_command(OUTPUT ${_nsis_binary_dir}/stratoshark-qt-manifest.nsh
			COMMAND set "PATH=${QT_BIN_PATH};%PATH%"
			COMMAND ${POWERSHELL_COMMAND} "${_nsis_source_dir}/windeployqt-to-nsis.ps1"
				-Executable $<TARGET_FILE:stratoshark>
				-FilePath ${_nsis_binary_dir}/stratoshark-qt-manifest.nsh
				$<$<CONFIG:Debug>:-DebugConfig>
			DEPENDS "${_nsis_source_dir}/windeployqt-to-nsis.ps1"
		)

		# Build NSIS package dependencies. We build the package in
		# two stages so that stratoshark_nsis below doesn't trigger
		# any dependencies that might clobber any signed executables.
		add_custom_target(stratoshark_nsis_prep
			DEPENDS
				${STRATOSHARK_NSIS_FILES}
				copy_data_files
				user_guide_html
				${DATAFILE_DIR}/uninstall-stratoshark.exe
		)
		set_target_properties(stratoshark_nsis_prep PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)

		# Dump the installer into
		# ${CMAKE_CURRENT_SOURCE_DIR}/packaging/nsis
		# Note that executables and DLLs *must* be built separately
		add_custom_target(stratoshark_nsis
			COMMAND ${MAKENSIS_EXECUTABLE} ${NSIS_OPTIONS}
				$<$<CONFIG:Debug>:-DBUNDLE_DEBUG_DLLS>
				stratoshark.nsi
			WORKING_DIRECTORY ${_nsis_source_dir}
		)
		set_target_properties(stratoshark_nsis PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)
	endif()
endmacro( ADD_NSIS_PACKAGE_TARGETS )

set(CLEAN_FILES
	${DATAFILE_DIR}/uninstall-wireshark.exe
	wireshark-${VERSION}-${WIRESHARK_TARGET_PLATFORM}.exe
	wireshark-config.nsh
	wireshark-manifest.nsh
	wireshark-qt-manifest.nsh
	${DATAFILE_DIR}/uninstall-stratoshark.exe
	stratoshark-${VERSION}-${WIRESHARK_TARGET_PLATFORM}.exe
	stratoshark-config.nsh
	stratoshark-manifest.nsh
	stratoshark-qt-manifest.nsh
)
