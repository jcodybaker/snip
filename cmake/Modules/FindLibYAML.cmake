find_path( LibYAML_INCLUDE_DIR NAMES yaml.h)
find_library( LibYAML_LIBRARIES NAMES yaml)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibYAML DEFAULT_MSG
        LibYAML_LIBRARIES
        LibYAML_INCLUDE_DIR
        )
