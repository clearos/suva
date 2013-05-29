#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([suva], [3.1],
	[http://www.clearfoundation.com/docs/developer/bug_tracker/],
	[suva], [http://www.clearfoundation.com])
AM_INIT_AUTOMAKE([suva], [3.1])
AC_CONFIG_SRCDIR([svconf.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([suva.spec])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Check for windres (Windows).
if test -z "$host_alias"; then
	hostaliaswindres=
else
	hostaliaswindres="$host_alias-windres"
fi
AC_CHECK_PROGS(WINDRES, [windres $hostaliaswindres $host_os-windres])
AC_SUBST([WINDRES])

case "$host" in
	x86-*-linux* | ia64-*-linux* | i586-*-linux* | i686-*-linux* | x86_64-*-linux* | alpha-*-linux*)
		AC_DEFINE(_REENTRANT, 1, [Use reentrant code])
		;;
	*-*-linux*)
		AC_DEFINE(_REENTRANT, 1, [Use reentrant code])
		;;
	*-*-cygwin* | *-*-mingw*)
		if test x$WINDRES != x; then
			use_resources_rc=true
		fi
		;;
esac
AM_CONDITIONAL(USE_RESOURCES_RC, test x$use_resources_rc = xtrue)

# Checks for required libraries.
AC_CHECK_LIB([crypto], [RSA_public_encrypt], [], [
	AC_MSG_ERROR([RSA_public_encrypt not found but is required.])])
AC_CHECK_LIB([expat], [XML_ParserCreate], [], [
	AC_MSG_ERROR([XML_ParserCreate not found but is required.])])
AC_CHECK_LIB([pthread], [pthread_create], [], [
	AC_MSG_ERROR([pthread_create not found but is required.])])

# Checks for optional libraries.
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([popt], [poptParseArgvString])

# Need any extra libraries?
case "$host" in
	*-*-cygwin* | *-*-mingw*)
		EXTRA_LIBS="-lws2_32"
		;;
	*)
		EXTRA_LIBS=""
		;;
esac
AC_SUBST([EXTRA_LIBS])

# Checks for server libraries.
COMMON_LIBS=$LIBS
LIBS=
AC_CHECK_LIB([db], [db_env_create])
AC_CHECK_LIB([pq], [PQconnectdb])
AC_CHECK_LIB([mysqlclient], [mysql_real_connect])
SERVER_LIBS=$LIBS
LIBS=$COMMON_LIBS
AC_SUBST([SERVER_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h execinfo.h fcntl.h netdb.h netinet/in.h netinet/tcp_var.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h sys/signal.h sys/wait.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_BIGENDIAN
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_REALLOC
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([backtrace clock_gettime dup2 getpagesize gettimeofday inet_ntoa memmove memset pathconf select socket socketpair strcasecmp strdup strerror strndup strnlen strtol sysconf usleep PQescapeStringConn])

# Output files
AC_CONFIG_FILES([Makefile
	plugin/Makefile
	plugin/isfd/Makefile
	plugin/scl/Makefile
	resources.h])
AC_OUTPUT
