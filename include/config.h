/* include/config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#undef HAVE_ARPA_INET_H

/* Define to 1 if you have the `bzero' function. */
#undef HAVE_BZERO

/* Define to 1 if you have the <fcntl.h> header file. */
#undef HAVE_FCNTL_H

/* Define to 1 if you have the `fork' function. */
#undef HAVE_FORK

/* Define to 1 if you have the `gethostbyname' function. */
#undef HAVE_GETHOSTBYNAME

/* Define to 1 if you have the `gettimeofday' function. */
#undef HAVE_GETTIMEOFDAY

/* Define to 1 if you have the `inet_ntoa' function. */
#undef HAVE_INET_NTOA

/* Define to 1 if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* Define to 1 if you have the `dl' library (-ldl). */
#undef HAVE_LIBDL

/* Define to 1 if you have the `ldap' library (-lldap). */
#undef HAVE_LIBLDAP

/* Define to 1 if you have the `pam' library (-lpam). */
#undef HAVE_LIBPAM

/* Define to 1 if you have the `pam_misc' library (-lpam_misc). */
#undef HAVE_LIBPAM_MISC

/* Define to 1 if you have the `pthread' library (-lpthread). */
#undef HAVE_LIBPTHREAD

/* Define to 1 if you have the <memory.h> header file. */
#undef HAVE_MEMORY_H

/* Define to 1 if you have the `memset' function. */
#undef HAVE_MEMSET

/* Define to 1 if you have the <netdb.h> header file. */
#undef HAVE_NETDB_H

/* Define to 1 if you have the <netinet/in.h> header file. */
#undef HAVE_NETINET_IN_H

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#undef HAVE_REALLOC

/* Define to 1 if you have the `select' function. */
#undef HAVE_SELECT

/* Define to 1 if you have the `socket' function. */
#undef HAVE_SOCKET

/* Define to 1 if you have the <stdint.h> header file. */
#undef HAVE_STDINT_H

/* Define to 1 if you have the <stdlib.h> header file. */
#undef HAVE_STDLIB_H

/* Define to 1 if you have the `strdup' function. */
#undef HAVE_STRDUP

/* Define to 1 if you have the `strftime' function. */
#undef HAVE_STRFTIME

/* Define to 1 if you have the <strings.h> header file. */
#undef HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#undef HAVE_STRING_H

/* Define to 1 if you have the `strtol' function. */
#undef HAVE_STRTOL

/* Define to 1 if you have the <syslog.h> header file. */
#undef HAVE_SYSLOG_H

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#undef HAVE_SYS_IOCTL_H

/* Define to 1 if you have the <sys/select.h> header file. */
#undef HAVE_SYS_SELECT_H

/* Define to 1 if you have the <sys/socket.h> header file. */
#undef HAVE_SYS_SOCKET_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#undef HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/time.h> header file. */
#undef HAVE_SYS_TIME_H

/* Define to 1 if you have the <sys/types.h> header file. */
#undef HAVE_SYS_TYPES_H

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#undef HAVE_SYS_WAIT_H

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* Define to 1 if you have the `vfork' function. */
#undef HAVE_VFORK

/* Define to 1 if you have the <vfork.h> header file. */
#undef HAVE_VFORK_H

/* Define to 1 if `fork' works. */
#undef HAVE_WORKING_FORK

/* Define to 1 if `vfork' works. */
#undef HAVE_WORKING_VFORK

/* Define to the address where bug reports for this package should be sent. */
#undef PACKAGE_BUGREPORT

/* Define to the full name of this package. */
#undef PACKAGE_NAME

/* Define to the full name and version of this package. */
#undef PACKAGE_STRING

/* Define to the one symbol short name of this package. */
#undef PACKAGE_TARNAME

/* Define to the version of this package. */
#undef PACKAGE_VERSION

/* Define to the type of arg 1 for `select'. */
#undef SELECT_TYPE_ARG1

/* Define to the type of args 2, 3 and 4 for `select'. */
#undef SELECT_TYPE_ARG234

/* Define to the type of arg 5 for `select'. */
#undef SELECT_TYPE_ARG5

/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#undef TIME_WITH_SYS_TIME

/* Define to empty if `const' does not conform to ANSI C. */
#undef const

/* Define default value of pathname for configuration file */
#ifdef FREEBSD
#define SS5_CONFIG_FILE    "/usr/local/etc/opt/ss5/ss5.conf"
#else
#define SS5_CONFIG_FILE    "/etc/opt/ss5/ss5.conf"
#endif

/* Define default value of pathname for HA file */
#ifdef FREEBSD
#define SS5_PEERS_FILE     "/usr/local/etc/opt/ss5/ss5.ha"
#else
#define SS5_PEERS_FILE     "/etc/opt/ss5/ss5.ha"
#endif

/* Define default value of pathname for password file */
#ifdef FREEBSD
#define SS5_PASSWORD_FILE  "/usr/local/etc/opt/ss5/ss5.passwd"
#else
#define SS5_PASSWORD_FILE  "/etc/opt/ss5/ss5.passwd"
#endif

/* Define default value of pathname for log file */
#define SS5_LOG_FILE  "/var/log/ss5/ss5.log"

/* Define default value of pathname for pid file */
#define SS5_PID_FILE  "/var/run/ss5/ss5.pid"

/* Define default value of path for profile files */
#ifdef FREEBSD
#define SS5_PROFILE_PATH   "/usr/local/etc/opt/ss5"
#else
#define SS5_PROFILE_PATH   "/etc/opt/ss5"
#endif

/* Define default value of path for trace files */
#define SS5_TRACE_PATH   "/var/log/ss5"

/* Define default value of path modules */
#ifdef FREEBSD
#define SS5_LIB_PATH       "/usr/local/lib"
#else
#define SS5_LIB_PATH       "/usr/lib"
#endif

/* Define default value of bind addr */
#define SS5_DEFAULT_ADDR   "0.0.0.0"

/* Define default value of bind port */
#define SS5_DEFAULT_PORT   "1080"

/* Define default value of user process */
#define SS5_DEFAULT_USER   "nobody"

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#undef inline
#endif

/* Define to `int' if <sys/types.h> does not define. */
#undef pid_t

/* Define to rpl_realloc if the replacement function should be used. */
#undef realloc

/* Define as `fork' if `vfork' does not work. */
#undef vfork
