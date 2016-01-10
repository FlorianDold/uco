AC_PREREQ([2.69]) 
AC_INIT([uco], [1.0], [dold@in.tum.de  ])
AM_INIT_AUTOMAKE([-Wall])

# pretty build rules
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_CONFIG_HEADERS([config.h])


# check for libjansson (Jansson JSON library)
jansson=0
AC_MSG_CHECKING([for jansson])
AC_ARG_WITH([jansson],
            [AS_HELP_STRING([--with-jansson=PFX], [base of jansson installation])],
            [AC_MSG_RESULT([given as $with_jansson])],
            [AC_MSG_RESULT([not given])
             with_jansson=yes])
AS_CASE([$with_jansson],
        [yes], [],
        [no], [AC_MSG_ERROR([--with-jansson is required])],
        [LDFLAGS="-L$with_jansson/lib $LDFLAGS"
         CPPFLAGS="-I$with_jansson/include $CPPFLAGS"])
AC_CHECK_LIB(jansson,json_pack,
  [AC_CHECK_HEADER([jansson.h],[jansson=1])])
AS_IF([test $jansson = 0],
  [AC_MSG_ERROR([[
***
*** You need libjansson to build this program.
*** ]])])




AC_CONFIG_FILES([
                 Makefile
                 src/Makefile
                 ])
AC_OUTPUT
