/* -*- C -*-
 * $Id: pam.c,v 1.1 2002/11/06 08:04:48 ttate Exp $
 */

#include "pam.h"

#ifdef HAVE_STDARG_PROTOTYPES
#include <stdarg.h>
#define va_init_list(a,b) va_start(a,b)
#else
#include <varargs.h>
#define va_init_list(a,b) va_start(a)
#endif

VALUE rb_mPAM;            /* PAM module */
VALUE rb_cPAMHandle;      /* PAM Handle Class */
VALUE rb_ePAMError;       /* PAM Runtime Error */
VALUE rb_pam_errors[RBPAM_MAX_ERRORS];  /* PAM Errors */

VALUE rb_sPAMMessage;
VALUE rb_sPAMResponse;

static VALUE
rb_pam_define_err(int err, const char *name)
{
  if( 0 < err && err < RBPAM_MAX_ERRORS ){
    rb_pam_errors[err] = rb_define_class_under(rb_mPAM, name, rb_ePAMError);
  }
  else{
    rb_define_class_under(rb_mPAM, name, rb_ePAMError);
  };
};

static void
rb_pam_init_errors()
{
  int i;

  for( i=0; i < RBPAM_MAX_ERRORS; i++ ){
    rb_pam_errors[i] = Qnil;
  };
  rb_pam_define_err(PAM_SUCCESS, "PAM_SUCCESS");
  rb_pam_define_err(PAM_OPEN_ERR, "PAM_OPEN_ERR");
  rb_pam_define_err(PAM_SYMBOL_ERR, "PAM_SYMBOL_ERR");
  rb_pam_define_err(PAM_SERVICE_ERR, "PAM_SERVICE_ERR");
  rb_pam_define_err(PAM_SYSTEM_ERR, "PAM_SYSTEM_ERR");
  rb_pam_define_err(PAM_BUF_ERR, "PAM_BUF_ERR");
  rb_pam_define_err(PAM_PERM_DENIED, "PAM_PERM_DENIED");
  rb_pam_define_err(PAM_AUTH_ERR, "PAM_AUTH_ERR");
  rb_pam_define_err(PAM_CRED_INSUFFICIENT, "PAM_CRED_INSUFFICIENT");
  rb_pam_define_err(PAM_AUTHINFO_UNAVAIL, "PAM_AUTHINFO_UNAVAIL");
  rb_pam_define_err(PAM_USER_UNKNOWN, "PAM_USER_UNKNOWN");
  rb_pam_define_err(PAM_MAXTRIES, "PAM_MAXTRIES");
  rb_pam_define_err(PAM_NEW_AUTHTOK_REQD, "PAM_NEW_AUTHOK_REQD");
  rb_pam_define_err(PAM_ACCT_EXPIRED, "PAM_ACCT_EXPIRED");
  rb_pam_define_err(PAM_SESSION_ERR, "PAM_SESSION_ERR");
  rb_pam_define_err(PAM_CRED_UNAVAIL, "PAM_CRED_UNAVAIL");
  rb_pam_define_err(PAM_CRED_EXPIRED, "PAM_CRED_EXPIRED");
  rb_pam_define_err(PAM_CRED_ERR, "PAM_CRED_ERR");
  rb_pam_define_err(PAM_NO_MODULE_DATA, "PAM_NO_MODULE_DATA");
  rb_pam_define_err(PAM_CONV_ERR, "PAM_CONV_ERR");
  rb_pam_define_err(PAM_AUTHTOK_ERR, "PAM_AUTHTOK_ERR");
#if defined(PAM_AUTHTOK_RECOVER_ERR)
  rb_pam_define_err(PAM_AUTHTOK_RECOVER_ERR, "PAM_AUTHTOK_RECOVERY_ERR");
#elif defined(PAM_AUTHTOK_RECOVERY_ERR)
  rb_pam_define_err(PAM_AUTHTOK_RECOVERY_ERR, "PAM_AUTHTOK_RECOVERY_ERR");
#endif
  rb_pam_define_err(PAM_AUTHTOK_LOCK_BUSY, "PAM_AUTHTOK_LOCK_BUSY");
  rb_pam_define_err(PAM_AUTHTOK_DISABLE_AGING, "PAM_AUTHTOK_DISABLE_AGING");
  rb_pam_define_err(PAM_TRY_AGAIN, "PAM_TRY_AGAIN");
  rb_pam_define_err(PAM_IGNORE, "PAM_IGNORE");
  rb_pam_define_err(PAM_ABORT, "PAM_ABORT");
  rb_pam_define_err(PAM_AUTHTOK_EXPIRED, "PAM_AUTHTOK_EXPIRED");
#if defined(PAM_MODULE_UNKNOWN)
  rb_pam_define_err(PAM_MODULE_UNKNOWN, "PAM_MODULE_UNKNOWN");
#endif
#if defined(PAM_BAD_ITEM)
  rb_pam_define_err(PAM_BAD_ITEM, "PAM_BAD_ITEM");
#endif
#if defined(PAM_CONV_AGAIN)
  rb_pam_define_err(PAM_CONV_AGAIN, "PAM_CONV_AGAIN");
#endif
#if defined(PAM_INCOMPLETE)
  rb_pam_define_err(PAM_INCOMPLETE, "PAM_INCOMPLETE");
#endif
};

void
#ifdef HAVE_STDARG_PROTOTYPES
rb_pam_raise(int err, const char *fmt, ...)
#else
rb_pam_raise(err, fmt, va_alist)
     int err;
     const char *fmt;
     va_dcl
#endif
{
  va_list args;
  char buf[BUFSIZ];

  if( 0 < err && err < RBPAM_MAX_ERRORS && rb_pam_errors[err] ){
    va_init_list(args,fmt);
    vsnprintf(buf, BUFSIZ, fmt, args);
    va_end(args);
    rb_exc_raise(rb_exc_new2(rb_pam_errors[err],buf));
  }
  else{
    rb_raise(rb_ePAMError, "undefined pam exception (error code = %d)",err);
  };
};

VALUE
rb_pam_start(int argc, VALUE argv[], VALUE self)
{
  return rb_pam_handle_s_start(argc, argv, rb_cPAMHandle);
};


void
Init_pam()
{
  extern Init_pam_handle();

  rb_mPAM = rb_define_module("PAM");
  rb_ePAMError = rb_define_class("PAMError",rb_eRuntimeError);

  rb_sPAMMessage = rb_struct_define("Message","msg_style","msg",0);
  rb_sPAMResponse = rb_struct_define("Response","resp","resp_retcode",0);

  rb_define_const(rb_mPAM,"Message",rb_sPAMMessage);
  rb_define_const(rb_mPAM,"Response",rb_sPAMResponse);

  rb_define_const(rb_mPAM,"PAM_VERSION", rb_tainted_str_new2(RUBY_PAM_VERSION));
  rb_define_const(rb_mPAM,"PAM_MAJOR_VERSION", INT2FIX(RUBY_PAM_MAJOR_VERSION));
  rb_define_const(rb_mPAM,"PAM_MINOR_VERSION", INT2FIX(RUBY_PAM_MINOR_VERSION));

  rb_define_module_function(rb_mPAM, "start", rb_pam_start, -1);

  rb_pam_init_errors();

#define rb_pam_define_const(c) rb_define_const(rb_mPAM,#c,INT2NUM(c))
  rb_pam_define_const(PAM_CONV);
  rb_pam_define_const(PAM_CHANGE_EXPIRED_AUTHTOK);
  rb_pam_define_const(PAM_DELETE_CRED);
  rb_pam_define_const(PAM_ERROR_MSG);
  rb_pam_define_const(PAM_ESTABLISH_CRED);
  rb_pam_define_const(PAM_OLDAUTHTOK);
  rb_pam_define_const(PAM_PROMPT_ECHO_OFF);
  rb_pam_define_const(PAM_PROMPT_ECHO_ON);
  rb_pam_define_const(PAM_REFRESH_CRED);
  rb_pam_define_const(PAM_REINITIALIZE_CRED);
  rb_pam_define_const(PAM_RHOST);
  rb_pam_define_const(PAM_RUSER);
  rb_pam_define_const(PAM_SERVICE);
  rb_pam_define_const(PAM_SILENT);
  rb_pam_define_const(PAM_TEXT_INFO);
  rb_pam_define_const(PAM_TTY);
  rb_pam_define_const(PAM_USER);
  rb_pam_define_const(PAM_USER_PROMPT);
  rb_pam_define_const(PAM_DISALLOW_NULL_AUTHTOK);
#undef rb_pam_define_const

  Init_pam_handle();
};
