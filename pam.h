/* -*- C -*-
 * $Id: pam.h,v 1.1 2002/11/06 08:04:48 ttate Exp $
 */

#ifndef RB_PAM_H
#define RB_PAM_H 1

#include <ruby.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define RUBY_PAM_MAJOR_VERSION 1
#define RUBY_PAM_MINOR_VERSION 5
#define RUBY_PAM_VERSION "1.5"

typedef struct rb_pam_struct {
  pam_handle_t *ptr;
  int start;
  int status;
  struct pam_conv *conv;
} *RPAM;

extern VALUE rb_mPAM;          /* PAM module */
extern VALUE rb_cPAMHandle;   /* PAM Handle Class */
extern VALUE rb_ePAMError;
extern VALUE rb_pam_errors[];

#define RBPAM_MAX_ERRORS 40

extern VALUE rb_sPAMMessage;
extern VALUE rb_sPAMResponse;

extern void rb_pam_raise(int, const char *, ...);
extern VALUE rb_pam_start(int, VALUE[], VALUE);

extern VALUE rb_pam_handle_new(pam_handle_t *);
extern VALUE rb_pam_handle_s_start(int, VALUE[], VALUE);
extern VALUE rb_pam_handle_end(VALUE);
extern VALUE rb_pam_handle_authenticate(int, VALUE[], VALUE);
extern VALUE rb_pam_handle_acct_mgmt(int, VALUE[], VALUE);
extern VALUE rb_pam_handle_setcred(int, VALUE[], VALUE);
extern VALUE rb_pam_handle_chauthtok(int, VALUE[], VALUE);
extern VALUE rb_pam_handle_open_session(int, VALUE[], VALUE);
extern VALUE rb_pam_handle_close_session(int, VALUE[], VALUE);

#endif /* RB_PAM_H */
