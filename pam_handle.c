/* -*- C -*-
 * $Id: pam_handle.c,v 1.2 2002/12/21 22:09:35 ttate Exp $
 */

#include "pam.h"

VALUE rb_cPAMHandle;

static int
rb_pam_inner_conv(int num_msg,
		  const struct pam_message **msg,
		  struct pam_response **resp,
		  void *appdata_ptr)
{
  VALUE func = rb_ary_entry((VALUE)appdata_ptr,0);
  VALUE data = rb_ary_entry((VALUE)appdata_ptr,1);
  VALUE rmsg = Qnil;
  VALUE rres = Qnil;
  struct pam_response *reply = NULL;
  int i;

  rmsg = rb_ary_new();
  for( i = 0; i < num_msg; i++ ){
    VALUE m_msg;
    VALUE m_style;

    m_msg = msg[i]->msg ? rb_tainted_str_new2(msg[i]->msg) : Qnil;
    m_style = INT2NUM(msg[i]->msg_style);
    rb_ary_push(rmsg,
		rb_struct_new(rb_sPAMMessage, m_style, m_msg, 0));
  };

  /* An exception will be raised. */
  if( SYMBOL_P(func) ){
    rres = rb_funcall(rb_mKernel, SYM2ID(func), 2, rmsg, data);
  }
  else{
    rres = rb_funcall(func, rb_intern("call"), 2, rmsg, data);
  };

  if( TYPE(rres) != T_ARRAY ){
    rb_raise(rb_eTypeError,"return type must be Array of PAM::Response");
  };

  /*
  while( RARRAY(rres)->len < num_msg ){
    rb_ary_push(rres,Qnil);
  };
  */

  reply = (struct pam_response *)malloc(sizeof(struct pam_response) * num_msg);
  if( !reply ){
    rb_raise(rb_eRuntimeError,"can't allocate the memory");
  };
  for( i = 0; i < num_msg; i++ ){
    VALUE rrep = rb_ary_entry(rres,i);
    if( rrep != Qnil ){
      VALUE r_resp = rb_struct_getmember(rrep,rb_intern("resp"));
      VALUE r_retcode = rb_struct_getmember(rrep,rb_intern("resp_retcode"));

      reply[i].resp = ((r_resp != Qnil) ? strdup(STR2CSTR(r_resp)) : NULL);
      reply[i].resp_retcode = ((r_retcode != Qnil) ? NUM2INT(r_retcode) : 0);
    }
    else{
      reply[i].resp = NULL;
      reply[i].resp_retcode = 0;
    };
  };
  *resp = reply;

  return PAM_SUCCESS;
};

#define CREATE_PAM_CONV(arg_conv,arg_data) { \
  arg_conv = (struct pam_conv *)malloc(sizeof(struct pam_conv)); \
  arg_conv->conv = rb_pam_inner_conv; \
  arg_conv->appdata_ptr = (void*)arg_data; \
}

#define CREATE_PAM_CONV2(arg_conv,arg_proc,arg_data) { \
  arg_conv = (struct pam_conv *)malloc(sizeof(struct pam_conv)); \
  arg_conv->conv = rb_pam_inner_conv; \
  arg_conv->appdata_ptr = (void*)rb_assoc_new(arg_proc,arg_data); \
}

static void
rb_pam_handle_free(struct rb_pam_struct *pam)
{
  if( pam && pam->start ){
    pam_end(pam->ptr,pam->status);
    pam->start = 0;
    if( pam->conv ){
      free(pam->conv);
    };
  };
};

static void
rb_pam_handle_gc_mark(struct rb_pam_struct *pam)
{
  if( pam && pam->start && pam->conv ){
    rb_gc_mark((VALUE)(pam->conv->appdata_ptr));
  };
};

VALUE
rb_pam_handle_new(pam_handle_t *pamh)
{
  VALUE obj;
  struct rb_pam_struct *pam;

  obj = Data_Make_Struct(rb_cPAMHandle,struct rb_pam_struct,
			 rb_pam_handle_gc_mark,rb_pam_handle_free,pam);
  pam->ptr = pamh;
  pam->start = 0;
  pam->status = PAM_SUCCESS;
  pam->conv = NULL;
  
  return obj;
};

VALUE
rb_pam_handle_s_allocate(VALUE klass)
{
  VALUE obj;
  struct rb_pam_struct *pam;

  obj = Data_Make_Struct(rb_cPAMHandle, struct rb_pam_struct,
			 rb_pam_handle_gc_mark, rb_pam_handle_free, pam);
  pam->ptr = 0;
  pam->start = 0;
  pam->status = 0;
  pam->conv = NULL;

  return obj;
}

VALUE
rb_pam_handle_initialize(int argc, VALUE argv[], VALUE self)
{
  struct rb_pam_struct *pam;
  pam_handle_t *pamh = NULL;
  char *c_service = NULL;
  char *c_user = NULL;
  struct pam_conv *c_conv = NULL; 
  VALUE service, user, conv, data;
  int   status;

  switch( rb_scan_args(argc, argv, "31", &service, &user, &conv, &data) ){
  case 3:
    c_service = STR2CSTR(service);
    c_user = STR2CSTR(user);
    CREATE_PAM_CONV2(c_conv,conv,Qnil);
    break;
  case 4:
    c_service = STR2CSTR(service);
    c_user = STR2CSTR(user);
    CREATE_PAM_CONV2(c_conv,conv,data);
    break;
  default:
    rb_bug("rb_pam_handle_s_start");
  };

  if( (status = pam_start(c_service, c_user, c_conv, &pamh)) == PAM_SUCCESS ){
    Data_Get_Struct(self, struct rb_pam_struct, pam);
    if( pam->ptr && pam->start ){
      pam_end(pam->ptr, pam->status);
    }
    if( pam->conv ){
      free(pam->conv);
    }
    pam->ptr = pamh;
    pam->start = 1;
    pam->status = status;
    pam->conv = c_conv;
  }
  else{
    rb_pam_raise(status, "pam_start");
  };

  if( rb_block_given_p() ){
    rb_ensure(rb_yield,self,rb_pam_handle_end,self);
  };

  return Qnil;
};

VALUE
rb_pam_handle_s_start(int argc, VALUE argv[], VALUE klass)
{
  VALUE obj;

  obj = rb_pam_handle_s_allocate(klass);
  rb_obj_call_init(obj, argc, argv);

  return obj;
}

VALUE
rb_pam_handle_end(VALUE self)
{
  struct rb_pam_struct *pam;
  int c_retval;
  VALUE retval;

  Data_Get_Struct(self, struct rb_pam_struct, pam);

  if( ! pam->start ){
    rb_pam_raise(0, "pam hander is invalid");
  };
  pam->start = 0;

  if( (pam->status = pam_end(pam->ptr,pam->status)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status, "pam_end");
  };

  if( pam->conv ){
    free(pam->conv);
  };
  
  return Qnil;
};

VALUE
rb_pam_handle_conv(VALUE self, VALUE ary)
{
  struct rb_pam_struct *pam;
  struct pam_conv *conv;
  struct pam_message **msg;
  struct pam_response *resp;
  int status, i, msg_len;
  VALUE r;
  
  Check_Type(ary, T_ARRAY);
  Data_Get_Struct(self, struct rb_pam_struct, pam);
  status = pam_get_item(pam->ptr, PAM_CONV, (void*)(&conv));
  if( status != PAM_SUCCESS || !conv )
    rb_pam_raise(status, "rb_pam_handle_conv");

  msg_len = RARRAY(ary)->len;
  msg = (struct pam_message **)ALLOCA_N(struct pam_message *, msg_len);
  for( i=0; i<msg_len; i++ ){
    VALUE elem = RARRAY(ary)->ptr[i];
    VALUE m_style, m_msg;
    m_style = rb_struct_getmember(elem, rb_intern("msg_style"));
    m_msg = rb_struct_getmember(elem, rb_intern("msg"));
    msg[i] = (struct pam_message *)ALLOCA_N(struct pam_message, 1);
    msg[i]->msg_style = NUM2INT(m_style);
    if( m_msg == Qnil ){
      msg[i]->msg = NULL;
    }
    else{
      msg[i]->msg = (char*)ALLOCA_N(char, RSTRING(m_msg)->len + 1);
      strcpy((char*)(msg[i]->msg), STR2CSTR(m_msg));
    };
  };

  resp = NULL;
  status = (*(conv->conv))(msg_len, (const struct pam_message **)msg,
			   &resp, conv->appdata_ptr);
  if( status != PAM_SUCCESS || !resp ){
    rb_pam_raise(status, "conversation error");
  };

  /*
   * note that 'resp' is allocated by the application and is
   * correctly free()'d here
   */
  r = rb_ary_new();
  for( i=0; i<msg_len; i++ ){
    VALUE elem;
    VALUE r_resp;
    VALUE r_retcode;
    if( resp[i].resp ){
      r_resp = rb_tainted_str_new2(resp[i].resp);
      free(resp[i].resp);
    }
    else{
      r_resp = Qnil;
    };
    r_retcode = INT2NUM(resp[i].resp_retcode);
    elem = rb_struct_new(rb_sPAMResponse, r_resp, r_retcode, 0);
    rb_ary_push(r, elem);
  };
  free(resp);

  return r;
};

VALUE
rb_pam_handle_status(VALUE self)
{
  struct rb_pam_struct *pam;

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  return INT2NUM(pam->status);
};

VALUE
rb_pam_handle_authenticate(int argc, VALUE argv[], VALUE self)
{
  struct rb_pam_struct *pam;
  int c_flag;
  VALUE flag;

  switch( rb_scan_args(argc, argv, "01", &flag) ){
  case 0:
    c_flag = 0;
    break;
  case 1:
    if( flag == Qnil ){
      c_flag = 0;
    }
    else{
      c_flag = NUM2INT(flag);
    };
    break;
  default:
    rb_bug("rb_pam_handle_authenticate");
  }
  
  Data_Get_Struct(self,struct rb_pam_struct,pam);
  if( (pam->status = pam_authenticate(pam->ptr,c_flag)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status, "pam_authenticate");
  };

  return Qnil;
};

VALUE
rb_pam_handle_acct_mgmt(int argc, VALUE argv[], VALUE self)
{
  struct rb_pam_struct *pam;
  int c_flag;
  VALUE flag;

  switch( rb_scan_args(argc, argv, "01", &flag) ){
  case 0:
    c_flag = 0;
    break;
  case 1:
    if( flag == Qnil ){
      c_flag = 0;
    }
    else{
      c_flag = NUM2INT(flag);
    };
    break;
  default:
    rb_bug("rb_pam_handle_acct_mgmt");
  };

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  if( (pam->status = pam_acct_mgmt(pam->ptr,c_flag)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status, "pam_acct_mgmt");
  };

  return Qnil;
};

VALUE
rb_pam_handle_set_fail_delay(VALUE self, VALUE msec)
{
#ifdef HAVE_PAM_FAIL_DELAY
  struct rb_pam_struct *pam;
  int c_msec;

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  c_msec = NUM2INT(msec);
  if( (pam->status = pam_fail_delay(pam->ptr,c_msec)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status, "pam_fail_delay");
  };
#else
  rb_notimplement();
#endif

  return Qnil;
};  

VALUE
rb_pam_handle_setcred(int argc, VALUE argv[], VALUE self)
{
#ifdef HAVE_PAM_SETCRED
  struct rb_pam_struct *pam;
  int c_flag;
  VALUE flag;

  switch( rb_scan_args(argc, argv, "01", &flag) ){
  case 0:
    c_flag = 0;
    break;
  case 1:
    if( flag == Qnil ){
      c_flag = 0;
    }
    else{
      c_flag = NUM2INT(flag);
    };
    break;
  default:
    rb_bug("rb_pam_handle_setcred");
  };

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  if( (pam->status = pam_setcred(pam->ptr,c_flag)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status,"pam_setcred");
  };
#else
  rb_notimplement();
#endif

  return Qnil;
};  

VALUE
rb_pam_handle_chauthtok(int argc, VALUE argv[], VALUE self)
{
#ifdef HAVE_PAM_CHAUTHTOK
  struct rb_pam_struct *pam;
  int c_flag;
  VALUE flag;

  switch( rb_scan_args(argc, argv, "01", &flag) ){
  case 0:
    c_flag = 0;
    break;
  case 1:
    if( flag == Qnil ){
      c_flag = 0;
    }
    else{
      c_flag = NUM2INT(flag);
    };
    break;
  default:
    rb_bug("rb_pam_handle_chauthtok");
  };

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  c_flag = NUM2INT(flag);
  if( (pam->status = pam_chauthtok(pam->ptr,c_flag)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status, "pam_chauthtok");
  };
#else
  rb_notimplement();
#endif

  return Qnil;
};  


VALUE
rb_pam_handle_close_session(int argc, VALUE argv[], VALUE self)
{
#ifdef HAVE_PAM_CLOSE_SESSION
  struct rb_pam_struct *pam;
  int c_flag;
  VALUE flag;

  switch( rb_scan_args(argc, argv, "01", &flag) ){
  case 0:
    c_flag = 0;
    break;
  case 1:
    if( flag == Qnil ){
      c_flag = 0;
    }
    else{
      c_flag = NUM2INT(flag);
    };
    break;
  default:
    rb_bug("rb_pam_handle_close_session");
  };

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  if( (pam->status = pam_close_session(pam->ptr,c_flag)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status,"pam_close_session");
  };
#else
  rb_notimplement();
#endif

  return Qnil;
};  

static VALUE
rb_pam_handle_open_session_ensure(VALUE self)
{
  return rb_pam_handle_close_session(0, 0, self);
};

VALUE
rb_pam_handle_open_session(int argc, VALUE argv[], VALUE self)
{
#ifdef HAVE_PAM_OPEN_SESSION
  struct rb_pam_struct *pam;
  int c_flag;
  VALUE flag;

  switch( rb_scan_args(argc, argv, "01", &flag) ){
  case 0:
    c_flag = 0;
    break;
  case 1:
    if( flag == Qnil ){
      c_flag = 0;
    }
    else{
      c_flag = NUM2INT(flag);
    };
    break;
  default:
    rb_bug("rb_pam_handle_open_session");
  };

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  if( (pam->status = pam_open_session(pam->ptr,c_flag)) != PAM_SUCCESS ){
    rb_pam_raise(pam->status,"pam_open_session");
  };
#else
  rb_notimplement();
#endif

  if( rb_block_given_p() ){
    rb_ensure(rb_yield, self, rb_pam_handle_open_session_ensure, self);
  };

  return Qnil;
};  


VALUE
rb_pam_handle_set_item(VALUE self, VALUE type, VALUE item)
{
  struct rb_pam_struct *pam;
  void *c_item;
  int c_type;

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  c_type = NUM2INT(type);
  switch( c_type ){
  case PAM_SERVICE:
  case PAM_USER:
  case PAM_TTY:
  case PAM_RHOST:
  case PAM_RUSER:
  case PAM_USER_PROMPT:
    c_item = (void*)STR2CSTR(item);
    break;
  case PAM_CONV:
    {
      struct pam_conv *c_conv;
      CREATE_PAM_CONV(c_conv,item);
      free(pam->conv);
      pam->conv = c_conv;
      c_item = (void*)c_conv;
    };
    break;
  default:
    rb_raise(rb_eArgError,"unkown item type");
  };
  pam->status = pam_set_item(pam->ptr,c_type,c_item);
  return INT2NUM(pam->status);
};

VALUE
rb_pam_handle_get_item(VALUE self, VALUE type)
{
  struct rb_pam_struct *pam;
  const void *c_item;
  int c_type;
  VALUE ret;

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  c_type = NUM2INT(type);
  pam->status = pam_get_item(pam->ptr,c_type,&c_item);

  if( !c_item ){
    return Qnil;
  };

  switch( c_type ){
  case PAM_SERVICE:
  case PAM_USER:
  case PAM_TTY:
  case PAM_RHOST:
  case PAM_RUSER:
  case PAM_USER_PROMPT:
    ret = rb_str_new2((char*)c_item);
    break;
  case PAM_CONV:
    {
      struct pam_conv *conv = (struct pam_conv *)c_item;
      if( conv->conv == rb_pam_inner_conv ){
	ret = (VALUE)(conv->appdata_ptr);
      }
      else{
	ret = rb_assoc_new(INT2NUM((long)(conv->conv)),
			   INT2NUM((long)(conv->appdata_ptr)));
      };
    }
    break;
  default:
    rb_raise(rb_eArgError,"unknown item type");
  };

  return ret;
};

VALUE
rb_pam_handle_strerror(VALUE self, VALUE errnum)
{
  struct rb_pam_struct *pam;
  const char *str;

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  pam->status = -1;
  return( (str = pam_strerror(pam->ptr,NUM2INT(errnum))) ? rb_str_new2(str) : Qnil);
};

VALUE
rb_pam_handle_putenv(VALUE self, VALUE val)
{
#ifdef HAVE_PAM_PUTENV
  struct rb_pam_struct *pam;

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  pam->status = -1;
  return INT2NUM(pam_putenv(pam->ptr,STR2CSTR(val)));
#else
  rb_notimplemented();
#endif
};

VALUE
rb_pam_handle_getenv(VALUE self, VALUE val)
{
#ifdef HAVE_PAM_GETENV
  struct rb_pam_struct *pam;
  const char *str;

  Data_Get_Struct(self,struct rb_pam_struct,pam);
  pam->status = -1;
  return( (str = pam_getenv(pam->ptr,STR2CSTR(val))) ? rb_str_new2(str) : Qnil);
#else
  rb_notimplemented();
#endif
};

void
Init_pam_handle()
{
  rb_cPAMHandle = rb_define_class_under(rb_mPAM,"Handle",rb_cObject);
#if RUBY_VERSION_CODE < 170
  rb_define_singleton_method(rb_cPAMHandle,"new",rb_pam_handle_s_start,-1);
#endif
  rb_define_singleton_method(rb_cPAMHandle,"start",rb_pam_handle_s_start,-1);
#if RUBY_VERSION_CODE >= 173
  rb_define_alloc_func(rb_cPAMHandle,rb_pam_handle_s_allocate);
#else
  rb_define_singleton_method(rb_cPAMHandle,"allocate",rb_pam_handle_s_allocate,0);
#endif

#define rb_pamh_define_method(name,func,argc) \
  rb_define_method(rb_cPAMHandle,name,func,argc)
  rb_pamh_define_method("conv", rb_pam_handle_conv, 1);
  rb_pamh_define_method("initialize", rb_pam_handle_initialize, -1);
  rb_pamh_define_method("status",rb_pam_handle_status,0);
  rb_pamh_define_method("end",rb_pam_handle_end,0);
  rb_pamh_define_method("authenticate",rb_pam_handle_authenticate,-1);
  rb_pamh_define_method("acct_mgmt",rb_pam_handle_acct_mgmt,-1);
  rb_pamh_define_method("set_fail_delay",rb_pam_handle_set_fail_delay,1);
  rb_pamh_define_method("setcred",rb_pam_handle_setcred,-1);
  rb_pamh_define_method("chauthtok",rb_pam_handle_chauthtok,-1);
  rb_pamh_define_method("open_session",rb_pam_handle_open_session,-1);
  rb_pamh_define_method("close_session",rb_pam_handle_close_session,-1);
  rb_pamh_define_method("set_item",rb_pam_handle_set_item,2);
  rb_pamh_define_method("get_item",rb_pam_handle_get_item,1);
  rb_pamh_define_method("strerror",rb_pam_handle_strerror,1);
  rb_pamh_define_method("putenv",rb_pam_handle_putenv,1);
  rb_pamh_define_method("getenv",rb_pam_handle_getenv,1);
#undef rb_pamh_define_method

};
