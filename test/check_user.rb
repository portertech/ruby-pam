# -*- ruby -*-
# $Id: check_user.rb,v 1.1 2002/11/06 08:04:49 ttate Exp $

=begin
You need to create the /etc/pam.d/check_user file which
contains the following in the /etc/pam.d directory.

--
auth       required     /lib/security/pam_pwdb.so shadow nullok
account    required     /lib/security/pam_pwdb.so
password   required     /lib/security/pam_cracklib.so
password   required     /lib/security/pam_pwdb.so shadow use_authtok nullok
session    required     /lib/security/pam_pwdb.so
session    optional     /lib/security/pam_xauth.so
--

Or you need to add the following to the /etc/pam.conf file.

--
check_user auth      required /lib/security/pam_pwdb.so shadow nullok
check_user account   required /lib/security/pam_pwdb.so
check_user password  required /lib/security/pam_cracklib.so
check_user password  required /lib/security/pam_pwdb.so shadow use_authtok nullok
check_user session   required /lib/security/pam_pwdb.so
check_user session   optional /lib/security/pam_xauth.so
--

See also the PAM administration guide depended on your OS.
=end


require "pam"

def pam_conv(msgs, data)
  ret = []

  print("pam_conv: data = #{data.inspect}\n")
  msgs.each{|msg|
    case msg.msg_style
    when PAM::PAM_PROMPT_ECHO_ON
      printf(msg.msg)
      if( str = $stdin.gets )
	user.chomp!
      end
      ret.push(PAM::Response.new(str,0))
    when PAM::PAM_PROMPT_ECHO_OFF
      printf(msg.msg)
      `stty -echo`
      begin
	if( str = $stdin.gets )
	  str.chomp!
	end
      ensure
	`stty echo`
      end
      ret.push(PAM::Response.new(str, 0))
    else
      # unexpected, bug?
      ret.push(PAM::Response.new(nil, 0))
    end
  }

  ret
end

if( ARGV[0] && ARGV[1] )
  service = ARGV[0]
  user    = ARGV[1]
else
  print("usage:\n #{$0} <service> <user>\n")
  exit(1)
end
conv = proc{|msg| pam_conv(msg)}
conv_data = user

# PAM.start("check_user", user, conv){|pam|
PAM.start(service, user, :pam_conv, conv_data){|pam|
#  pam.set_fail_delay(0)
#  pam.set_item(PAM::PAM_RUSER, ruser)
#  pam.set_item(PAM::PAM_RHOST, rhost)
#  pam.set_item(PAM::PAM_CONV, [conv, conv_data])
  print("PAM_RUSER   = ", pam.get_item(PAM::PAM_RUSER), "\n")
  print("PAM_RHOST   = ", pam.get_item(PAM::PAM_RHOST), "\n")
  print("PAM_USER    = ", pam.get_item(PAM::PAM_USER), "\n")
  print("PAM_SERVICE = ", pam.get_item(PAM::PAM_SERVICE), "\n")
  print("PAM_CONV    = ", pam.get_item(PAM::PAM_CONV).inspect, "\n")
  begin
    pam.authenticate(0)
  rescue PAM::PAM_USER_UNKNOWN
    print("unknown user: #{pam.get_item(PAM::PAM_USER)}")
    exit(1)
  rescue PAM::PAM_AUTH_ERR
    print("authentication error: #{pam.get_item(PAM::PAM_USER)}\n")
    exit(1)
  rescue PAM::PAMError
    print("error code = #{pam.status}\n")
    exit(1)
  end

  begin
    pam.acct_mgmt(0)
    pam.open_session{
      # do something
    }
  rescue PAM::PAMError
    printf("you can't access.\n")
    exit(1)
  end

  print("\n",
	"authenticated!\n")
}
