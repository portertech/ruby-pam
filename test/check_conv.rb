# -*- ruby -*-
# $Id: check_conv.rb,v 1.1 2002/11/06 08:04:49 ttate Exp $

require "pam"

def pam_conv(msgs, data)
  ret = []

  msgs.each{|msg|
    case msg.msg_style
    when PAM::PAM_PROMPT_ECHO_ON
      printf(msg.msg)
      if( str = $stdin.gets )
	str.chomp!
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
  msg = [PAM::Message.new(PAM::PAM_PROMPT_ECHO_ON, "login: "),
	 PAM::Message.new(PAM::PAM_PROMPT_ECHO_OFF, "passwd: ")]
  p msg
  rs = pam.conv(msg)
  p rs
}
