# -*- ruby -*-
# $Id: check_get_item.rb,v 1.1 2002/11/06 08:04:49 ttate Exp $

require "pam"

def pam_conv(msgs, data)
  ret = []

  msgs.each{|msg|
    case msg.msg_style
    when PAM::PAM_PROMPT_ECHO_ON
      printf("User: ")
      if( user = $stdin.gets )
	user.chomp!
      end
      ret.push(PAM::Response.new(user,0))
    when PAM::PAM_PROMPT_ECHO_OFF
      printf("Password: ")
      `stty -echo`
      begin
	if( pass = $stdin.gets )
	  pass.chomp!
	end
      ensure
	`stty echo`
      end
      ret.push(PAM::Response.new(pass, 0))
    else
      ret.push(PAM::Response.new(nil, 0))
    end
  }

  ret
end

conv = proc{|msg| pam_conv(msg)}
user = ENV['LOGNAME']
data = user

PAM.start("check_user",user,conv,data){|pam|
  conv2,data2 = pam.get_item(PAM::PAM_CONV)
  if( conv == conv2 && data == data2 )
    print("ok\n")
  else
    print("error\n")
  end
}
