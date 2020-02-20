#!/usr/bin/env python3

from common.common import *
from common.mailsender import mailsender

import testcases

config2 = {
	"attacker_site": b"owlhut.com",
	"legitimate_site": b"facebook.com",
	"victim_address": b"abelyang227+test@mail.abelyang.com",
	"case_id": b"case_b1",
}
config = {
	"attacker_site": b"mail1.abelyang.com",
	"legitimate_site": b"mail2.abelyang.com",
	"victim_address": b"abelyang227+test@mail.abelyang.com",
	"case_id": b"case_b1",
}

def fixup_test_case_data(t):
	t = recursive_fixup(t, b"attack.com", config["attacker_site"])
	t = recursive_fixup(t, b"legitimate.com", config["legitimate_site"])
	t= recursive_fixup(t, b"victim@victim.com", config["victim_address"])
	return t

test_cases = fixup_test_case_data(testcases.test_cases)

def build_email(case_id):	
	msg_content = test_cases[case_id]["data"]
	dkim_para = test_cases[case_id].get("dkim_para")
	if dkim_para != None:
		dkim_msg =   dkim_para["sign_header"] +b"\r\n\r\n" + msg_content["body"]
		dkim_header = generate_dkim_header(dkim_msg, dkim_para)
		msg = msg_content["from_header"] + dkim_header + msg_content["to_header"] + msg_content["subject_header"] + msg_content["custom"] + msg_content["other_headers"] + msg_content["body"]
	else:
		msg = msg_content["from_header"] + msg_content["to_header"] + b"Subject: " + case_id.encode("utf-8") + b": "+test_cases[case_id]["case_name"]+ msg_content["custom"] + msg_content["other_headers"] + msg_content["body"]
	return msg

def build_smtp_seqs(case_id):
	cmd_seqs = {
		"helo": test_cases[case_id]["helo"],
		"mailfrom": test_cases[case_id]["mailfrom"],
		"rcptto": test_cases[case_id]["rcptto"],
		"msg_content": build_email(case_id)
	}
	return cmd_seqs

def main():
    case_list = ["a4"]

	# Different cases of inconsistent interpretation of From header between email servers and MUAs
    case_list_diff_from = ["6a","6b","6c","6e","6d","6f"] 	# 6e is our case, but after rcptpolicyd release, it can't be reproduced

	# Figure 8: Different cases of inconsistent interpretations of email addresses between email servers and MUAs.
    case_list_diff_cs = ["8a","8b","8d","8e","8f"]  		# exclude 8c due to obsolete already

	# custom cases
    case_list_our_own = ["00","1a","1b","1c","1d","1e"]			# customize our own testcase here

    case_list = case_list_our_own + case_list_diff_from + case_list_diff_cs
    for s in case_list:
	#cmd_seqs = build_smtp_seqs(config["case_id"].decode("utf-8"))
        print("\n\n####   " + test_cases["case_"+s]["case_name"].decode("utf-8")+ "\n")
        cmd_seqs = build_smtp_seqs("case_"+s)
        mail_server = get_mail_server_from_email(config["victim_address"])
        mail_sender = mailsender()
        mail_sender.set_param((mail_server, 25), rcpt_to = cmd_seqs["rcptto"], email_data = cmd_seqs["msg_content"], helo=cmd_seqs["helo"], mail_from= cmd_seqs["mailfrom"], starttls=True)
        mail_sender.send_email()

if __name__ == '__main__':
    main()



