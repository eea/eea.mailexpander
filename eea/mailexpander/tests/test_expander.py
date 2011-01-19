import os
import ldap
import smtplib
import unittest
import logging
from mock import Mock, patch, wraps

from eea.mailexpander.expander import Expander, RETURN_CODES, log
from test_ldap_agent import StubbedLdapAgent

log.setLevel(logging.INFO)
class ExpanderTest(unittest.TestCase):
    def setUp(self):
        self.smtp = Mock()
        self.agent = StubbedLdapAgent(ldap_server='')
        self.mock_conn = self.agent.conn

        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        ldap_data = [
            (role_dn('test'), ldap.SCOPE_BASE, [
                (role_dn('test'), {
                    'uniqueMember': [ user_dn('userone'), user_dn('usertwo'),],
                    'permittedPerson': [ user_dn('userone') ],
                    'permittedSender': ['alexandru.plugaru@eaudeweb.ro',
                                        '*@eaudeweb.ro', 'members', 'owners'],
                    'owner': [ user_dn('user3') ]
                }),
            ]),
            (user_dn('userone'), ldap.SCOPE_BASE, [
                (user_dn('userone'), {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                    'telephoneNumber': ['555 1234 2'],
                    'o': ['Testers Club'],
                }),
            ]),
            (user_dn('usertwo'), ldap.SCOPE_BASE, [
                (user_dn('usertwo'), {
                    'cn': ['User two'],
                    'mail': ['user_two@example.com'],
                    'telephoneNumber': ['5155 1234 2'],
                    'o': ['Testers Club 2'],
                }),
            ]),
            (user_dn('user3'), ldap.SCOPE_BASE, [
                (user_dn('user3'), {
                    'cn': ['User three'],
                    'mail': ['user_three@example.com'],
                    'telephoneNumber': ['5155 1234 2'],
                    'o': ['Testers Club 2'],
                }),
            ]),
        ]

        def ldap_search_called(dn, scope, **kwargs):
            for l_dn, l_scope, data in ldap_data:
                if (l_dn, l_scope) == (dn, scope):
                    return data
            return []

        self.mock_conn.search_s.side_effect = ldap_search_called
        def smtp_sendmail_called(from_email, emails, content):
            assert emails == ['user_two@example.com', 'user_one@example.com']
            assert content == open(os.path.join(os.path.dirname(__file__),
                                    'mail_content.txt')).read()

        self.smtp.sendmail.side_effect = smtp_sendmail_called

    def test_expand(self):
        """ Expand lists """
        expander = Expander(self.agent, self.smtp)

        from_email = 'alexandru.plugaru@eaudeweb.ro'
        role_email = 'test@roles.eionet.europa.eu'
        content = open(os.path.join(os.path.dirname(__file__),
                                    'mail_content.txt')).read()

        return_code = expander.expand(from_email, role_email, content)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Should work see permittedSender: *@eaudeweb.ro
        from_email = 'someone@eaudeweb.ro'
        return_code = expander.expand(from_email, role_email, content)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Should fail - no such user
        from_email = 'someone@yyyy.ro'
        return_code = expander.expand(from_email, role_email, content)
        self.assertEqual(return_code, RETURN_CODES['EX_NOPERM'])

        #Owner can send
        from_email = 'user_three@example.com'
        return_code = expander.expand(from_email, role_email, content)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Member can send
        from_email = 'user_one@example.com'
        return_code = expander.expand(from_email, role_email, content)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Should fail.. no such role
        role_email = 'test1@roles.eionet.europa.eu'
        return_code = expander.expand(from_email, role_email, content)
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

