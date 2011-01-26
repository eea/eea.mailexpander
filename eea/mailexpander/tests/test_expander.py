#!/usr/bin/env python
# -*- coding: utf-8 -*-

import email
import ldap
import logging
import os
import smtplib
import unittest
from copy import deepcopy
from mock import Mock, patch, wraps

from eea.mailexpander.expander import Expander, RETURN_CODES, log
from test_ldap_agent import StubbedLdapAgent

log.setLevel(logging.CRITICAL)

with open(os.path.join(os.path.dirname(__file__), 'mail_content.txt')) as f:
    body_fixture = f.read()

class ExpanderTest(unittest.TestCase):
    def setUp(self):
        self.smtp = Mock()
        self.agent = StubbedLdapAgent(ldap_server='')
        self.mock_conn = self.agent.conn

        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        self.ldap_data = [
            (role_dn('test'), ldap.SCOPE_BASE, [
                [role_dn('test'), {
                    'uniqueMember': [ user_dn('userone'), user_dn('usertwo'),],
                    'permittedPerson': [ user_dn('user4') ],
                    'permittedSender': ['alexandru.plugaru@eaudeweb.ro',
                                        '*@eaudeweb.ro', 'members', 'owners'],
                    'owner': [ user_dn('user3') ]
                }],
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
                    'mail': ['user_three@example.com',
                             'user_3333@example.com'],
                    'telephoneNumber': ['5155 1234 2'],
                    'o': ['Testers Club 2'],
                }),
            ]),
            (user_dn('user4'), ldap.SCOPE_BASE, [
                (user_dn('user4'), {
                    'cn': ['User four'],
                    'mail': ['user_four@example.com'],
                    'telephoneNumber': ['5155 1234 2'],
                    'o': ['Testers Club 5'],
                }),
            ]),
        ]

        def ldap_search_called(dn, scope, **kwargs):
            for l_dn, l_scope, data in self.ldap_data:
                if (l_dn, l_scope) == (dn, scope):
                    return data
            return []

        self.mock_conn.search_s.side_effect = ldap_search_called

    def test_send(self):
        """ Test basic sending with sendmail """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'
        dest_emails = ['user_two@example.com', 'user_one@example.com']

        smtp_mock = Mock()

        expander = Expander(self.agent, smtp_mock)
        expander.can_expand = Mock(return_value=True)
        return_code = expander.expand(from_email, role_email, body_fixture)

        new_body_fixture = smtp_mock.sendmail.call_args[0][2]
        smtp_mock.sendmail.assert_called_once_with(from_email, dest_emails,
                                                   new_body_fixture)

        #Check the modified headers
        em = email.message_from_string(new_body_fixture)
        self.assertEqual(len(em.get_all('received')), 2)
        self.assertEqual(len(em.get_all('resent-from')), 1)
        self.assertEqual(em.get('resent-from'), role_email)
        self.assertTrue(em.get('subject').startswith('[%s]' %
                                                     role_email.split('@')[0]))

        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_send_failure(self):
        """ Some failure tests """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'

        smtp_mock = Mock()
        smtp_mock.sendmail.side_effect = Mock(
            side_effect=smtplib.SMTPException)

        expander = Expander(self.agent, smtp_mock)
        return_code = expander.expand(from_email, role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_SOFTWARE'])

    def test_can_expand(self):
        """ Check if the user can expand """

        smtp_mock = Mock()
        def smtp_sendmail_called(from_email, emails, content):
            """ Content is modified but this is not the subject of this test"""
            assert emails == ['user_two@example.com', 'user_one@example.com']

        smtp_mock.sendmail.side_effect = smtp_sendmail_called

        expander = Expander(self.agent, smtp_mock)

        role_email = 'test@roles.eionet.europa.eu'

        return_code = expander.expand('alexandru.plugaru@eaudeweb.ro',
                                      role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Should work see permittedSender: *@eaudeweb.ro
        return_code = expander.expand('someone@eaudeweb.ro',
                                      role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Should fail - no such user
        return_code = expander.expand('someone@yyyy.ro', role_email,
                                      body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_NOPERM'])

        #Owner can send
        return_code = expander.expand('user_three@example.com', role_email,
                                      body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Member can send
        return_code = expander.expand('user_one@example.com',
                                      role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #PermitedPerson
        return_code = expander.expand('user_four@example.com',
                                      role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_ldap(self):
        """ Test ldap errors """

        expander = Expander(self.agent, self.smtp)
        from_email = 'user_one@example.com'
        role_email = 'test12@roles.eionet.europa.eu'

        #Should fail.. no such role
        return_code = expander.expand(from_email, role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])


        #Ldap server is down
        self.agent.get_role = Mock(side_effect=ldap.SERVER_DOWN)
        return_code = expander.expand(from_email, role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_TEMPFAIL'])

        #Other error
        self.agent.get_role = Mock(side_effect=TypeError)
        return_code = expander.expand(from_email, role_email, body_fixture)
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

    def test_batch(self):
        """ Test sending batch e-mails. Generate 60 ldap users and expect
        batches of 50 e-mails

        """
        user_dn = self.agent._user_dn

        user_dns = []
        ldap_data = deepcopy(self.ldap_data)

        for i in range(1, 119):
            ldap_data.append(
                (user_dn('usertest%s' % i), ldap.SCOPE_BASE, [
                    (user_dn('usertest%s' % i), {
                        'cn': ['User %s' % i],
                        'mail': ['user.%s@example.com' % i],
                        'telephoneNumber': ['11111'],
                        'o': ['Testers Club %s' % i],
                    }),
                ], )
            )
            user_dns.append(user_dn('usertest%s' % i))
        ldap_data[0][2][0][1]['uniqueMember'].extend(user_dns) #Adding members

        def ldap_search_called(dn, scope, **kwargs):
            for l_dn, l_scope, data in ldap_data:
                if (l_dn, l_scope) == (dn, scope):
                    return data
            return []

        self.mock_conn.search_s.side_effect = ldap_search_called

        global total_mails
        total_mails = 0 #Count all emails
        def smtp_sendmail_called(from_email, emails, content):
            assert len(emails) <= 50
            global total_mails
            total_mails += len(emails)

        smtp_mock = Mock()
        smtp_mock.sendmail.side_effect = smtp_sendmail_called

        expander = Expander(self.agent, smtp_mock)
        return_code = expander.expand('user_one@example.com',
                                      'test@roles.eionet.europa.eu',
                                      body_fixture)
        self.assertEqual(total_mails, 120)

if __name__ == '__main__':
    unittest.main()

