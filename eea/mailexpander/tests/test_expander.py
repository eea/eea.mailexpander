#!/usr/bin/env python
# -*- coding: utf-8 -*-

import email
import ldap
import logging
import os
import smtplib
import unittest
from copy import deepcopy
try:
    from email.iterators import body_line_iterator
except ImportError: #py2.4
    from email.Iterators import body_line_iterator
from mock import Mock, patch, wraps

from eea.mailexpander.expander import Expander, RETURN_CODES, log
from test_ldap_agent import StubbedLdapAgent

log.setLevel(logging.CRITICAL)

def ldap_search(dn, scope, ldap_data, **kwargs):
    """ Used to return data from different ldap_data sources """
    for l_dn, l_scope, data in ldap_data:
        if (l_dn, l_scope) == (dn, scope):
            return data
    return []

class ExpanderTest(unittest.TestCase):
    def setUp(self):
        self.agent = StubbedLdapAgent(ldap_server='')
        self.mock_conn = self.agent.conn

        self.expander = Expander(self.agent)
        self.expander.send_emails = Mock(return_value=RETURN_CODES['EX_OK'])

        #Load fixtures from ./fixtures directory into dictionary with keys as
        #filenames without extentions
        self.fixtures = {}
        fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        fixture_paths = os.listdir(fixtures_dir)
        for fixture_filename in fixture_paths:
            fixture_path = os.path.join(fixtures_dir, fixture_filename)
            if os.path.isfile(fixture_path):
                content = None
                f =  open(fixture_path, 'rb')
                content = f.read()
                f.close()
                self.fixtures[os.path.splitext(fixture_filename)[0]] = content

        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        self.ldap_data = [
            (role_dn('test'), ldap.SCOPE_BASE, [
                [role_dn('test'), {
                    'uniqueMember': [ user_dn('userone'), user_dn('usertwo'),],
                    'permittedPerson': [ user_dn('user4') ],
                    'permittedSender': ['test@email.com',
                                        '*@email.com', 'members', 'owners'],
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
            return ldap_search(dn, scope, self.ldap_data, **kwargs)

        self.mock_conn.search_s.side_effect = ldap_search_called

    def test_send(self):
        """ Test successful sending of the e-mails (7bit, 8bit, base64, binary)
        After the modifications of the headers during the expantion
        the content itself should remain unmodified.

        """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'
        dest_emails = ['user_two@example.com', 'user_one@example.com']

        self.expander.can_expand = Mock(return_value=True)

        for fixture_name, fixture_content in self.fixtures.iteritems():
            return_code = self.expander.expand(from_email, role_email,
                                          self.fixtures[fixture_name])
            self.assertEqual(return_code, RETURN_CODES['EX_OK'])

            new_body = self.expander.send_emails.call_args[0][2]

            em = email.message_from_string(new_body)
            self.assertEqual(len(em.get_all('sender')), 1)
            self.assertEqual(em.get('sender'), 'owner-' + role_email)
            self.assertTrue(em.get('subject').startswith('[%s]' %
                                                         role_email.split('@')[0]))

            ignore_headers = ('received', 'sender', 'subject', 'list-id',
                              'list-post', ) #Checked above
            #Check the rest of the message, make sure they stay the same
            old_em = email.message_from_string(
                        email.message_from_string(fixture_content).as_string())

            for header, value in em.items():
                if header.lower() not in ignore_headers:
                    self.assertEquals(value, old_em.get(header))

            if hasattr(str, 'partition'): #Don't test if <2.5
                #Based on boundary make sure the message body is untouched
                boundary = em.get_boundary()
                old_body = old_em.as_string().rpartition(boundary)[0].\
                                    partition(boundary)[2].partition(boundary)[2]
                new_body = em.as_string().rpartition(boundary)[0].\
                                    partition(boundary)[2].partition(boundary)[2]
                self.assertEquals(old_body, new_body)

    def test_send_to_owners(self):
        from_email = 'user_one@example.com'
        role_email = 'owner-test@roles.eionet.europa.eu'
        return_code = self.expander.expand(from_email, role_email,
                                          self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1], [
            'user_three@example.com', 'user_3333@example.com'])

    def test_smtp_failure(self):
        """ SMTP Failure test """

        self.expander.send_emails = Mock(side_effect=smtplib.SMTPException)
        return_code = self.expander.expand('user_one@example.com',
                                      'test@roles.eionet.europa.eu',
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_SOFTWARE'])

    def test_can_expand(self):
        """ Check if the user can expand, test with invalid
        ldap entries

        """
        def send_emails_called(from_email, emails, content):
            """ Content is modified but this is not the subject of this test"""
            assert emails == ['user_two@example.com', 'user_one@example.com']
            return RETURN_CODES['EX_OK']

        self.expander.send_emails.side_effect = send_emails_called

        role_email = 'test@roles.eionet.europa.eu'
        return_code = self.expander.expand('test@email.com',
                                      role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Should work see permittedSender: *@email.com
        return_code = self.expander.expand('someone@email.com',
                                      role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Should fail - no such user
        return_code = self.expander.expand('someone@yyyy.ro', role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOPERM'])

        #Owner can send
        return_code = self.expander.expand('user_three@example.com', role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #Member can send
        return_code = self.expander.expand('user_one@example.com',
                                      role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #PermitedPerson
        return_code = self.expander.expand('user_four@example.com',
                                      role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #PermitedPerson with CamelCase - email addresses are case insensitve
        return_code = self.expander.expand('User_Four@example.com',
                                      role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        #*@email as destination
        return_code = self.expander.expand('user_four@example.com',
                                      '*@email.com',
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

        #te*@email as destination
        return_code = self.expander.expand('user_four@example.com',
                                      'te*@email.com',
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

    def test_anyone_can_expand(self):
        """ Anyone can expand.
        'anyone' value in permittedSender attribute

        """
        user_dn = self.agent._user_dn

        self.agent.get_role = Mock(return_value={
            'description': 'anyone',
            'owner': [user_dn('userone')],
            'members_data': {
                user_dn('userone'): {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
                user_dn('usertest1'): {
                    'cn': ['User 1'],
                    'mail': ['user.1@example.com'],
                },
            },
            'uniqueMember': [
                user_dn('userone'),
                user_dn('usertwo'),
            ],
            'permittedSender': ['anyone',],
        })
        return_code = self.expander.expand('test12342424@email.com',
                                      'test_empty@roles.eionet.europa.eu',
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_ldap(self):
        """ Test ldap errors """

        from_email = 'user_one@example.com'
        role_email = 'test12@roles.eionet.europa.eu'

        #Should fail.. no such role
        return_code = self.expander.expand(from_email, role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

        #Ldap server is down
        self.agent.get_role = Mock(side_effect=ldap.SERVER_DOWN)
        return_code = self.expander.expand(from_email, role_email,
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_TEMPFAIL'])

        #Other error
        self.agent.get_role = Mock(side_effect=TypeError)
        return_code = self.expander.expand(from_email, role_email,
                                      self.fixtures['content_7bit'])
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
            return ldap_search(dn, scope, ldap_data, **kwargs)

        self.mock_conn.search_s.side_effect = ldap_search_called

        global total_mails
        total_mails = 0 #Count all emails
        def send_emails_called(from_email, emails, content):
            assert len(emails) <= 50
            global total_mails
            total_mails += len(emails)
            return RETURN_CODES['EX_OK']

        self.expander.send_emails.side_effect = send_emails_called
        return_code = self.expander.expand('user_one@example.com',
                                      'test@roles.eionet.europa.eu',
                                      self.fixtures['content_7bit'])
        self.assertEqual(total_mails, 120)

    def test_empty_role(self):
        """ Test invalid role scenarios (missing members,
        empty uniqueMember's)

        """

        #No owner attribute - should not fail
        self.agent.get_role = Mock(return_value={
            'description': 'no owner',
            'members_data': {
                'uid=userone,ou=Users,o=EIONET,l=Europe': {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
                'uid=usertest1,ou=Users,o=EIONET,l=Europe': {
                    'cn': ['User 1'],
                    'mail': ['user.1@example.com'],
                },
            },
            'uniqueMember': [
                'uid=userone,ou=Users,o=EIONET,l=Europe',
                'uid=usertwo,ou=Users,o=EIONET,l=Europe',
            ],
            'permittedSender': [
                'test@email.com'
            ]
        })
        return_code = self.expander.expand('test@email.com',
                                      'test_empty@roles.eionet.europa.eu',
                                      self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

if __name__ == '__main__':
    unittest.main()
