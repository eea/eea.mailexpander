import ldap
from mock import Mock, patch, wraps
import unittest

from eea.mailexpander import ldap_agent

class StubbedLdapAgent(ldap_agent.LdapAgent):
    def connect(self, server):
        return Mock()

class LdapAgentTest(unittest.TestCase):
    def setUp(self):
        self.agent = StubbedLdapAgent(ldap_server='')
        self.mock_conn = self.agent.conn

    def test_get_role(self):
        """ Getting role information also
        Test the permittedPerson and the permittedSender attributes """
        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        calls_list = []
        def mock_called(dn, scope, **kwargs):
            expected_dn, expected_scope, ret = calls_list.pop(0)
            assert dn == expected_dn
            assert scope == expected_scope
            return ret

        self.mock_conn.search_s.side_effect = mock_called

        # no local members
        calls_list[:] = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'), {
                    'uniqueMember': [ user_dn('userone'), user_dn('usertwo')],
                    'permittedPerson': [ user_dn('userone') ],
                    'permittedSender': ['alexandru.plugaru@eaudeweb.ro',
                                        '*@eaudeweb.ro', 'members']
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
            ])
        ]

        role_data = self.agent.get_role('A')
        assert role_data['permittedSender'] == ['alexandru.plugaru@eaudeweb.ro',
                                           '*@eaudeweb.ro', 'members']
        assert role_data['permittedPerson'] == [
            'uid=userone,ou=Users,o=EIONET,l=Europe']

        assert role_data['members_data'] == {
            user_dn('userone'): {
                'cn': ['User one'],
                'mail': ['user_one@example.com'],
                'telephoneNumber': ['555 1234 2'],
                'o': ['Testers Club'],
            },
            user_dn('usertwo'): {
                'cn': ['User two'],
                'mail': ['user_two@example.com'],
                'telephoneNumber': ['5155 1234 2'],
                'o': ['Testers Club 2'],
            }}
