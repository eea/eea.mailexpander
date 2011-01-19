# -*- coding: utf-8 -*-
import ldap, ldap.filter

class LdapAgent(object):
    def __init__(self, **config):
        self.conn = self.connect(config['ldap_server'])
        self.conn.protocol_version = ldap.VERSION3
        self._encoding = config.get('encoding', 'utf-8')
        self._user_dn_suffix = config.get('users_dn',
                                          "ou=Users,o=EIONET,l=Europe")
        self._role_dn_suffix = config.get('roles_dn',
                                          "ou=Roles,o=EIONET,l=Europe")

    def connect(self, server):
        conn = ldap.initialize('ldap://' + server)
        conn.protocol_version = ldap.VERSION3
        return conn

    def _query(self, dn):
        return self.conn.search_s(dn, ldap.SCOPE_BASE)[0][1]

    def _role_dn(self, role_id):
        if role_id is None:
            id_bits = []
        else:
            id_bits = role_id.split('-')

        dn_start = ''
        for c in range(len(id_bits), 0, -1):
            dn_start += 'cn=%s,' % '-'.join(id_bits[:c])
        return dn_start + self._role_dn_suffix

    def _user_id(self, user_dn):
        assert user_dn.endswith(',' + self._user_dn_suffix)
        assert user_dn.startswith('uid=')
        user_id = user_dn[len('uid=') : - (len(self._user_dn_suffix) + 1)]
        assert ',' not in user_id
        return user_id

    def _user_dn(self, user_id):
        assert ',' not in user_id
        return 'uid=' + user_id + ',' + self._user_dn_suffix

    def get_role(self, role_id):
        """
        Returns a dictionary describing the role `role_id`.
        Also return all the members and their emails
        """

        query_dn = self._role_dn(role_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE)

        assert len(result) == 1
        dn, attr = result[0]
        assert dn == query_dn

        attr['members_data'] = {}
        if 'uniqueMember' in attr:
            for member_dn in attr['uniqueMember']:
                attr['members_data'][member_dn] = self._query(member_dn)
        return attr
