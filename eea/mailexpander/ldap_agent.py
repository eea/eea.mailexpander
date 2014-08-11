# -*- coding: utf-8 -*-

__version__ = """$Id$"""

import ldap, ldap.filter

class LdapAgent(object):
    def __init__(self, **config):
        self.ldap_server = config['ldap_server']
        if self.ldap_server[:7] != 'ldap://':
            self.ldap_server = 'ldap://' + self.ldap_server
        self.conn = self.connect()
        self.conn.protocol_version = ldap.VERSION3
        self._encoding = config.get('encoding', 'utf-8')
        self._user_dn_suffix = config.get('users_dn',
                                          "ou=Users,o=EIONET,l=Europe")
        self._role_dn_suffix = config.get('roles_dn',
                                          "ou=Roles,o=EIONET,l=Europe")

    def connect(self):
        conn = ldap.initialize(self.ldap_server)
        conn.protocol_version = ldap.VERSION3
        return conn

    def _ancestor_roles_dn(self, role_dn):
        """
        Given a subrole dn, returns a list of all ancestors. First is
        the given subrole, then the ancestors, with last element the top-most
        one.
        """

        # Example usage::
        #     >>> self._ancestor_roles_dn(
        #     ...   "cn=eionet-nfp,cn=eionet,ou=Roles,o=EIONET,l=Europe")
        #     ['cn=eionet-nfp,ou=Roles,o=EIONET,l=Europe',
        #      'cn=eionet,ou=Roles,o=EIONET,l=Europe']

        assert role_dn.endswith(',' + self._role_dn_suffix), "Invalid Role DN"
        role_dn_start = role_dn[: - (len(self._role_dn_suffix) + 1)]
        dn_bits = role_dn_start.split(',')
        dn_bits.reverse()

        ancestors = []
        accumulator = self._role_dn_suffix
        for bit in dn_bits:
            assert bit.startswith('cn=')
            accumulator = bit + "," + accumulator
            ancestors.insert(0, accumulator)

        return ancestors

    def _query(self, dn):
        # This query naively thinks that all searches return something
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
        """ Returns a dictionary describing the role `role_id`.
        Also return all the members and their emails

        """

        query_dn = self._role_dn(role_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE)

        try:
            assert len(result) == 1
            dn, attr = result[0]
            assert dn.lower() == query_dn.lower()
        except AssertionError:
            raise ValueError

        def get_data(data, key, target_attr):
            return_attr = {}
            if data.has_key(key):
                for dn in data[key]:
                    if dn == '': continue #Ignore empty DN attributes
                    try: return_attr[dn] = self._query(dn)
                    except: pass # Ignore members that don't exist in ldap any longer
            return {target_attr: return_attr}

        attr.update(get_data(attr, 'uniqueMember', 'members_data'))
        attr.update(get_data(attr, 'owner', 'owners_data'))

        return attr
