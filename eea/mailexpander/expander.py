#!/usr/bin/env python
# -*- coding: utf-8 -*-

import email
import getopt
import ldap
import logging
import smtplib
import sys
import time
from fnmatch import fnmatch

from ldap_agent import LdapAgent

RETURN_CODES = {
   'EX_OK':           0,  # successful termination
   'EX_USAGE':        64, # command line usage error
   'EX_DATAERR':      65, # data format error
   'EX_NOINPUT':      66, # cannot open input
   'EX_NOUSER':       67, # addressee unknown
   'EX_NOHOST':       68, # host name unknown
   'EX_UNAVAILABLE':  69, # service unavailable
   'EX_SOFTWARE':     70, # internal software error
   'EX_OSERR':        71, # system error (e.g., can't fork)
   'EX_OSFILE':       72, # critical OS file missing
   'EX_CANTCREAT':    73, # can't create (user) output file
   'EX_IOERR':        74, # input/output error
   'EX_TEMPFAIL':     75, # temp failure; user is invited to retry
   'EX_PROTOCOL':     76, # remote error in protocol
   'EX_NOPERM':       77, # permission denied
   'EX_CONFIG':       78, # configuration error
}

sys.tracebacklimit = 0
log = logging.getLogger('MAILEXPANDER')
log.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
log.addHandler(stream_handler)

class Expander(object):
    """ """
    def __init__(self, agent, smtp):
        self.agent = agent
        self.smtp = smtp

    def expand(self, from_email, role_email, content):
        """ Get from-email and to-email (a ldap role) and the content.
        Check if the from-email can send to the specified role and then expand
        send the messages to all the members in that role.
        Also queue max 50 messages per send so that the mailer can deliver them
        asynchronously """

        try:
            role, domain = role_email.split('@')
            log.info("New mail from %s to %s", from_email, role_email)

            try:
                role_data = self.agent.get_role(role)
            except ldap.SERVER_DOWN:
                log.error("LDAP server is down")
                return RETURN_CODES['EX_TEMPFAIL']
            except (ldap.NO_SUCH_OBJECT, ValueError):
                log.info("%r role not found in ldap", role)
                return RETURN_CODES['EX_NOUSER']
            except:
                log.error("%r role not found exception", role)
                return RETURN_CODES['EX_NOUSER']

            #Check if from_email can expand
            if self.can_expand(from_email, role_data) is False:
                return RETURN_CODES['EX_NOPERM']

            #Split the emails in to batches
            email_batches = [[]]
            batch = 0
            batch_size = 50 #Send 50 emails batches

            for dn, data in role_data['members_data'].iteritems():
                if len(email_batches[batch]) >= batch_size:
                    batch += 1
                    email_batches.append([]) #Init new batch
                email_batches[batch].extend(data['mail'])

            #Add the necessary headers such as Recieved and modify the subject
            #with [role]
            em = email.message_from_string(content)
            #Prepend to subject:
            subject = em.get('subject')
            if ("[%s] " % role) in subject:
                subject = subject.replace(("[%s]" % role), '')
            em.replace_header('subject', "[%s] %s"  % (role, subject))

            #Add a Recieved: header
            if em.get('received'):
                em.add_header('Received', em.get('received'))

            #Add Sender: header
            if role_email not in em.get_all('sender', []):
                em.add_header('Sender', role_email)

            content = em.as_string()

            #connect to sendmail and send the emails
            for emails in email_batches:
                self.smtp.sendmail(from_email, emails, content)
                log.info("Sent emails to %r", emails)
            return RETURN_CODES['EX_OK']

        except:
            log.error("Internal error")
            return RETURN_CODES['EX_SOFTWARE']

    def can_expand(self, from_email, role_data):
        """ Check if the from_email has the permissions to send to the current
        role. In the current role lookup 2 attributes to see if the users are
        allowed to expand:

        permittedSender -- Possible values:
                            - 'members' (All `uniqueMember` attributes),
                            - 'owners' (All `owner` attributes),
                            - *@domain.com, admin.*@domain.com (fnmatch patters)
                            - alex@domain.com (simple email addresses)
        permittedPerson -- DN of a user (match the user's email with `from_email`)

        """

        if 'permittedSender' in role_data:
            for sender_pattern in role_data['permittedSender']:
                if sender_pattern == 'owners':
                    if 'owner' in role_data:
                        for owner_dn in role_data['owner']:
                            try:
                                owner = self.agent._query(owner_dn)
                            except ldap.INVALID_DN_SYNTAX:
                                log.exception("Invalid DN: %s", owner_dn)
                                continue
                            if from_email in owner['mail']:
                                return True
                elif sender_pattern == 'members':
                    if 'members_data' in role_data:
                        for user_dn, user_attrs in role_data['members_data'].iteritems():
                            if from_email in user_attrs['mail']:
                                return True
                elif fnmatch(from_email, sender_pattern):
                    return True
        if 'permittedPerson' in role_data:
            for permitted_dn in role_data['permittedPerson']:
                try:
                    if from_email in self.agent._query(permitted_dn)['mail']:
                        return True
                except ldap.INVALID_DN_SYNTAX:
                    log.exception("Invalid DN: %s", permitted_dn)
                    continue
        return False

def usage():
    print "%s -r [from-email] -f [to-email] -l [ldap-host] -o [logfile]"
    log.error("Invalid arguments %r", sys.argv)
    sys.exit(RETURN_CODES['EX_USAGE'])

def main():
    log.info("=========== starting rolesmailer ============")

    try: #Handle cmd arguments
        opts, args = getopt.getopt(sys.argv[1:], "r:f:l:o:")
    except getopt.GetoptError, err:
        usage()

    logfile = None
    try:
        opts = dict(opts)
        from_email = opts['-f']
        role_email = opts['-r']
        ldap_server = opts['-l']
        logfile = opts.get('-o')
    except KeyError:
        usage()

    if logfile is not None:
        logfile_handler = logging.FileHandler(logfile, 'w')
        log.setLevel(logging.INFO)
        log.addHandler(logfile_handler)
        log.removeHandler(stream_handler)

    try:
        #Message body + headers come from raw_input. Make sure they stay untouched
        content = ""
        while True:
            buffer = sys.stdin.read()
            if not buffer:
                break
            content += buffer

        #Open connection with the ldap
        try:
            agent = LdapAgent(ldap_server=ldap_server)
        except:
            log.error("Cannot connect to LDAP %s", ldap_server)
            return RETURN_CODES['EX_TEMPFAIL']

        #Since this is the same mailer use localhost
        smtp = smtplib.SMTP('localhost')
        try:
            expander = Expander(agent, smtp)
            return_code = expander.expand(from_email, role_email, content)
        finally:
            smtp.quit()

        return return_code
    except:
        log.error("Unexpected error")
        return RETURN_CODES['EX_SOFTWARE']

if __name__ == '__main__':
    log.removeHandler(stream_handler)
    sys.exit(main())
