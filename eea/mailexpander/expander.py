#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = """$Id$"""

import email
import getopt
import ldap
import logging
import smtplib
import sys
import os
import time
import fcntl
import string

from ConfigParser import ConfigParser
from fnmatch import fnmatch
from logging.handlers import SysLogHandler
from subprocess import Popen, PIPE

from ldap_agent import LdapAgent

try:
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
except ImportError, e:
    from email.MIMEText import MIMEText
    from email.MIMEMultipart import MIMEMultipart


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
log = logging.getLogger('rolesexpander')
log.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)

class Expander(object):
    """ Sendmail mailer. Uses LDAP roles to send e-mails to ldap users in that
    specific role. Same behavior as a maillist.

    """
    def __init__(self, ldap_agent, **config):
        self.agent = ldap_agent
        self.sendmail_path = config.get('sendmail_path', '/usr/sbin/sendmail')
        self.archivefile = config.get('mailbox', None)
        also_string = config.get('also_send_to', '')
        self.also_send_to = map(string.strip, also_string.split(','))
        self.noreply = config.get('no_reply', 'no-reply@eea.europa.eu')

    def expand(self, from_email, role_email, content):
        """ Send e-mails to ldap users based on `role_email` checking if
        `from_email` is allowed to do so. Prepend the `role` name to the e-mail
        subject. Modify the headers according to these priciples:
        http://tools.ietf.org/html/rfc5321#page-31
        Also queue max 50 messages per send so that the mailer can deliver them
        asynchronously.

        Arguments::

            from_email -- Sender e-mail (as received from sendmail)
            role_email -- A pseudo address (Ex: ldap-role@roles.eionet.europa.eu)
            content -- E-mail headers and body

        """

        try:
            role = role_email.split('@')[0]
            log.info("New mail from %s to %s", from_email, role_email)

            """ If an e-mail is sent to a role starting with owner- then get
            the `owner` attributes of that `role` and send them the message.
            This is useful when unintended e-mail is sent such as vacation
            reponses.
            """
            send_to_owners = False
            if role.lower().startswith('owner-'):
                role = role.split('owner-')[1]
                send_to_owners = True
            try:
                role_data = self.agent.get_role(role)
                assert 'members_data' in role_data, (
                    '`uniqueMember` attribute is missing')
                # It is perfectly legit to have no owner
                #assert 'owner' in role_data, (
                #    '`owner` attribute is missing')
            except AssertionError:
                log.exception("In %r role:" % role)
                return RETURN_CODES['EX_NOUSER']
            except ldap.SERVER_DOWN:
                log.error("LDAP server is down")
                return RETURN_CODES['EX_TEMPFAIL']
            except (ldap.NO_SUCH_OBJECT, ValueError):
                log.info("%r role not found in ldap", role)
                return RETURN_CODES['EX_NOUSER']
            except:
                log.error("%r role not found exception", role)
                return RETURN_CODES['EX_NOUSER']

            if send_to_owners is True: #Send e-mail to owners
                for owner_dn, owner_data in role_data['owners_data'].items():
                    retval = self.send_emails(from_email, owner_data['mail'],
                                     content)
                    if retval != RETURN_CODES['EX_OK']: return retval
                return RETURN_CODES['EX_OK']

            #Check if from_email can expand
            if self.can_expand(from_email, role_data) is False:
                return RETURN_CODES['EX_NOPERM']

            #Add the necessary headers such as Received and modify the subject
            #with [role]
            em = email.message_from_string(content)
            #Prepend to subject:
            subject = em.get('subject', '(no-subject)')
            if not ("[%s] " % role) in subject:
                subject = "[%s] %s"  % (role, subject)
                try:
                    em.replace_header('subject', subject)
                except KeyError:
                    em.add_header('subject', subject)

            #Add Sender: header
            sender = 'owner-' + role_email
            del em['Sender'] # Exception won't be raised
            em['Sender'] = sender
            # List-Post etc. is described in RFC 2369
            del em['List-Help']
            del em['List-Subscribe']
            del em['List-Unsubscribe']
            del em['List-Owner']
            # List-ID is described in RFC 2919
            del em['List-ID']
            em['List-ID'] = '<%s>' % role_email.replace('@','.')
            del em['List-Post']
            em['List-Post'] = '<mailto:%s>' % role_email # Used by Thunderbird and KMail

            content = em.as_string()

            #Split the emails in to batches
            email_batches = [[]]
            batch = 0
            batch_size = 50 #Send in email batches

            for dn, data in role_data['members_data'].iteritems():
                if len(email_batches[batch]) >= batch_size:
                    batch += 1
                    email_batches.append([]) #Init new batch
                clean_addresses = filter(lambda i: i.find('@')>0, data.get('mail',['']))
                email_batches[batch].extend(clean_addresses)

            self.write_to_archive(from_email, content)

            # If there are any addresses to always send to
            if self.also_send_to != ['']:
                retval = self.send_emails('owner-' + role_email, self.also_send_to, content)

            #Send e-mails
            for emails in email_batches:
                retval = self.send_emails('owner-' + role_email, emails, content)
                if retval != RETURN_CODES['EX_OK']: return retval
            try:
                retval = self.send_confirmation_email(subject, from_email, role)
            except Exception, e:
                log.exception("Error sending confirmation")
            else:
                if retval != RETURN_CODES['EX_OK']:
                    log.error("Error sending confirmation: %d", retval)
            return RETURN_CODES['EX_OK']
        except:
            log.exception("Internal error")
            return RETURN_CODES['EX_SOFTWARE']

    def write_to_archive(self, from_email, content):
        """ Write the email to a MBOX file. (mailbox only does read-only in Python 2.4)
        The lockf call can return IOError, which we abort to writing on
        It is more important that we send the email than we save the message
        """
        if self.archivefile is None:
            return # No mailbox to write to
        mboxfd = open(self.archivefile,'ab')
        try:
            fcntl.lockf(mboxfd, fcntl.LOCK_EX | fcntl.LOCK_NB) # Get an exclusive lock - don't block
            # We could try 10 times and sleep one second between each try
            # if we get an EAGAIN or EACCES error
            # except IOError, e:
            #     if e.errno in (errno.EAGAIN, errno.EACCES): ...
        except:
            log.error("Unable to acquire exclusive lock on %s" % self.archivefile)
            return
        mboxfd.write('From ' + from_email + '  ' + time.asctime() + '\n')
        mboxfd.write(content)
        mboxfd.write('\n')
        fcntl.lockf(mboxfd, fcntl.LOCK_UN) # Not really necessary - we close it
        mboxfd.close()

    def can_expand(self, from_email, role_data):
        """ Check if the from_email has the permissions to send to the current
        role. In the current role lookup 2 attributes to see if the users are
        allowed to expand:

        permittedSender -- Possible values:
                            - 'anyone' (All senders are accepted)
                            - 'members' (All `uniqueMember` attributes),
                            - 'owners' (All `owner` attributes),
                            - *@domain.com, admin.*@domain.com (fnmatch patters)
                            - alex@domain.com (simple email addresses)
        permittedPerson -- DN of a user (match the user's email with `from_email`)

        """

        #Convert to lower in case of mixed-case e-mail addresses
        from_email = from_email.lower()

        if 'permittedSender' in role_data:
            if 'anyone' in role_data['permittedSender']:
                return True
            for sender_pattern in role_data['permittedSender']:
                sender_pattern = sender_pattern.lower()
                if sender_pattern == 'owners':
                    if 'owner' in role_data:
                        for owner_dn in role_data['owner']:
                            try:
                                owner = self.agent._query(owner_dn)
                            except:
                                # Log that we couldn't get the email.
                                log.exception("Invalid `owner` DN: %s", owner_dn)
                                continue
                            if from_email in map(str.lower, owner['mail']):
                                return True
                elif sender_pattern == 'members':
                    if 'members_data' in role_data:
                        for user_dn, user_attrs in role_data['members_data'].iteritems():
                            if from_email in map(str.lower, user_attrs['mail']):
                                return True
                elif fnmatch(from_email, sender_pattern):
                    return True
        if 'permittedPerson' in role_data:
            for permitted_dn in role_data['permittedPerson']:
                try:
                    persons_emails = self.agent._query(permitted_dn)['mail']
                    if from_email in map(str.lower, persons_emails):
                        return True
                except:
                    # Log that we couldn't get the email.
                    log.exception("Invalid DN: %s", permitted_dn)
                    continue
        return False

    def send_confirmation_email(self, subject, to_email, role):
        """ If sending emails succeeded send a confirmation email to sender and
        let him know that everything went as expected

        """
        log.info("Sending confirmation email to %s", to_email)
        content = ""
        confirmation_email_template = os.path.join(os.path.dirname(__file__),
                                                   'templates',
                                                   'confirmation_email.html')
        if os.path.isfile(confirmation_email_template):
            f = open(confirmation_email_template, 'rb')
            content = f.read()
            f.close()

        content = content.replace('{{role_id}}', role)

        html_part = MIMEText(content, 'html')
        message = MIMEMultipart('alternative')
        message['Subject'] = "Confirmation: %s" % subject
        message['From'] = self.noreply
        message['To'] = to_email
        message.attach(html_part)

        smtp = smtplib.SMTP('localhost')
        try:
            try:
                smtp.sendmail(self.noreply, to_email, message.as_string())
                log.debug('Confirmation email sent to %s', to_email)
            except smtplib.SMTPException:
                log.exception("SMTP Error")
                log.error("Failed to send confirmation email using smtplib to %s",
                          to_email)
                return RETURN_CODES['EX_PROTOCOL']
            except:
                log.exception("Unknown smtplib error")
                return RETURN_CODES['EX_UNAVAILABLE']
        finally:
            try:
                smtp.quit()
            except:
                pass

        return RETURN_CODES['EX_OK']

    def send_emails(self, from_email, emails, content):
        """ Use /usr/bin/sendmail or fallback to smtplib.

        """
        if len(emails) == 0: # Nobody to send to - it happens
            return RETURN_CODES['EX_OK']
        try:
            # This should be secure check:
            # http://docs.python.org/library/subprocess.html#using-the-subprocess-module
            # It turns out that sendmail splits the addresses on space, eventhough
            # there is one address per argument. See RFC5322 section 3.4
            # Try: /usr/sbin/sendmail 'soren.roug @eea.europa.eu' and it will complain
            # about the address. We therefore clean them with smtplib.quoteaddr
            quotedemails = map(smtplib.quoteaddr, emails)
            ps = Popen([self.sendmail_path, '-f', smtplib.quoteaddr(from_email), '--'] + quotedemails,
                                                                    stdin=PIPE)
            ps.stdin.write(content)
            ps.stdin.flush()
            ps.stdin.close()
            return_code = ps.wait()
            if return_code in (RETURN_CODES['EX_OK'], RETURN_CODES['EX_TEMPFAIL']):
                log.debug("Sent emails to %r", emails)
                return RETURN_CODES['EX_OK']
            else:
                log.error("Failed to send emails using sendmail to %r. "
                          "/usr/sbin/sendmail exited with code %d", emails,
                          return_code)
            return return_code
        except OSError: #fallback to smtplib
            # Since this is the same mailer we use localhost
            # Smtplib quotes the addresses internally
            log.exception("Cannot use sendmail program. Falling back to "
                          "smtplib.")
            log.warning("If the smtp connection fails some emails will be lost")
            smtp = smtplib.SMTP('localhost')
            try:
                try:
                    smtp.sendmail(from_email, emails, content)
                    log.debug("Sent emails to %r", emails)
                except smtplib.SMTPException:
                    log.exception("SMTP Error")
                    log.error("Failed to send emails using smtplib to %r", emails)
                    return RETURN_CODES['EX_PROTOCOL']
                except:
                    log.exception("Unknown smtplib error")
                    return RETURN_CODES['EX_UNAVAILABLE']
            finally:
                try:
                    smtp.quit()
                except:
                    pass
            return RETURN_CODES['EX_OK']

def usage():
    print ("%s -r [to-email] -f [from-email] -c [config-file] -l [ldap-host] "
          "-o [logfile]") % sys.argv[0]
    # You can't log when you have just removed the log handler
    #log.error("Invalid arguments %r" % sys.argv)
    sys.exit(RETURN_CODES['EX_USAGE'])

def main():
    #Don't return log to output when in mailer
    log.removeHandler(stream_handler)

    try: #Handle cmd arguments
        opts, args = getopt.getopt(sys.argv[1:], "c:r:f:l:o:")
    except getopt.GetoptError, err:
        usage()

    logfile = None
    ldap_config = {}
    sendmail_path = ''
    try:
        opts = dict(opts)
        from_email = opts['-f']
        role_email = opts['-r']
        if '-c' in opts:
            config = ConfigParser()
            config.read([opts['-c']])
            logfile = opts.get('-o', config.get('expander', 'log'))
            expander_config = dict(config.items('expander'))
            ldap_config = dict(config.items('ldap'))
        else:
            ldap_config['ldap_server'] = opts['-l']
            logfile = opts.get('-o')
    except KeyError:
        usage()

    if logfile is not None:
        if logfile == 'syslog':
            log_handler = SysLogHandler('/dev/log', SysLogHandler.LOG_MAIL)
            formatter = logging.Formatter("%(name)s: %(levelname)s - %(message)s")
            log_handler.setFormatter(formatter)
        else:
            log_handler = logging.FileHandler(logfile, 'a')
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            log_handler.setFormatter(formatter)
        log.setLevel(logging.INFO)
        log.addHandler(log_handler)

    log.debug("=========== starting rolesmailer ============")
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
            agent = LdapAgent(**ldap_config)
        except:
            log.error("Cannot connect to LDAP %s", ldap_config['ldap_server'])
            return RETURN_CODES['EX_TEMPFAIL']

        expander = Expander(agent, **expander_config)
        return expander.expand(from_email, role_email, content)
    except:
        log.error("Unexpected error")
        return RETURN_CODES['EX_SOFTWARE']

if __name__ == '__main__':
    sys.exit(main())
