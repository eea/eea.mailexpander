eea.mailexpander
================

https://svn.eionet.europa.eu/projects/Zope/ticket/3844

This program acts as a sendmail mailer and allows sending mails to a certain
ldap group (role) based on a few rules.

The ldap role should have 2 attributes:
    permittedPerson -- DN pointing to a ldap user
    permittedSender -- Email, patterns and 2 preset strings: 'members', 'owners'
    owner -- DN pointing to a ldap user

Usage/Installation
------------------

To configure the sendmail see docs/SENDMAIL.rst
