eea.mailexpander sendmail configuration
=======================================

This is a guide on how to configure the sendmail server to use this mailer.

1. Copy m4 macro file
    To add this mailer in the sendmail copy the `misc/rolesmail.m4` file to a
    convenient directory for example in debian: /etc/mail/m4/rolesmail.m4 .

2. Configure the mailer
    Now open rolesmail.m4 and modify the set up EXPANDER_MAILER_PATH with the
    mailexpander script path and also modify the ldap server path under -l
    argument. However, since this program is build specifically for EIONET
    Ldap schema it will not work for any ldap server

3. Add mailer to sendmail.mc
    Open up the sendmail.mc file usually located in /etc/mail/ and add

    `before MAILER_DEFINITIONS`:

        include(\`/etc/mail/m4/rolesmail.m4')dnl

    **and**

    `after MAILER_DEFINITIONS`:

        MAILER(\`rolesmail')dnl

    Here is a full example::

        include(\`/etc/mail/m4/rolesmail.m4')dnl
        dnl # Default Mailer setup
        MAILER_DEFINITIONS
        MAILER(\`local')dnl
        MAILER(\`smtp')dnl
        MAILER(\`rolesmail')dnl

4. Add rule to mailertable
    If you want to use mailertable make sure you have FEATURE(\`mailertable')dnl
    in your sendmail.mc .

    Then add the below line to user /etc/mail/mailertable::

        roles.eionet.europa.eu   rolesmail:roles.eionet.europa.eu

    This will tell the sendmail program that all emails to
    roles.eionet.europa.eu should use our rolesmail mailer

    The semantics are simple. Any left-hand-side entry that does not
    begin with a dot matches the full host name indicated. Left-hand-side
    entries beginning with a dot match anything ending with that domain
    name (including the leading dot) -- that is, they can be thought of
    as having a leading ".+" regular expression pattern for a non-empty
    sequence of characters. Matching is done in order of most-to-least
    qualified -- for example, even though ".my.domain" is listed first
    in the above example, an entry of "host1.my.domain" will match
    the second entry since it is more explicit.

    The right-hand-side should always be a "mailer:host" pair. The mailer
    is the configuration name of a mailer (that is, an M line in the
    sendmail.cf file). The "host" will be the hostname passed to that
    mailer.

5. Reload sendmail
    After everything is setup up run::

        make
        service sendmail reload
