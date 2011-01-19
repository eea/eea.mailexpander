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

    Then add the bellow line to user /etc/mail/mailertable::

        roles.eionet.europa.eu   rolesmail:eea.eionet.europa.eu

    This will tell the sendmail program that all emails to roles.eionet.europa.eu
    should use our rolesmail mailer

5. Reload sendmail
    After everything is setup up run::

        make
        service sendmail reload
