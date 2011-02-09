PUSHDIVERT(-1)

ifdef(`EXPANDER_MAILER_PATH',, `define(`EXPANDER_MAILER_PATH', /usr/local/sbin/roleexpander)')
ifdef(`EXPANDER_MAILER_ARGS',, `define(`EXPANDER_MAILER_ARGS', `roleexpander -c /etc/mail/roleexpander.ini -r $u')')dnl
#ifdef(`EXPANDER_MAILER_ARGS',, `define(`EXPANDER_MAILER_ARGS', `roleexpander -l ldap.eionet.europa.eu -o syslog -r $u')')dnl


POPDIVERT

#################################
###   EEA Roles Mail expander ###
#################################

VERSIONID(`$Id$')
Mrolesmail, P=EXPANDER_MAILER_PATH,
		F=DFMuX,
		F=f,
		S=EnvFromSMTP/HdrFromSMTP,
		R=EnvToSMTP/HdrFromSMTP,
		T=DNS/RFC822/SMTP,
		U=roleslog,
		A=EXPANDER_MAILER_ARGS
