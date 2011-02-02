PUSHDIVERT(-1)

ifdef(`EXPANDER_MAILER_PATH',, `define(`EXPANDER_MAILER_PATH', /usr/local/sbin/roleexpander)')
ifdef(`EXPANDER_MAILER_ARGS',, `define(`EXPANDER_MAILER_ARGS', `roleexpander -l ldap.eionet.europa.eu -r $u')')dnl

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
		A=EXPANDER_MAILER_ARGS
