0.9 (2014-09-23)
======================
* Bug fix: fix mail expansion when mail info for owner, from LDAP search returns list
  [tiberich #20422]

0.8 (2014-09-23)
======================
* Feature: added the -t switch to test if an expansion will go or not.
  [tiberich #20422]

0.7 (2014-09-23)
======================
* Bug fix: added _role_info method to ldap agent
  [tiberich #20422]

0.6 (2014-08-13)
======================
* Change: inherit permitted senders from parent roles
  [tiberich #20422]

0.5 (2014-01-23)
======================
* Bug fix: parse the email address into components, to retrieve the real address of the sender,
  in case that sender's ISP decorates the address with additional info
  [tiberich #18055]

0.4 (unreleased)
======================
* #4543 feature: send back a confirmation email to sender [bogdatan, simiamih]
