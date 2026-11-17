# Simple Magic Login

- Contributors: akirk
- Requires PHP: 7.4
- Stable tag: 0.1.0
- License: GPLv2 or later

Minimal email-link login, inspired by Magic Login by HandyPlugins.
This is an independent reimplementation, with no dependency on Magic Login.

## Description

### Usage

Activate on each site that should use email-first login. Do not network activate
unless you want it on every site. Keep the original Magic Login plugin inactive
on those sites to avoid competing login handlers. There are no settings screens.

wp-login.php asks for an email address. Existing members of that site receive a
single-use link and six-digit code valid for 15 minutes. Open “Have a six-digit
login code?” on the login page to enter your email and code on another device.
Using either the link or the code invalidates both. Five incorrect code attempts
disable that code; the long login link still works. Requesting a new email
replaces both the old link and code. No custom tables are created.
Password or email changes invalidate outstanding links. Known and unknown emails
receive the same response text (delivery timing can differ). Requests are limited to one email per user per minute
and ten attempts per direct IP address per 15 minutes of inactivity. Both limits
are shared across all sites in the same multisite network, including when the
plugin is activated on individual sites. On a single-site install they apply
to that site.

“Log in with password” reveals the password field and changes the submit button
to “Log In”.
Password resets and other WordPress login actions continue to use WordPress.

The login page uses the actual WordPress form, adapted in the browser for email
login. Standard login form hooks and fields added by other plugins are preserved.
Without JavaScript it stays a standard password form. Password submissions and
their errors are handled entirely by WordPress. Interim login dialogs also keep
the standard password form.

Both the revealed password form and the email-link confirmation offer Remember
Me. When checked, WordPress uses a persistent login (14 days by default).
Otherwise it uses its normal session cookie (valid for up to two days by default).
The 15-minute link expiry only controls redemption, not the resulting session.

Emails use wp_mail() and the site's existing mail delivery setup. Opening a link
shows the account email and a confirmation button. Only submitting that form
consumes the link, so ordinary email link scanners do not sign in or use it up.

WordPress wp_authenticate_user restrictions are checked before sending and
redeeming a link. Users with the Two Factor plugin enabled must use password
login. They receive an explanatory email with a password login link instead of
a login token or code, subject to the same email and IP throttling. Delivery logs
identify these messages with mail_type two_factor_notice.
Other MFA/SSO plugins that depend on the authenticate filter or native
login form need separate integration; their challenges are not run by this flow.
Use the simple_magic_login_allowed filter to exclude affected accounts.
Request throttling uses network transients and is best effort under concurrent
requests. Login links and codes remain bound to the site that issued them.

Site-bound links limit where a link is redeemed, not the scope of WordPress's
normal login session. A successful login uses the network's standard cookies and
the account's existing permissions elsewhere in the network.

Activation example:

```sh
wp --url=alex.kirk.at plugin activate simple-magic-login
```

### Troubleshooting email

Diagnostics are written to PHP's configured error log with the prefix
[simple-magic-login]. When WordPress debug logging is configured, this normally
means WP_DEBUG_LOG; otherwise check the PHP/web server error log.
Entries include the site ID, user ID where applicable, and the outcome:
request_blocked (with reason), request_throttled_ip, request_throttled_user,
request_invalid_nonce, request_invalid_email, mail_transport_error, mail_failed,
or mail_accepted. Transport errors include a redacted error message, never the
mail body. Login links, codes, email addresses, and raw IP addresses are not logged.
mail_accepted means wp_mail returned success, not that the email reached an inbox.
