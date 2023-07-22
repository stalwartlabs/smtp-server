stalwart-smtp v0.3.1
================================
- Added: Milter filter support. Documentation is available [here](https://stalw.art/docs/smtp/filter/milter).
- Added: Match IP address type using /0 mask (#16).
- Fix: Support for OpenLDAP password hashing schemes between curly brackets (#8). 
- Fix: Add CA certificates to Docker runtime (#5).

stalwart-smtp v0.3.0
================================
- Added **LDAP** support.
- Removed concept of `databases`, `lists`, `remotes` lists and replaced it with `directories`.
- Fixed error when using PKCS8 DKIM private keys.

stalwart-smtp v0.1.2
================================
- Fix: `sender-domain` key not available for evaluation.
- Bump to latest mail-auth.

stalwart-smtp v0.1.1
================================
- Fix: Only the first TLS certificate is used rather than the full chain (#3)
- Fix: Update name for `reject-non-fqdn` setting (#6).

stalwart-smtp v0.1.0
================================
- Initial release.
