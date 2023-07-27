# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [0.3.2] - 2023-07-28

### Added
- Sender and recipient address rewriting using regular expressions and sieve scripts.
- Subaddressing and catch-all addresses using regular expressions (#10).
- Dynamic variables in SMTP rules.
 
### Changed
- Added CLI to Docker container (#19).
 
### Fixed
- Workaround for a bug in `sqlx` that caused SQL time-outs (#15).
- Support for ED25519 certificates in PEM files (#20). 
- Better handling of concurrent IMAP UID map modifications (#17).
- LDAP domain lookups from SMTP rules.

## [0.3.1] - 2023-07-22

### Added
- Milter filter support.
- Match IP address type using /0 mask (#16).
 
### Changed
 
### Fixed
- Support for OpenLDAP password hashing schemes between curly brackets (#8). 
- Add CA certificates to Docker runtime (#5).

## [0.3.0] - 2023-07-16

### Added
- **LDAP** authentication.
- **subaddressing** and **catch-all** addresses.

### Changed
- Removed concept of `databases`, `lists`, `remotes` lists and replaced it with `directories`.
 
### Fixed
- Error when using PKCS8 DKIM private keys.


## [0.1.2] - 2023-03-11

### Added
- **LDAP** authentication.
- **subaddressing** and **catch-all** addresses.

### Changed
- Bump to latest mail-auth.
 
### Fixed
- Error `sender-domain` key not available for evaluation.

## [0.1.1] - 2023-03-06

### Added

### Changed
 
### Fixed
- Only the first TLS certificate is used rather than the full chain (#3)
- Update name for `reject-non-fqdn` setting (#6).

## [0.1.0] - 2023-03-01

Initial release.

