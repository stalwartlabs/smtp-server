# Stalwart SMTP Server

[![Build](https://github.com/stalwartlabs/smtp-server/actions/workflows/build.yml/badge.svg)](https://github.com/stalwartlabs/smtp-server/actions/workflows/build.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![](https://img.shields.io/discord/923615863037390889?label=Chat)](https://discord.gg/jtgtCNj66U)
[![](https://img.shields.io/twitter/follow/stalwartlabs)](https://twitter.com/stalwartlabs)
[![](https://img.shields.io/mastodon/follow/109929667531941122)](https://mastodon.social/@stalwartlabs)

**Stalwart SMTP** is a modern SMTP server developed in Rust with a focus on security, speed, and extensive configurability. 
It features built-in DMARC, DKIM, SPF and ARC support for message authentication, strong transport security through DANE, MTA-STS and SMTP TLS reporting, and offers great flexibility and customization thanks to its dynamic configuration rules and native support for Sieve scripts.

Key features:

- Sender and Message Authentication:
  - Domain-based Message Authentication, Reporting, and Conformance (**DMARC**) verification and failure/aggregate reporting.
  - DomainKeys Identified Mail (**DKIM**) verification, signing and failure reporting.
  - Sender Policy Framework (**SPF**) policy evaluation and failure reporting.
  - Authenticated Received Chain (**ARC**) verification and sealing.
  - Reverse IP (**iprev**) validation.
- Strong Transport Security:
  - DNS-Based Authentication of Named Entities (**DANE**) Transport Layer Security.
  - SMTP MTA Strict Transport Security (**MTA-STS**).
  - SMTP TLS Reporting (**TLSRPT**) delivery and analysis.
- Inbound Filtering and Throttling:
  - Sieve scripting language with support for all [registered extensions](https://www.iana.org/assignments/sieve-extensions/sieve-extensions.xhtml).
  - **Milter** support for integration with external content filtering systems such as SpamAssassin and ClamAV.
  - Address rewriting.
  - Filtering, modification and removal of message parts or headers.
  - DNS block lists (**DNSBL**) & Greylisting.
  - Inbound concurrency & rate limiting.
- Flexible Queues:
  - Unlimited virtual queues with custom routing rules.
  - Delayed delivery with `FUTURERELEASE` and `DELIVERBY` extensions support.
  - Priority delivery with `MT-PRIORITY` extension support.
  - Outbound throttling & Disk quotas.
- Logging and Reporting:
  - Detailed logging of SMTP transactions and events, including delivery attempts, errors, and policy violations.
  - Integration with **OpenTelemetry** to enable monitoring, tracing, and performance analysis of SMTP server operations.
  - Automatic analysis of incoming DMARC/TLS aggregate reports, DMARC/DKIM/SPF authentication failure reports as well as abuse reports.
- And more:
  - SASL authentication.
  - LDAP, PostgreSQL, MySQL, MSSQL and SQLite support.
  - Email aliases, mailing lists, subaddressing and catch-all addresses support.
  - Granular configuration rules.
  - REST API for management.
  - Memory safe (thanks to Rust).

## Get Started

Install Stalwart SMTP Server on your server by following the instructions for your platform:

- [Linux / MacOS](https://stalw.art/docs/install/linux)
- [Windows](https://stalw.art/docs/install/windows)
- [Docker](https://stalw.art/docs/install/docker)

All documentation is available at [stalw.art/docs/get-started](https://stalw.art/docs/get-started).

> **Note**
> If you need a more comprehensive solution that includes IMAP and JMAP servers, you should consider installing the [Stalwart Mail Server](https://github.com/stalwartlabs/mail-server) instead.

## Support

If you are having problems running Stalwart SMTP, you found a bug or just have a question,
do not hesitate to reach us on [Github Discussions](https://github.com/stalwartlabs/smtp-server/discussions),
[Reddit](https://www.reddit.com/r/stalwartlabs) or [Discord](https://discord.gg/gNCVEEkWyX).
Additionally you may become a sponsor to obtain priority support from Stalwart Labs Ltd.

## Funding

Part of the development of this project was funded through the [NGI0 Entrust Fund](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu/) programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 101069594.

If you find the project useful you can help by [becoming a sponsor](https://github.com/sponsors/stalwartlabs). Thank you!

## License

Licensed under the terms of the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html) as published by
the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
See [LICENSE](LICENSE) for more details.

You can be released from the requirements of the AGPLv3 license by purchasing
a commercial license. Please contact licensing@stalw.art for more details.
  
## Copyright

Copyright (C) 2020-2023, Stalwart Labs Ltd.
