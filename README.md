# Stalwart SMTP Server

[![Test](https://github.com/stalwartlabs/smtp-server/actions/workflows/test.yml/badge.svg)](https://github.com/stalwartlabs/smtp-server/actions/workflows/test.yml)
[![Build](https://github.com/stalwartlabs/smtp-server/actions/workflows/build.yml/badge.svg)](https://github.com/stalwartlabs/smtp-server/actions/workflows/build.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![](https://img.shields.io/discord/923615863037390889?label=Chat)](https://discord.gg/jtgtCNj66U)
[![](https://img.shields.io/twitter/follow/stalwartlabs?style=flat)](https://twitter.com/stalwartlabs)

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
  - Filtering, modification and removal of MIME parts or headers.
  - DNS block lists (**DNSBL**) & Greylisting.
  - Inbound concurrency & rate limiting.
  - Integration with external content filtering systems such as SpamAssassin and ClamAV.
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
  - PostgreSQL, MySQL, MSSQL and SQLite support.
  - Granular configuration rules.
  - REST API for management.
  - Memory safe (thanks to Rust).

## Get Started

Install Stalwart SMTP on your server by following the instructions for your platform:

- [Linux / MacOS](https://stalw.art/smtp/get-started/linux/)
- [Windows](https://stalw.art/smtp/get-started/windows/)
- [Docker](https://stalw.art/smtp/get-started/docker/)

You may also [compile Stalwart SMTP from the source](https://stalw.art/smtp/development/compile/).

## Support

If you are having problems running Stalwart SMTP, you found a bug or just have a question,
do not hesitate to reach us on [Github Discussions](https://github.com/stalwartlabs/smtp-server/discussions),
[Reddit](https://www.reddit.com/r/stalwartlabs) or [Discord](https://discord.gg/9dXkHzCk).
Additionally you may become a sponsor to obtain priority support from Stalwart Labs Ltd.

## Documentation

Table of Contents

- Get Started
  - [Linux / MacOS](https://stalw.art/smtp/get-started/linux/)
  - [Windows](https://stalw.art/smtp/get-started/windows/)
  - [Docker](https://stalw.art/smtp/get-started/docker/)
- Configuration
  - [Overview](https://stalw.art/smtp/settings/overview)
  - [Configuration Rules](https://stalw.art/smtp/settings/rules)
  - [General settings](https://stalw.art/smtp/settings/general)
  - [Remote hosts](https://stalw.art/smtp/settings/remote)
  - [Databases](https://stalw.art/smtp/settings/database)
  - [Local Lists](https://stalw.art/smtp/settings/list)
  - [Tracing & Logging](https://stalw.art/smtp/settings/tracing)
- Inbound settings
  - [Listeners](https://stalw.art/smtp/inbound/listeners)
  - [Sessions](https://stalw.art/smtp/inbound/session)
  - [EHLO Stage](https://stalw.art/smtp/inbound/ehlo)
  - [MAIL Stage](https://stalw.art/smtp/inbound/mail)
  - [RCPT Stage](https://stalw.art/smtp/inbound/rcpt)
  - [DATA Stage](https://stalw.art/smtp/inbound/data)
  - [AUTH Stage](https://stalw.art/smtp/inbound/auth)
  - [DNSBLs](https://stalw.art/smtp/inbound/dnsbl)
  - [Sieve Scripting](https://stalw.art/smtp/inbound/sieve)
  - [Throttling](https://stalw.art/smtp/inbound/throttle)
- Outbound settings
  - [Queues](https://stalw.art/smtp/outbound/queue)
  - [Transport & Routing](https://stalw.art/smtp/outbound/transport)
  - [TLS Security](https://stalw.art/smtp/outbound/tls)
  - [Throttling](https://stalw.art/smtp/outbound/throttle)
  - [Quotas](https://stalw.art/smtp/outbound/quota)
  - [DNS](https://stalw.art/smtp/outbound/dns)
- Email Authentication
  - [DKIM](https://stalw.art/smtp/auth/dkim)
  - [SPF](https://stalw.art/smtp/auth/spf)
  - [ARC](https://stalw.art/smtp/auth/arc)
  - [DMARC](https://stalw.art/smtp/auth/dmarc)
  - [Reverse IP](https://stalw.art/smtp/auth/iprev)
  - [Report Analysis](https://stalw.art/smtp/auth/analysis)
- Management
  - [API](https://stalw.art/smtp/management/api)
  - [CLI](https://stalw.art/smtp/management/cli)
  - [Queue](https://stalw.art/smtp/management/queue)
  - [Reports](https://stalw.art/smtp/management/reports)
- Development
  - [Compiling](https://stalw.art/smtp/development/compile/)
  - [Tests](https://stalw.art/smtp/development/test/)
  - [RFCs conformed](https://stalw.art/smtp/development/rfc/)

## Roadmap

The following major features and enhancements are planned for Stalwart SMTP:

- Embedded Antispam and Antivirus
- WASM filters
- Distributed mode
- Web-based administration

## Testing & Fuzzing

The base tests perform protocol compliance tests as well as basic functionality testing on different functions across the Stalwart SMTP code base. 
To run the base test suite execute:

```bash
cargo test
```

To run the fuzz tests please refer to the Stalwart libraries that handle parsing for the SMTP server: [smtp-proto](https://github.com/stalwartlabs/smtp-proto),
[mail-parser](https://github.com/stalwartlabs/mail-parser),
[mail-auth](https://github.com/stalwartlabs/mail-auth) and [sieve-rs](https://github.com/stalwartlabs/sieve). 

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
