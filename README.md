# New Relic Ruby security agent

The New Relic security agent for Ruby is in public preview and is not generally available. This module enables instrumentation of Ruby applications for interactive application security analysis (IAST) and exposes exploitable vulnerabilities.

**Note:** The IAST capability should only be used in pre-production environments and never in production. 

[![Gem Version](https://badge.fury.io/rb/newrelic_security.svg)](https://badge.fury.io/rb/newrelic_security)

## Installation

The software is meant to be used along with the [New Relic Ruby Agent](https://github.com/newrelic/newrelic-ruby-agent). You can see New Relic ruby agent install instructions [here](https://github.com/newrelic/newrelic-ruby-agent#installing-and-using).

#### With Bundler
For using with Bundler, add the Ruby agent to your project's Gemfile.

```
gem 'newrelic_security', require: false
```

and run `bundle install` to activate the new gem.

#### Without Bundler
If you are not using Bundler, install the gem with:

```
gem install newrelic_security
```

## Getting Started
The newrelic_security must be explicitly enabled in order to perform IAST analysis of the application. In the newrelic.yml, set the following parameters:

```
 security:
   agent:
     enabled: true
   enabled: true
```

## Support Matrix
### Ruby Versions
- CRuby: 2.4 or higher
- JRuby: 9.0 or higher
### Web frameworks
- Rails: 4.0 or higher
- Sinatra: 2.0 or higher
- Padrino: 0.15 or higher
- Grape: 1.2 or higher
- Roda: 3.19 or higher
- Rack: 1.6 or higher
- gRPC: 1 or higher
### Web servers
- Puma: 3 or higher
- Unicorn: 4 or higher
- Thin: 1 or higher
- Passenger: 5 or higher
- Falcon: 0.29 or higher
- Webrick: Supported for all agent-supported versions of Ruby
### Databases
- Active Record: 4.0 or higher
- Sequel: 4.45 or higher
- MongoDB: 2.4 or higher
- Sqlite3 
- Mysql2
- PostgreSql

### HTTP / network clients
- Async::HTTP: 0.59.0 or higher
- Curb: 0.8.1 or higher
- Ethon: 0.12.0 or higher
- Excon: 0.19.0 or higher
- gRPC: 1.0.0 or higher
- HttpClient: 2.2.0 or higher
- HttpRb: 0.9.9 or higher
- HTTPX: 1.0.0 or higher
- Net::HTTP: Supported for all agent-supported versions of Ruby.
- Typhoeus: 0.5.3 or higher
- Patron: 0.10 or higher

### Other
- nokogiri
- net-ldap

### Supported Vulnerabilities
- Remote Code Execution
- SQL Injection
- NoSQL Injection
- Stored XSS
- Reflected XSS
- Reverse Shell attack
- File Access
- SSRF
- Application Integrity Violation
- LDAP Injection
- XPath Injection

## Testing
We use Minitest for the Ruby Security agent.
#### Prerequisite
```
rake test_bundle
```
#### Running All Unit tests
The following command runs all the unit tests:
```
BUNDLE_GEMFILE=Gemfile_test bundle exec rake test
```
#### Running Specific Tests
To run a single unit test file use the command like:
```
BUNDLE_GEMFILE=Gemfile_test bundle exec ruby test/newrelic_security/instrumentation-security/kernel/kernel_test.rb
```

## Feedback or Contribute

Any feedback provided to New Relic about the New Relic csec-ruby-agent, including feedback provided as source code, comments, or other copyrightable or patentable material, is provided to New Relic under the terms of the Apache Software License, version 2. If you do not provide attribution information or a copy of the license with your feedback, you waive the performance of those requirements of the Apache License with respect to New Relic. The license grant regarding any feedback is irrevocable and persists past the termination of the preview license.

Keep in mind that when you submit a pull request or other feedback, you'll need to sign the New Relic CSEC Agent CLA via the click-through using CLA-Assistant. You only have to sign this CLA one time per project.

If you have any questions, or to execute our corporate CLA (which is required if your contribution is on behalf of a company), drop us an email at opensource@newrelic.com.

**A note about vulnerabilities**

As noted in our [security policy](../../security/policy), New Relic is committed to the privacy and security of our customers and their data. We believe that providing coordinated disclosure by security researchers and engaging with the security community are important means to achieve our security goals.

If you believe you have found a security vulnerability in this project or any of New Relic's products or websites, we welcome and greatly appreciate you reporting it to New Relic through [HackerOne](https://hackerone.com/newrelic).

If you would like to contribute to this project, review [these guidelines](./CONTRIBUTING.md).

To all contributors, we thank you!  Without your contribution, this project would not be what it is today.  We also host a community project page dedicated to [Project Name](<LINK TO https://opensource.newrelic.com/projects/... PAGE>).

## License
The New Relic csec-ruby-agent is licensed under the New Relic Pre-Release Software Notice.

The New Relic csec-ruby-agent also uses source code from third-party libraries. You can find full details on which libraries are used and the terms under which they are licensed in the [third-party notices document](./THIRD_PARTY_NOTICES.md).
