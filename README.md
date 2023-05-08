# New Relic Ruby security agent

The New Relic security agent for Ruby is in limited preview and is not generally available.This module enables instrumentation of Ruby applications for interactive application security analysis (IAST) and exposes exploitable vulnerabilities. 

**Note:** The IAST capability should only be used in pre-production environments and never in production. 

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
   mode: IAST
   validator_service_url: wss://csec.nr-data.net
```

## Support Matrix
### Ruby Versions
- CRuby: 2.4 & above
- JRuby: 9.2 & above
### Web frameworks
- Rails: 6 & above
- Sinatra: 3 & above
### Web servers
- Puma: 3 & above
- Unicorn: 5 & above
- Webrick: 1.6 & above
- Thin: 1.8 & above
- Passenger: 6 & above
### Databases
- Sqlite3
- Mysql2
- PostgreSql
- MongoDB

## Testing
We use Minitest for the Ruby Security agent.
#### Prerequisite
```
rake test_bundle
```
#### Running All Unit tests
The following command runs all the unit tests without Rails:
```
rake test
```
#### Running Specific Tests
To run a single unit test file use the command like:
```
ruby test/newrelic_security/instrumentation-security/kernel/kernel_test.rb
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

The New Relic csec-ruby-agent also uses source code from third-party libraries. You can find full details on which libraries are used and the terms under which they are licensed in the third-party notices document.
