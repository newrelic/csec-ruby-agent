# New Relic Ruby Security Agent Release Notes

## v0.4.0

Version 0.4.0 introuduces Rack framework support, GraphQL support & CI/CD integration as part of security. Updated json_version: **1.2.9**

- Feature: Rack framework support [PR#149](https://github.com/newrelic/csec-ruby-agent/pull/149)

- Feature: GraphQL support [PR#133](https://github.com/newrelic/csec-ruby-agent/pull/133)

- Feature: CI/CD integration support [PR#146](https://github.com/newrelic/csec-ruby-agent/pull/146)

- Bugfix: Fix for Agent is sending 404 http error in runtime error json [PR#147](https://github.com/newrelic/csec-ruby-agent/pull/147)

- Bugfix: Fix for Exception occurred in generating unhandled exception in Sinatra jruby app [PR#150](https://github.com/newrelic/csec-ruby-agent/pull/150)

- Bugfix: Fix for Do not send empty url endpoint json & Reconnect in random interval between 5-15 secs [PR#151](https://github.com/newrelic/csec-ruby-agent/pull/151)

- Bugfix: Fix for Wrong formated critical error message [PR#148](https://github.com/newrelic/csec-ruby-agent/pull/148)

- BugFix: Fix for Vulnerability is missed in text/json because of small stackTrace [PR#155](https://github.com/newrelic/csec-ruby-agent/pull/155)

- BugFix: Fix for API endpoints not detected in grape framework in JRuby environment [PR#158](https://github.com/newrelic/csec-ruby-agent/pull/158)

- BugFix: Fix for XML content type vulnerability not detected [PR#159](https://github.com/newrelic/csec-ruby-agent/pull/159)

- BugFix: Fix for Concurrency issue observed in JRuby environment, BufferOverflowException observed in writing events to websocket [PR#161](https://github.com/newrelic/csec-ruby-agent/pull/161)

- Memory usage optimisations [PR#153](https://github.com/newrelic/csec-ruby-agent/pull/153)

## v0.3.0

Version 0.3.0 introduces more control on IAST scanning through new configs(exclude_from_iast_scan, scan_schedule & scan_controllers) and 
features like API inventory for gRPC server and IAST scan start related timestamps.

Updated json_version: **1.2.8**

- Feature: IAST scan exclusion for apis, http request parameters(header, query & body) & IAST detection categories and scan scheduling through delay, duration & cron schedule. [PR#131](https://github.com/newrelic/csec-ruby-agent/pull/131)

- Feature: IAST scan request rate limit to control IAST scan request firing. [PR#132](https://github.com/newrelic/csec-ruby-agent/pull/132)

- Feature: API endpoints support for gRPC server applications. [PR#143](https://github.com/newrelic/csec-ruby-agent/pull/143)

- Feature: Reporting of IAST scanning application procStartTime, trafficStartedTime & scanStartTime. [PR#136](https://github.com/newrelic/csec-ruby-agent/pull/136)

- Misc Chore: Optimised SSRF events parameters to send only URL in parameters. [PR#129](https://github.com/newrelic/csec-ruby-agent/pull/129)

##### New security configs

```yaml
security:
  exclude_from_iast_scan:
    api: []
    http_request_parameters:
      header: []
      query: []
      body: []
    iast_detection_category:
      insecure_settings: false
      invalid_file_access: false
      sql_injection: false
      nosql_injection: false
      ldap_injection: false
      javascript_injection: false
      command_injection: false
      xpath_injection: false
      ssrf: false
      rxss: false
  scan_schedule:
    delay: 0
    duration: 0
    schedule: ""
    always_sample_traces: false
  scan_controllers:
    iast_scan_request_rate_limit: 3600
```

##### Deprecated security configs (will be removed in next major release v1.0.0)
```yaml
security:
  request:
    body_limit: 300
  detection:
    rci:
      enabled: true
    rxss:
      enabled: true
    deserialization:
      enabled: true
```

## v0.2.0

Version 0.2.0 introuduces Error reporting as part of security. Any unhandled or 5xx errors in application runtime will now be visible in IAST capability UI. Updated json_version: **1.2.4**

- Feature: Unhandled and 5xx error reporting [PR#134](https://github.com/newrelic/csec-ruby-agent/pull/134)

- Bugfix: Fix for API route not present in rails7 [PR#127](https://github.com/newrelic/csec-ruby-agent/pull/127)

- Bugfix: Fix for Sqlite3 parameters sent in wrong fromat [PR#130](https://github.com/newrelic/csec-ruby-agent/pull/130)

- Bugfix: Fix for multiple events have same id [PR#135](https://github.com/newrelic/csec-ruby-agent/pull/135)

- Bugfix: Fix for NR_CSEC_VALIDATOR_HOME_TMP placeholder value not replaced during File Access fuzzing [PR#138](https://github.com/newrelic/csec-ruby-agent/pull/138)

- Bugfix: Fix for appServerInfo fields are not present in File Operation events [PR#139](https://github.com/newrelic/csec-ruby-agent/pull/139)

- Sending security agent critical errors to APM error inbox [PR#137](https://github.com/newrelic/csec-ruby-agent/pull/137)

- Added key identifiers in entityGuid and acccountId in all json reporting [PR#101](https://github.com/newrelic/csec-ruby-agent/pull/101)


## v0.1.0

Version 0.1.0 introduces `newrelic_security` agent for public preview under Newrelic pre-release software notice.

- json_version: 1.2.0

[New Relic Interactive Application Security Testing (IAST)](https://docs.newrelic.com/docs/iast/introduction/) can help you prevent cyberattacks and breaches on your applications by probing your running code for exploitable vulnerabilities.

The `newrelic_security` gem provides this feature for Ruby. It depends on `newrelic_rpm` gem version v9.12.0 or above.

At this time, the security agent is intended for use only within a dedicated security testing environment(or pre production) with data that can tolerate modification or deletion. The security agent is available as a separate Ruby gem, `newrelic_security`. It is recommended that this separate gem only be introduced to a security testing environment by leveraging Bundler grouping like so:

```ruby
  # Gemfile
  gem 'newrelic_rpm'               # New Relic APM observability agent

  group :security do
    gem 'newrelic_security', require: false        # New Relic security agent
  end
```

In order to run the security agent, make sure `newrelic_security` is not loaded by bundler but `newrelic_rpm` only by adding `require: false` in Gemfile. To run the security agent by newrelic_rpm, you need to update your configuration in newrelic.yml. At a minimum, `security.agent.enabled` and `security.enabled` must be set to `true`. They are `false` by default. Similar to the gem installation, we recommend you set these configurations for a special security testing environment only.

Here's an example using `newrelic.yml`:

```yaml
  common: &default_settings
    license_key: <%= ENV['NEW_RELIC_LICENSE_KEY'] %>
    app_name: "Example app"

  development:
    <<: *default_settings
    app_name: <%= app_name %> (Development)

  security:
    <<: *default_settings
    security.enabled: true
    security.agent.enabled: true

  production:
    <<: *default_settings
```

The following configuration relate to the `newrelic_security` gem:

| Configuration name | Default | Behavior |
| ------------------ | ------- |----------|
| security.agent.enabled | `false` | If `true`, the security agent is loaded (a Ruby 'require' is performed) |
| security.enabled | `false` |  If `true`, the security agent is started (the agent runs in its event loop) |
| security.mode | `'IAST'` | Defines the mode for the security agent to operate in. Currently only 'IAST' is supported |
| security.validator_service_url | `'wss://csec.nr-data.net'` | Defines the endpoint URL for posting security related data |
| security.detection.rci.enabled | `true` | If `true`, enables RCI (remote code injection) detection |
| security.detection.rxss.enabled | `true` | If `true`, enables RXSS (reflected cross-site scripting) detection |
| security.detection.deserialization.enabled | `true` |  If `true`, enables deserialization detection |
| security.application_info.port | `nil` | An Integer representing the port the application is listening on. This setting is mandatory for Passenger servers. Other servers should be detected by default. |

## v0.0.3

This is pre released test version.

## v0.0.2

This is pre released test version.

## v0.0.1

This is pre released test version.
