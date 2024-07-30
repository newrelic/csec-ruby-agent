# New Relic Ruby Security Agent Release Notes

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
