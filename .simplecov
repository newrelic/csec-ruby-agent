# frozen_string_literal: true

SimpleCov.start do
  enable_coverage(:branch)
  add_filter('/test/')
end

# This prevents coverage from dropping below the baseline amount
Simplecov.minimum_coverage(line: 52, branch: 17)

# TODO: Enable this when codebase is at 70% test coverage
# SimpleCov.minimum_coverage(line: 70, branch: 70)
