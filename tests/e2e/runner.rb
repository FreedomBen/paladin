#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Pure-Ruby runner for the symcrypt CLI end-to-end suite. We avoid Rake because
# this environment ships no `rake` gem; this loads every cases/**/*_test.rb and
# lets minitest run them. Any arguments are passed through to minitest:
#
#   ruby runner.rb                 # run all cases
#   ruby runner.rb -n /round_trip/ # filter by name
#   ruby runner.rb --seed 1234     # fix the randomization seed
#
# Normally invoked through run.sh, which builds the binary first.

$LOAD_PATH.unshift(__dir__)
require "test_helper"

unless File.executable?(Symcrypt.binary)
  warn "symcrypt binary not found at #{Symcrypt.binary}"
  warn "build it first:  cargo build -p symcrypt-cli   (or set SYMCRYPT_BIN)"
  exit 1
end

cases = Dir.glob(File.join(__dir__, "cases", "**", "*_test.rb")).sort
warn "symcrypt E2E: binary=#{Symcrypt.binary}  cases=#{cases.size}"
cases.each { |file| require file }

# minitest/autorun (pulled in via test_helper) runs the loaded cases at exit.
