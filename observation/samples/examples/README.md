# Example Event Logs

This directory contains sanitized representative examples produced by the
observation pipeline.

The examples are derived from real pipeline output but contain no private
runtime telemetry.


## Sanitization

The examples replace machine-specific values with deterministic placeholders,
including:

- hostnames
- usernames
- filesystem paths
- PIDs
- execution IDs
- socket cookies

The event structure, field names, event types, policy names, and representative
values are preserved so that the examples remain useful for documentation and
development.

## Runtime data

Actual runtime telemetry is stored separately under:

`observation/samples/`

The runtime directories are not intended to be committed to the repository.