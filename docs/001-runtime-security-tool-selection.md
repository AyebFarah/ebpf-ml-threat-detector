# Why Tetragon Was Selected

## Decision

Tetragon was selected because it better matches the objectives and technical requirements of this project.

It provides:

- Correlated kernel events containing process, file, system call, and network context.
- A consistent JSON format that simplifies data collection and processing.
- Rich contextual information that reduces the preprocessing required before machine-learning tasks.
- Custom monitoring through YAML-based `TracingPolicy` resources, without requiring the development of new eBPF programs.
- Continuous runtime monitoring capabilities rather than focusing primarily on debugging and troubleshooting.
- Natural integration with a telemetry pipeline for feature extraction and real-time threat detection.

## Comparison

| Criterion | Tetragon | Inspektor Gadget | Reason for Choosing Tetragon |
|---|---|---|---|
| Purpose | Runtime security monitoring and behavioral observation | Collection of tracing and debugging data | Better suited for continuous security monitoring |
| Event correlation | Automatically correlates processes, system calls, file accesses, and network events | Events from different gadgets may need to be correlated manually | Provides more complete behavioral information |
| Feature extraction | Includes rich contextual information in each event | Events from multiple gadgets must be combined | Simplifies feature extraction for machine learning |
| Output format | Provides a consistent JSON format for events | The output may vary depending on the gadget | Makes data collection and processing easier |
| Custom monitoring | New monitoring rules can be defined using YAML-based `TracingPolicy` resources | New functionality may require developing a custom gadget in Go | Faster and simpler to customize |
| Scalability | Designed for continuous monitoring in production environments | Mainly intended for debugging, troubleshooting, and system inspection | Better suited for long-running telemetry collection |
| Kubernetes integration | Provides Kubernetes resources such as `TracingPolicy` and can be deployed using a `DaemonSet` | Supports Kubernetes, primarily for diagnostic purposes | More appropriate for future distributed deployments |
| Machine-learning integration | Events are already structured and correlated | Additional preprocessing is required to merge events | Reduces data preparation before training machine-learning models |

## Example Scenario

Consider the following scenario:

> A malicious process opens a sensitive file and then connects to a remote server.

### Tetragon

Tetragon can provide event information containing:

- Process name, such as `python3`
- Parent process
- File access information
- The `connect()` system call
- Destination IP address and port

The event contains correlated behavioral information that can be transformed directly into machine-learning features with limited preprocessing.

### Inspektor Gadget

With Inspektor Gadget, the information may be collected separately by different gadgets:

| Gadget | Information Collected |
|---|---|
| `trace_open` | File access |
| `trace_tcp` | Network connection |
| `trace_exec` | Process execution |

These events must then be correlated manually using identifiers such as the process ID (`PID`) and timestamps before they can be consumed by the machine-learning pipeline.

## Conclusion

Tetragon was selected because it provides richer event context, built-in event correlation, consistent output, flexible policy-based monitoring, and better support for continuous runtime security monitoring.

These characteristics reduce the complexity of the telemetry pipeline and minimize the preprocessing required for machine-learning-based threat detection.
