<h1 align="center">isobox</h1>

<p align="center">
  <strong>Run a command in a sandbox, with the same flags on every OS.</strong>
</p>

<p align="center">
  <a href="https://github.com/can1357/isobox/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/can1357/isobox/ci.yml?branch=main&style=flat&colorA=222222&colorB=3FB950" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/can1357/isobox"><img src="https://img.shields.io/badge/pkg.go.dev-reference-00ADD8?style=flat&colorA=222222&logo=go&logoColor=white" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/can1357/isobox"><img src="https://img.shields.io/badge/go%20report-A%2B-3FB950?style=flat&colorA=222222" alt="Go Report Card"></a>
  <a href="https://github.com/can1357/isobox/blob/main/LICENSE"><img src="https://img.shields.io/github/license/can1357/isobox?style=flat&colorA=222222&colorB=58A6FF" alt="License"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&colorA=222222&logo=go&logoColor=white" alt="Go"></a>
</p>

<p align="center">
  Simple universal sandboxing with preload capabilities.<br>
  One policy compiles to Seatbelt, gVisor, or AppContainer, and your command's exit code passes straight through.
</p>

---

```sh
isobox -- echo hi
```

| OS      | Backend                  | Mechanism            |
| ------- | ------------------------ | -------------------- |
| macOS   | Seatbelt                 | `sandbox-exec`       |
| Linux   | gVisor                   | `runsc`              |
| Windows | AppContainer             | in-process Win32     |

By default the CLI chooses the native backend, then optional Docker backends if
they can satisfy requested capabilities the native backend cannot. Override with
`--backend`.

## The problem it solves

Every OS sandbox has its own vocabulary and its own gaps. A profile that denies
network on macOS does not transfer to Linux, and the two do not even agree on what
"deny network" includes. isobox papers over this with an explicit **capability
model** instead of a lowest-common-denominator illusion:

- Each backend declares the set of capabilities it can actually enforce.
- Build your policy from the **intersection of per-OS backend unions**:
  `(macOS native+compatible) ∩ (Linux native+compatible) ∩ (Windows native+compatible)`.
- Reach for one backend's **union** extras and isobox still runs, but attaches a
  queryable **caveat** wherever enforcement falls short of the stated intent.
- `--strict` refuses anything outside that portable per-OS intersection, so you
  fail loudly instead of silently degrading.

Because the capability tables are plain data, you can inspect or preview any
backend's plan from any host. Running it still needs that backend's tool installed.

## Install

Install Go 1.26+ and `just`, then:

```sh
just build
just test
```

Without `just`:

```sh
go build -o isobox ./cmd/isobox
go test ./...
```

On Linux, the optional LD_PRELOAD filesystem fallback is C:

```sh
just isoboxfs-build
just isoboxfs-test
```

This builds `preload/isoboxfs/libisoboxfs.so` from the C sources under
`preload/isoboxfs`.

GitHub Actions runs `just build` and `just test` on Ubuntu, macOS, and Windows,
plus the C preload build and test on Ubuntu.

## Quick start

```sh
isobox -- echo hi                              # agent defaults (see Profiles)
isobox --profile=tight -- echo hi              # locked down: no net, read-only, no writes
isobox --net=enable -- curl https://example.com
isobox --writable ./work -- just build         # persist ./work plus the default cwd
isobox --write=ephemeral -- ./build.sh         # writes happen, then vanish
isobox --cpus 1.5 --memory 512m -- ./build.sh  # cap CPU and memory
isobox --readable . --cpus 1 --memory 512m -- ./build.sh  # macOS can auto-pick Docker/runsc if configured
isobox --print --backend gvisor -- ls /        # preview the Linux plan from any OS
isobox --caps                                  # print the capability matrix
```

Everything after `--` is the command and its arguments.

## Profiles

A profile sets the defaults; explicit flags always override it.

- **`agent`** (default): outbound-only network, the command working directory and OS
  temp writable, broad host reads with common credential paths denied, and writes
  elsewhere kept off the host. On gVisor this is a memory-backed root overlay plus
  persistent writable binds. Seatbelt and AppContainer cannot redirect outside
  writes, so they deny them and report the caveat in the plan.
- **`tight`**: no external network, broad reads, no writes anywhere.

## Capabilities

`isobox --caps` prints the live matrix (`yes` = enforced, `-` = unsupported):

```
CAPABILITY          WINDOWS  DOCKER-EPHEMERAL  DOCKER-RUNSC-EPHEMERAL  GVISOR  SEATBELT  PORTABLE  DESCRIPTION
fs.read.deny        -        -                 -                       yes     yes       -         read broadly except denied sensitive paths
fs.read.host        -        -                 -                       yes     yes       -         read the host filesystem broadly
fs.read.scope       yes      yes               yes                     yes     yes       yes       restrict host/user filesystem reads to an allowlist plus backend runtime paths
fs.write.deny       yes      yes               yes                     yes     yes       yes       deny all writes to the host filesystem
fs.write.ephemeral  yes      yes               yes                     yes     yes       yes       permit backend ephemeral writes; configured host inputs stay untouched
fs.write.scope      yes      yes               yes                     yes     yes       yes       permit writes under listed paths plus opt-in temp roots; listed-path writes persist
ipc.restrict        yes      yes               yes                     yes     -         yes       no host local IPC endpoint reachable
kernel.isolation    -        -                 yes                     yes     -         -         serve syscalls from a user-space kernel; shield host kernel
mach.restrict       -        -                 -                       -       yes       -         restrict Mach service lookups (Seatbelt-only)
net.disable         yes      yes               yes                     yes     yes       yes       deny network access; some backends additionally block loopback (see caveats)
net.enable          yes      yes               yes                     yes     yes       yes       permit network access
net.outbound        yes      yes               yes                     yes     yes       yes       permit outbound connections; block inbound TCP listeners
proc.no_exec        yes      -                 -                       yes     -         -         forbid executing another program image
res.cpu             yes      yes               yes                     yes     -         yes       limit CPU usage to a fraction of the host's cores
res.memory          yes      yes               yes                     yes     -         yes       limit the sandbox's memory footprint
```

`PORTABLE` marks the intersection of per-OS compatibility unions, not the
intersection of every named backend. For example, macOS can satisfy resource caps
through Docker/runsc even though Seatbelt itself cannot. Always inspect plan
caveats; backend runtime paths, temp roots, loopback behavior, and platform
ambient grants can still differ.

## Inspecting a plan

`--print` compiles a spec to a backend's plan and shows it without running. It works
for any backend on any host, so you can review the exact Linux invocation from a Mac:

```
$ isobox --print --backend gvisor -- just build
backend:  gvisor
enforces: fs.read.deny, fs.read.host, fs.write.ephemeral, fs.write.scope, kernel.isolation, net.outbound
filesystem: linux-namespace-view
caveats:
  - host filesystem scopes can expose host IPC endpoints
  - gvisor overlay flag syntax varies by runsc version (used --overlay2=root:memory)
  ...
argv:
  runsc --overlay2=root:memory --oci-seccomp run --bundle <bundle> isobox-gvisor-...
```

For Seatbelt the plan also includes the generated SBPL profile; for AppContainer it
includes the resolved grants.

## CLI reference

| Flag                                      | Default        | Meaning                                                                                                  |
| ----------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------- |
| `--profile=agent\|tight`                  | `agent`        | Apply defaults. `tight` restores the no-network/no-write posture.                                        |
| `--net=disable\|enable\|outbound`         | profile        | Network policy. `outbound` allows clients but blocks listen/inbound.                                     |
| `--write=none\|scope\|ephemeral\|overlay` | profile        | Deny writes, persist only `--writable`, discard all writes, or persist writable paths with shadow/deny elsewhere. |
| `--writable PATH`                         | cwd in profile | Repeatable. Writable path; adds to the agent cwd grant, or implies `--write=scope` under `tight`.        |
| `--readable PATH`                         | –              | Repeatable. Restrict reads to these paths where the backend supports it.                                 |
| `--read-deny PATH`                        | credentials    | Repeatable. Deny reads to sensitive paths while broad/scoped reads remain.                               |
| `--no-exec`                               | `false`        | Forbid exec of a new program image after launch (fork/clone still allowed).                              |
| `--allow-temp`                            | profile        | Also allow writes to the OS temp dir. Requires `--write=scope` or `--write=overlay`.                     |
| `--cpus N`                                | –              | Limit CPU usage to N logical cores (fractional allowed, e.g. `1.5`). May auto-select Docker/runsc on macOS when the rest of the spec fits. |
| `--memory SIZE`                           | –              | Limit memory (`512m`, `2g`, or raw bytes). May auto-select Docker/runsc on macOS when the rest of the spec fits.                          |
| `--mach-allow NAME`                       | –              | Repeatable. Allow a Mach service global-name (Seatbelt only).                                            |
| `--strict`                                | `false`        | Reject capabilities outside the per-OS portable intersection.                                             |
| `--dir PATH`                              | –              | Working directory for the command; also becomes the default agent writable path.                        |
| `--backend BACKEND`                       | `auto`         | Auto-select or force a backend (`seatbelt`, `gvisor`, `appcontainer`, `docker-ephemeral`, `docker-runsc-ephemeral`).                     |
| `--print`                                 | `false`        | Compile and print the plan without running.                                                              |
| `--caps`                                  | `false`        | Print the capability matrix and exit.                                                                    |
| `--version`                               | `false`        | Print version and build information and exit.                                                            |

Backend tools and Docker workarounds are configurable through
`ISOBOX_SANDBOX_EXEC`, `ISOBOX_RUNSC`, `ISOBOX_DOCKER`, `ISOBOX_DOCKER_IMAGE`,
`ISOBOX_DOCKER_RUNTIME`, and `ISOBOX_DOCKER_RUNSC_RUNTIME`.

## Library

```go
spec := isobox.Spec{
	Args:        []string{"just", "build"},
	Net:         isobox.NetDisable,
	Write:       isobox.WriteScope,
	Writable:    []string{"out"},
	CPUs:        1.5,        // cap at 1.5 cores where the backend supports it
	MemoryBytes: 512 << 20,  // cap at 512 MiB; 0 means unlimited
}

r, err := isobox.NewForSpec(spec) // native first, optional Docker backends if needed
if err != nil {
	panic(err)
}

plan, _ := r.Compile(spec) // inspect plan.Caveats without running
code, err := r.Run(context.Background(), spec, isobox.Stdio{})
if err != nil {
	panic(err) // failed to launch the sandbox
}
os.Exit(code) // the command's own exit code
```

The capability tables are plain data, so any backend is inspectable from any host:

```go
isobox.Union()                       // every capability any backend supports
isobox.Intersection()                // capabilities common to all backends
isobox.CapsOf(isobox.BackendGvisor)  // one backend's set
isobox.BackendForSpec(spec)          // auto-selection result on this host
isobox.NewBackend(b)                 // a runner for a named backend, on any OS
```

## Companion tools

- `cmd/isobox-sshd` starts an SSH server _inside_ an isobox so you can shell in and
  poke at the confinement interactively, the way a remote user would.
- `cmd/isobox-testkit-host` and `cmd/isobox-testkit-client` form an end-to-end test
  harness that launches a probe inside a sandbox and reports, per capability,
  whether enforcement actually held.

## Notes and caveats

- `--write=overlay` is exact on gVisor: `--overlay2=root:memory` makes writes
  outside persisted binds ephemeral while `--writable` paths still hit the host.
  Seatbelt and AppContainer cannot redirect filesystem writes, so they degrade
  outside-overlay writes to denial with a plan caveat.
- gVisor `--read-deny` obscures existing denied paths with empty bind mounts.
  Docker and AppContainer also apply caveated read-deny masks/temporary DENY
  ACEs where they can, but they still do not advertise `fs.read.deny` because
  they lack broad host-read support. Nonexistent denied paths cannot always be
  pre-mounted or ACL-stamped without touching the host.
- macOS `--write=ephemeral` clones the workspace with APFS `clonefile(2)`; it
  protects that workspace, not all of `/`.
- Windows `--write=ephemeral` recursively copies the workspace to a temporary
  AppContainer-writable directory and deletes it on exit; it is workspace-scoped
  and a full byte copy.
- Scoped-write rules are path/mount/ACL based. Hardlinks or nested mountpoints
  under writable paths can still affect the same host objects through aliases
  outside the lexical scope; plan caveats call this out.
- `--cpus`/`--memory` cap resources on every backend that has a real mechanism:
  gVisor maps them onto the sandbox's host cgroup via the OCI bundle (`runsc` needs
  cgroup support to enforce), Docker backends pass `--cpus`, `--memory`, and
  `--memory-swap` to `docker run`, and AppContainer assigns the process to a
  Windows job object (whole-job memory cap plus a CPU hard cap scheduled as a
  share of all host cores). Seatbelt has no kernel resource-limit primitive, so
  isobox applies caveated best-effort process-group CPU/memory watchdogs but does
  not advertise `res.cpu` or `res.memory`.
- `--net=outbound` is TCP-server oriented. Docker and gVisor deny
  `listen`/`accept`/`accept4`; UDP bind behavior is backend-specific and called
  out in plan caveats.
- On macOS, `docker-ephemeral` is an optional workaround for disposable Linux-image
  runs. Set `ISOBOX_DOCKER_IMAGE`; it isolates at the VM level unless Docker is
  configured with a `runsc` runtime.
- Use `--backend docker-runsc-ephemeral` to require Docker's `runsc` runtime and
  get `kernel.isolation`; plain `docker-ephemeral` never advertises it even if
  `ISOBOX_DOCKER_RUNTIME=runsc` is set.
  Docker image tags are inspected and then rewritten to immutable image IDs before
  launch, so VOLUME policy checks and execution target the same image object.
- Seatbelt is covered end-to-end by the test suite where `sandbox-exec` exists.
  gVisor, AppContainer, and Docker are covered by compiler unit tests; verify
  runtime enforcement on a real Linux/Windows host before relying on them.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Can Bölük.
