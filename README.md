# Kasumi

Kasumi is an out-of-tree Linux kernel module (`kasumi_lkm.ko`) for Android GKI/Linux path control in root/SU environments.

It provides path redirection, hiding, directory merge/injection, and scoped proc/mount presentation through a root-only anonymous-fd + `ioctl` control plane. Kasumi was previously developed as HymoFS; Kasumi/KSM is the current project and ABI name.

中文版本：[README.zh-CN.md](./README.zh-CN.md)

## Status

- Repository type: LKM, not an in-tree kernel patch set
- Implementation: `src/`
- Userspace ABI: `src/include/kasumi_uapi.h`
- Protocol: `KSM_PROTOCOL_VERSION = 19`

Userspace and kernel must both use API 19. Older and newer protocols are unsupported; there is no downgrade path. All ioctls retain the fixed `'S'` magic. Clients check `KSM_IOC_GET_VERSION` before issuing operations and stop on a protocol mismatch.
- Path view: VFS lookup/vnode based; there is no syscall-table dispatcher or `sys_enter` redirect engine
- Control entry: root-only `reboot` GET_FD command, followed by fd-based ioctls

## API 19 transactions

API 19 publishes path rules, settings, standalone policy, maps rules and kstat rules under one generation. A fresh control file owns each transaction. Keep that file open through staging, commit and recovery.

1. Query `KSM_IOC_GET_CAPABILITIES` and the optional feature mask.
2. Call `KSM_IOC_BEGIN_TRANSACTION` with the expected generation. Zero captures the current generation. A generation change makes commit return `EAGAIN`. Abort the staged transaction, or close its file and open a fresh control file, before beginning again and restaging.
3. Stage path operations with `KSM_IOC_STAGE_TRANSACTION` and configuration with `KSM_IOC_STAGE_CONFIGURATION`. Each successful configuration stage replaces the previously staged configuration as a whole.
4. Commit with `KSM_IOC_COMMIT_TRANSACTION`. Inspect `state`, `error`, `generation` and `failed_operation`.
5. If copying the commit result failed, query the same file with `KSM_IOC_QUERY_TRANSACTION`. Repeating a successful commit is idempotent. Closing the file releases its staged state.

A transaction accepts at most 65,536 path operations, 65,536 maps rules and 65,536 kstat rules, with a shared limit of 64 MiB of staged data and up to 256 path operations per stage call. A failed stage preserves earlier staged operations. A failed commit preserves the published generation. `KSM_TX_REPLACE_PATH_RULES` replaces the path and xattr sets. `KSM_TX_REPLACE_XATTR_RULES` replaces only the xattr set. A configuration-only transaction preserves path rules. The embedded YukiSU provider owns UID policy and rejects standalone policy fields.

Maps and kstat rules have explicit `fields` masks. Selected zero values are meaningful. `KSM_MATCH_ANY_DEVICE` selects wildcard matching, while an exact device value of zero remains valid. Device values use the kernel encoding `(major << 20) | minor`. Timestamp seconds and signed sizes use their 64-bit two's-complement representation. `KSM_TX_CONFIG_RESET_POLICY` restores the unconfigured standalone policy state.

`KSM_CAP_LIVE_RULES` reports source and merge-directory monitoring. Updates retain the captured root, working directory and credentials. Source replacement publishes a new generation while existing open files retain their source reference. `GET_HOOKS` reports the live rule count and last refresh error. Prepare failures retain the previous published view.

Notification support is reported independently through `KSM_CAP_SOURCE_INOTIFY`, `KSM_CAP_MULTISOURCE_INOTIFY`, `KSM_CAP_SOURCE_FANOTIFY_INODE` and `KSM_CAP_MULTISOURCE_FANOTIFY`. Availability depends on the running kernel configuration and successful installation of the corresponding native entry adapter. Multi-source watches cover aliases, MERGE and virtual directories using a captured observer scope. Inotify retains its native watch descriptor, queue, rename cookies and watch-removal events. Fanotify retains native event queues and permission decisions, including pending decisions during teardown. Multi-source FID watches support native visible directories with `FAN_REPORT_FID` and masks without directory-entry events, subject to native filesystem ID and exportfs checks. Synthetic anchors, DIR_FID/NAME reporting and directory-entry FID events return `EOPNOTSUPP`. Composite `FAN_MARK_ADD | FAN_MARK_EVICTABLE` also returns `EOPNOTSUPP` because subscription snapshots retain object references. Mount and filesystem marks use their native visible-mount scope.

Source ACCESS/MODIFY notifications follow the native producer's result, timing and PID. The relay installs one native mark at the vnode's first successful open. Kernels with `FSNOTIFY_MARK_FLAG_NO_IREF` cache it until inode reclamation. Older kernels retire their inode-pinning mark at the last file release. Removing the last pathname preserves the relay for held files while retiring native user watches. Queued I/O retains the necessary file references through completion. Rule changes refresh multi-source subscriptions after materialization has finished, while failed transactions preserve existing subscriptions.

The mount projection uses the observed task's own namespace and root. Its cache contains metadata, with kernel references confined to active calls and native proc-file lifetimes. Ordinary applications use the selected policy scope and isolated UIDs use `SPOOF`.

Source-backed directory children support rename through a pre-lock syscall adapter. Renames and exchanges retain live visible dentries, so cwd and open directory paths follow the new names. Crossing between projected and native directories returns `EXDEV`. Exact single-file aliases return `EXDEV` because their configured path binding requires an explicit rule update. Source-less directories remain read-only. Older mmap ABIs retain their native source-file identity. Rule-owned identity domains preserve observed child inode numbers across dentry reclamation and hardlink or casefold aliases. Native unlink eviction and superblock shutdown retire the corresponding identities, while held references preserve their previous numbers. Module-generated inode numbers are unique within the live Kasumi registry, while the visible filesystem may also allocate native inode numbers in the same numeric range.

`KSM_CAP_SOURCE_XATTR` reports complete source get/list/set/remove xattr delegation. Operations enforce visible-object and source-object permissions, source mount idmaps and write references. Native VFS also enforces a read-only visible mount. Exec retains the visible file for binfmt and credential checks, including the visible mount's `nosuid` restrictions. Exec opens involving an idmapped visible or source mount return `EOPNOTSUPP` because vnode ownership cannot represent per-mount set-ID mappings; ordinary file access remains available. Its source file is protected against writes until the visible exec file's final release; source permissions, `noexec` restrictions and file capabilities still apply. SELinux context copying can fail after native create has created the source object.

`KSM_CAP_SOURCE_LOCKS` and `KSM_CAP_SOURCE_LEASES` advertise source-backed POSIX/OFD/flock and lease ownership. Direct source access and aliases share the source lock domain. Owner, signal and fasync operations use the source file, including close-race cleanup.

File-operation variants follow the source's read, write and iterator capabilities and a version-specific flag whitelist. NOWAIT preserves source freeze contention as `EAGAIN`. Buffered asynchronous reads use the io_uring worker fallback. Explicit `IOCB_WAITQ` requests return `EAGAIN`, and unsupported metadata requests return `EOPNOTSUPP`.

Kagami and the integrated ksud configuration accept nonempty `kasumi_kstat_rules`. Store 64-bit fields as decimal strings for exact JSON round trips. Selected zero values and explicit device wildcard masks retain their API 19 meaning. Enabling a nonempty kstat configuration requires the API 19 kstat capability.

## Conflict guard

Mount hiding retains the ordinary behavior. Command 38 and capability bit 12
are reserved; mount-namespace link projection and mode selection are removed.
The standalone policy, unload, and instance-watch commands retain their ABI.

Before installing hooks, Kasumi refuses to load alongside `pathmask`,
`procguard`, `nomount`, `susfs_guard_lkm`, or `hybridmount`, or when the running
IKCONFIG contains `CONFIG_KSU_SUSFS=y`, `CONFIG_NOMOUNT=y`, or
`CONFIG_HYBRIDMOUNT=y`. Once loaded, its module
notifier rejects later conflicting modules before their initialization. The
guard stays active until all Kasumi hooks and callbacks have been retired;
turning visibility off does not unload those hooks. Missing module-list/lock
symbols fail initialization. Unreadable IKCONFIG retains the integrated
implementation's logged, permissive fallback.

`KSM_IOC_GET_CONFLICTS` (46, `0x8508532e`) reads up to 16 fixed 80-byte records
in a 1288-byte snapshot. `KSM_IOC_ACK_CONFLICTS` (47, `0x4008532f`) accepts an
8-byte sequence. GET does not clear events. ACK clears through the displayed
maximum sequence; newer events survive, zero does nothing, and a future
sequence returns `EINVAL`. Both remain callable through an existing control fd
during unload preparation. Records last until this LKM unloads. When the LKM's
own initialization is refused, its memory is discarded: the loader reports the
failure and the kernel log identifies the conflicting target.

## Capabilities

- Redirect a visible path to a regular file, symlink, directory, character device, block device, or FIFO source
- Hide paths and merge/inject directory trees, including newly created virtual directory levels
- Preserve visible path, inode/device identity, SELinux context, and exec-time file capabilities where supported
- Forward file and directory mutations to directory-backed sources
- Apply policy by detected root provider or explicit allow/deny UID lists
- Present scoped `/proc/<pid>/maps`, `smaps`, `mountinfo`, `mounts`, `mountstats`, `fdinfo`, and statfs/statx mount identity
- Configure kstat, maps, mount-hide, statfs, and overlay-xattr features

Socket sources are not supported. Source-less virtual directories are read-only.

## CI KMI Targets

The default DDK release is `20260828`. Current workflows build:

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`
- `android17-6.18`

See `.github/workflows/build-lkm.yml` and `.github/workflows/ddk-lkm.yml`.

## Build

### DDK

```bash
ddk build
ddk build android14-6.1
ddk build android15-6.6
ddk build android17-6.18
```

### Kernel tree

Run against a prepared kernel tree after `modules_prepare`:

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

## Load and Module Parameters

```sh
insmod kasumi_lkm.ko
```

If required symbols are not exported and the installed KernelSU implementation supports it:

```sh
ksud insmod kasumi_lkm.ko
```

Useful parameters:

- `kasumi_skip_kallsyms=1`: resolve symbols individually through kprobes
- `kasumi_fscaps=0|1`: disable/enable exec-time source file-capability replay; default `1`
- `kasumi_device_sources=0|1`: disable/enable char/block/FIFO source wrappers; default `1`
- `kasumi_dummy_mode=1`: stop after early initialization for load testing
- `kasumi_dirhijack=0`: debug only; disables the VFS path-view provider and has no TSR fallback
- `kasumi_dirhijack_force=1`: test only; bypasses per-observer visibility policy

`kasumi_no_tracepoint` is retained as a legacy module parameter, but API 17 no longer has a syscall-redirect path engine.

## Userspace API

The shared ABI is defined by [`src/include/kasumi_uapi.h`](./src/include/kasumi_uapi.h). Userspace should include the matching header, zero-initialize all ABI structs, and keep all reserved fields zero.

### 1. Obtain the control fd

GET_FD is available only to UID 0. The fourth syscall argument points to an `int` that receives the new fd:

```c
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "src/include/kasumi_uapi.h"

static int kasumi_get_fd(void)
{
    int fd = -1;

    (void)syscall(SYS_reboot,
                  KSM_MAGIC1, KSM_MAGIC2, KSM_CMD_GET_FD, &fd);
    return fd;
}
```

The underlying `reboot` syscall normally returns an error because these are not Linux reboot magic values. Ignore that syscall return and check the value written to `fd`. The pointer must remain valid until the syscall returns.

### 2. Check protocol and capabilities

Do this before sending configuration commands:

```c
int version = 0;
int features = 0;

if (ioctl(fd, KSM_IOC_GET_VERSION, &version) < 0 ||
    version != KSM_PROTOCOL_VERSION) {
    return -1; /* incompatible userspace/kernel ABI */
}

if (ioctl(fd, KSM_IOC_GET_FEATURES, &features) < 0) {
    /* feature query failed */
}
```

Use the feature mask before requesting optional behavior, especially `KSM_FEATURE_QUIESCE` and `KSM_FEATURE_MOUNT_HIDE`.

### 3. API 19 transactional configuration

1. Obtain a dedicated control FD and require an exact `KSM_PROTOCOL_VERSION` match.
2. Query `KSM_IOC_GET_CAPABILITIES` and check the required capabilities and transaction limits.
3. Call `KSM_IOC_BEGIN_TRANSACTION` on that FD.
4. Stage rules and configuration with `KSM_IOC_STAGE_TRANSACTION` and `KSM_IOC_STAGE_CONFIGURATION`.
5. Publish with `KSM_IOC_COMMIT_TRANSACTION`. On failure, preserve the previous state and finish recovery with query/abort or by closing the FD.

The individual rule commands below remain part of API 19. Complete configuration updates and rebuilds use the transaction sequence above.

For `struct kasumi_syscall_arg`:

- `src` is the visible path controlled by Kasumi.
- `target` is the real backing source path.
- `type` carries `KSM_RULE_FLAGS_MASK`. Zero uses the configured policy.

### Rule ioctls

| ioctl | Argument | Meaning |
| --- | --- | --- |
| `KSM_IOC_ADD_RULE` | `struct kasumi_syscall_arg *` | Redirect visible `src` to backing `target`; replaces an existing rule for the same `src` |
| `KSM_IOC_ADD_MERGE_RULE` | `struct kasumi_syscall_arg *` | Merge backing directory `target` into visible directory `src` |
| `KSM_IOC_HIDE_RULE` | `struct kasumi_syscall_arg *` | Hide `src`; `target` is unused |
| `KSM_IOC_DEL_RULE` | `struct kasumi_syscall_arg *` | Delete the redirect/hide identified by `src` |
| `KSM_IOC_CLEAR_ALL` | no argument | Clear rules and feature state; configured policy is preserved |
| `KSM_IOC_LIST_RULES` | `struct kasumi_syscall_list_arg *` | Write the active rule listing to the caller-provided buffer |

All strings and buffers referenced by an ioctl argument must remain valid until that ioctl returns.

### Policy ioctls

`KSM_IOC_REPLACE_POLICY` is preferred over incremental updates. Set `version = KSM_POLICY_API_VERSION`, `size = sizeof(struct)`, and pass userspace UID arrays through `allow_uids`/`deny_uids` with their counts.

- `AUTO` selects a detected KernelSU or APatch provider.
- `MANUAL` uses explicit UID lists and requires an allow list.
- `MAGISK` is diagnostic-only; use `MANUAL` for Magisk environments.
- Deny entries win over allow entries; isolated UIDs always receive the concealment scope.
- `KSM_IOC_RESET_POLICY` resets policy explicitly. `KSM_IOC_CLEAR_ALL` does not.

To read a consistent snapshot, call `KSM_IOC_GET_POLICY`, then `KSM_IOC_GET_POLICY_UIDS` for the required lists, and retry if the returned `generation` values do not match.

### Feature and status ioctls

| ioctl | Argument |
| --- | --- |
| `KSM_IOC_GET_FEATURES` | `int *` feature mask |
| `KSM_IOC_GET_HOOKS` | `struct kasumi_syscall_list_arg *` output buffer |
| `KSM_IOC_SET_MOUNT_HIDE` | `struct kasumi_mount_hide_arg *` |
| `KSM_IOC_ADD_MAPS_RULE` / `KSM_IOC_CLEAR_MAPS_RULES` | `struct kasumi_maps_rule *` / no argument |
| `KSM_IOC_SET_MAPS_SPOOF` | `struct kasumi_maps_spoof_arg *` |
| `KSM_IOC_SET_STATFS_SPOOF` | `struct kasumi_statfs_spoof_arg *` |
| `KSM_IOC_ADD_SPOOF_KSTAT` / `KSM_IOC_UPDATE_SPOOF_KSTAT` | `struct kasumi_spoof_kstat *` |
| `KSM_IOC_HIDE_OVERLAY_XATTRS` | `struct kasumi_syscall_arg *`, using `src` |
| `KSM_IOC_SELINUX_FIX` | `int *` enable value |

SELinux Guard (`KSM_IOC_SELINUX_FIX`) provides bounded timing compensation for proc `attr/current` writes in the SPOOF scope. The original write runs first; only parse-skipping inputs that return `EINVAL` receive padding. The default budget is 100 ns, capped at 200 ns and 256 spin iterations, with an early exit when rescheduling is needed. Native SELinux permissions and return values are preserved. `KSM_IOC_GET_HOOKS` reports availability, budget and spin count; enabling returns `EOPNOTSUPP` only when the write proxy is unavailable.

For ioctls whose argument struct contains `err`, check both the `ioctl()` return value and `arg.err`.

### Unload handshake

If `KSM_FEATURE_QUIESCE` is available, keep exactly one control fd and initialize:

```c
struct kasumi_quiesce_arg q = {
    .version = KSM_QUIESCE_API_VERSION,
    .size = sizeof(q),
};

ioctl(fd, KSM_IOC_PREPARE_UNLOAD, &q);
```

`KSM_IOC_PREPARE_UNLOAD` is an idempotent terminal transition. Repeat it on the same fd while `q.state == KSM_QUIESCE_STATE_DRAINING`. When it reports `READY`, close the fd and invoke `delete_module`; the module-removal result remains the final liveness check. Do not use this command unless the controller is committed to unloading, because new GET_FD requests and ordinary control commands are rejected after draining starts.

### Removed or unsupported ABI slots

- uname and `/proc/cmdline` spoofing have been removed; their old command/feature numbers remain reserved.
- `KSM_IOC_SET_MIRROR_PATH` is retained for ABI numbering and returns `-EOPNOTSUPP`.
- `KSM_IOC_REORDER_MNT_ID` is not supported by the LKM build and returns `-EOPNOTSUPP`.

## Rule policy bypass

API 19 uses bit 0 of `kasumi_syscall_arg.type` as `KSM_RULE_BYPASS_POLICY`:
`type = 0` preserves the existing policy, and `type = 1` explicitly opts a rule
into global visibility or hiding. Controllers initialize
this field to zero. The structure size and ioctl encodings do not change.
This field is a flag mask, not a directory-entry file type.

The flag applies to `ADD_RULE`, `ADD_MERGE_RULE`, and `HIDE_RULE`; other bits
are rejected with `EINVAL`. Non-rule commands require zero. Materialized merge
children inherit the parent flag. Managed user hides use the same bit in
`kasumi_user_hide_arg.flags` on UPSERT, and QUERY returns the saved flags.
Other managed-hide requests still require zero input flags. RETRY preserves
the saved flag, including across storage rebinding.

Check `KSM_FEATURE_RULE_BYPASS` (feature bit 15, name `rule_bypass`) before
requesting bypass. Kagami rejects requests when this capability is unavailable
instead of silently treating them as ordinary rules.

Bypass rules apply even to processes excluded by policy, including privileged
and storage-service observers. They still obey Kasumi enablement, teardown,
and internal control/resolution recursion guards. Ordinary sibling rules keep
their existing policy. Bypass does not change mount hiding, maps spoofing, or
other unrelated features.

Manager and Kagami WebUI expose module and individual-rule switches, initially
off. The module flag applies to every Kasumi rule owned by that module; a
single path rule uses the existing longest-prefix selection. Effective bypass
is the module flag OR the selected path-rule flag. OverlayFS and Magic Mount
do not consume this setting. Module edits take effect when the module rules
are rebuilt, such as a Kasumi hot mount or the next boot; saved user hides are
submitted immediately and retain their existing binding-status reporting.

CLI examples (use `ksud kagami` as the prefix in YukiSU):

```sh
kagamid module set-bypass example on
kagamid module add-rule example /system/etc/example kasumi --bypass
kagamid hide add /data/local/tmp/example --bypass
kagamid hide list --details
```

Omitting `--bypass` writes zero; `set-bypass example off` disables the module
flag. Module rules persist a boolean `bypass`. Module-wide and user-hide
overrides are stored as `"on"` entries in `module_bypass.json` and
`hide_bypass.json`; absence means off. `hide list` retains the legacy string
array, while `--details` returns `{path, bypass}` objects. `LIST_RULES` reports
the numeric flags after ADD, MERGE, and HIDE records.

## Standard Userspace Controller

[Kagami](https://github.com/Rouyashiki/Kagami) is the only standard userspace controller implementation for the current Kasumi ABI. Use its Kasumi client and matching UAPI definitions as the reference when integrating API 19.

## Troubleshooting

- Cannot load: check `vermagic`, module signature policy, symbol availability, and `dmesg`.
- API mismatch: query `KSM_IOC_GET_VERSION` before any configuration command.
- Optional command returns `EOPNOTSUPP`: check `KSM_IOC_GET_FEATURES` and the ABI notes above.
- Inspect active routes and rules with `KSM_IOC_GET_HOOKS` and `KSM_IOC_LIST_RULES`.
- For merge/injection regressions, compare `ls`, `ls -l`, `ls -Z`, and `getfattr -n security.selinux` on canonical and symlinked paths.

## Repository Layout

- `src/`: LKM implementation and shared UAPI
- `scripts/`: automation scripts
- `tools/`: diagnostic tools
- `.github/workflows/`: multi-KMI build/release pipeline

## License

- SPDX: `Apache-2.0 OR GPL-2.0`
- See `LICENSE`, `LICENSE-GPL-2.0`, and `NOTICE`
