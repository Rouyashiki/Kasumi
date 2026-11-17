# Kasumi

Kasumi 是一个面向 Android GKI/Linux 的外置内核模块（LKM，产物为 `kasumi_lkm.ko`），用于 root/SU 环境下的路径控制。

它通过仅 root 可用的“匿名 fd + `ioctl`”控制面提供路径重定向、隐藏、目录合并/注入，以及按作用域生成的 proc/mount 视图。Kasumi 的前身是 HymoFS；当前项目名与 ABI 名称统一为 Kasumi/KSM。

English version: [README.md](./README.md)

## 当前状态

- 仓库形态：LKM，不是 in-tree 内核补丁
- 内核实现：`src/`
- 用户态 ABI：`src/include/kasumi_uapi.h`
- 当前协议：`KSM_PROTOCOL_VERSION = 19`

用户态与内核必须严格匹配 API 19；不支持 API 18 或未来版本，也不提供降级路径。所有 ioctl 均沿用固定的 `'S'` magic；客户端通过 `KSM_IOC_GET_VERSION` 检查版本，不匹配时停止操作。
- 路径视图：由 VFS lookup/vnode 提供，不再包含 syscall table dispatcher 或 `sys_enter` redirect 引擎
- 控制入口：root-only `reboot` GET_FD 命令，后续操作全部通过 fd ioctl 完成

## API 19 事务

API 19 通过一个 generation 发布路径规则、设置、独立版 policy、maps 与 kstat 规则。每个事务绑定独立打开的控制 file，staging、commit 和故障恢复都使用同一个 FD。

1. 查询 `KSM_IOC_GET_CAPABILITIES` 与可选 feature mask。
2. 调用 `KSM_IOC_BEGIN_TRANSACTION`，填写期望的 `expected_generation`，零表示捕获当前代际。commit 遇到代际变化会返回 `EAGAIN`，控制器需先 abort 暂存事务，或关闭其 file 并重新打开控制 file，再重新 begin 并暂存内容。
3. 使用 `KSM_IOC_STAGE_TRANSACTION` 添加路径操作，使用 `KSM_IOC_STAGE_CONFIGURATION` 添加配置。每次成功的配置 stage 都会整体替换此前暂存的配置。
4. 调用 `KSM_IOC_COMMIT_TRANSACTION`，检查 `state`、`error`、`generation` 与 `failed_operation`。
5. commit 结果复制失败时，在同一 file 上调用 `KSM_IOC_QUERY_TRANSACTION` 恢复状态。成功 commit 可幂等重试，关闭 file 会释放暂存内容。

单个事务的路径操作、maps 规则和 kstat 规则分别最多 65,536 个，共享 64 MiB 暂存数据上限，每次 stage 最多 256 个路径操作。stage 失败保留此前暂存的操作，commit 失败保留已发布 generation。`KSM_TX_REPLACE_PATH_RULES` 替换路径和 xattr 集合，`KSM_TX_REPLACE_XATTR_RULES` 仅替换 xattr 集合。仅配置事务保留路径规则。嵌入 YukiSU 的版本由现有 provider 管理 UID policy，拒绝独立版 policy 字段。

maps 与 kstat 使用显式 `fields` 掩码，选中的零值具有实际含义。`KSM_MATCH_ANY_DEVICE` 表示设备通配，精确匹配允许设备值为零。设备值采用内核编码 `(major << 20) | minor`，有符号时间秒数和 size 采用 64 位补码表示。`KSM_TX_CONFIG_RESET_POLICY` 恢复独立版未配置 policy 状态。

`KSM_CAP_LIVE_RULES` 表示支持源路径和 merge 目录监视。更新保留配置时的 root、工作目录与凭据。源文件替换会发布新 generation，旧 FD 继续持有原始源对象。`GET_HOOKS` 显示 live 规则数量和最后刷新错误，准备失败时保留上一代已发布视图。

通知支持通过 `KSM_CAP_SOURCE_INOTIFY`、`KSM_CAP_MULTISOURCE_INOTIFY`、`KSM_CAP_SOURCE_FANOTIFY_INODE` 与 `KSM_CAP_MULTISOURCE_FANOTIFY` 分别报告，取决于运行内核的配置及对应原生入口适配器是否安装成功。多来源 watch 按捕获的 observer scope 覆盖别名、MERGE 和虚拟目录。inotify 保留原生 watch descriptor、队列、rename cookie 和 watch 移除事件。fanotify 保留原生事件队列与权限裁决，包括卸载期间尚在等待的裁决。多来源 FID watch 支持原生可见目录上的 `FAN_REPORT_FID`，要求 mask 不含目录项事件，并通过原生 fsid 和 exportfs 检查。synthetic anchor、DIR_FID/NAME 和目录项 FID 事件返回 `EOPNOTSUPP`。复合订阅的快照持有对象引用，因此 `FAN_MARK_ADD | FAN_MARK_EVICTABLE` 也返回 `EOPNOTSUPP`。mount 和 filesystem mark 使用原生可见挂载作用域。

源 ACCESS/MODIFY 通知遵循原生 producer 的结果、时机和 PID。转发器在 vnode 首次成功打开时安装一个原生 mark。支持 `FSNOTIFY_MARK_FLAG_NO_IREF` 的内核将其缓存到 inode 回收，旧内核在最后一个 file 执行 release 时撤销持有 inode 强引用的 mark。删除最后一个路径时，转发器继续服务仍打开的文件，同时按原生语义撤销用户 watch。queued I/O 持有完成所需的 file 引用。规则更新在 materialization 完成后刷新多来源订阅，事务失败时保留已有订阅。

mount 投影使用被观察进程自己的 namespace 与 root。共享缓存保存 metadata，内核引用由活跃调用和原生 proc FD 生命周期持有。普通应用使用选定的 policy scope，isolated UID 使用 `SPOOF`。

源目录中的普通子项通过原生加锁前的 syscall adapter 支持 rename。重命名及交换会保留可见 dentry，使 cwd 与已打开目录的路径跟随新名字。投影目录与原生目录之间的移动返回 `EXDEV`。精确单文件别名返回 `EXDEV`，其配置路径绑定需要显式更新规则。无后端源的虚拟目录保持只读。旧 mmap ABI 沿用原生 source-file identity。规则持有的 identity domain 使已观察子项在 dentry 回收、硬链接及 casefold 别名之间保持 inode 编号。源对象 unlink 后的 eviction 与 superblock shutdown 撤销对应身份，已持有的引用继续保留旧编号。Kasumi 分配的 inode 编号在活跃 registry 内唯一，可见文件系统也可能在同一数值区间分配原生 inode。

`KSM_CAP_SOURCE_XATTR` 表示源对象 get/list/set/remove xattr 委托全部可用。操作遵循可见对象和源对象的权限检查、源挂载 idmap 与写引用。可见挂载的只读限制由原生 VFS 检查。exec 保留可见 file 供 binfmt 和凭据检查使用，包括可见挂载的 `nosuid` 限制。执行打开涉及 idmapped 可见挂载或源挂载时返回 `EOPNOTSUPP`，因为 vnode 的所有者属性无法表达每个挂载独立的 set-ID 映射；普通文件访问仍可用。源文件的防写保护持续到可见执行文件的最后一个引用释放；源对象权限、`noexec` 限制及文件能力仍然生效。native create 成功后的 SELinux context 复制仍可能失败。

`KSM_CAP_SOURCE_LOCKS` 与 `KSM_CAP_SOURCE_LEASES` 表示支持源对象的 POSIX/OFD/flock 和 lease 所有权。直接访问源路径与别名共享源锁域。owner、signal 和 fasync 操作作用于源 file，并处理加锁与关闭 FD 的竞态清理。

file_operations 变体按源对象的 read、write、iterator 能力与内核版本对应的 flags 白名单选择。NOWAIT 在源文件系统冻结竞争时返回 `EAGAIN`。buffered 异步读采用 io_uring worker 回退，显式 `IOCB_WAITQ` 请求返回 `EAGAIN`，尚未支持的 metadata 请求返回 `EOPNOTSUPP`。

Kagami 与集成 ksud 配置支持非空 `kasumi_kstat_rules`。64 位字段使用十进制字符串保存，以保证 JSON 往返精度。选中的零值和显式设备通配掩码遵循 API 19 语义。启用非空 kstat 配置需要 API 19 的 kstat 能力。

## 防冲突保护

挂载隐藏仅保留普通行为，命令 38 和能力位 12 保留，不再提供命名空间链接伪装或模式选择。
独立版原有的策略、卸载握手和实例监视命令保持 ABI 不变。

安装 hook 前，Kasumi 会拒绝与 `pathmask`、`procguard`、`nomount`、
`susfs_guard_lkm` 或 `hybridmount` 同时加载；运行内核的 IKCONFIG 包含
`CONFIG_KSU_SUSFS=y`、`CONFIG_NOMOUNT=y` 或 `CONFIG_HYBRIDMOUNT=y` 时也会拒绝加载。
加载成功后，通过模块通知器在冲突模块
初始化前拒绝其加载。保护持续到 Kasumi 的 hook 和回调全部退出；关闭可见性功能
不会卸载这些 hook。无法获取模块列表或加载锁时拒绝初始化。无法读取 IKCONFIG
时沿用集成版行为：记录日志并允许初始化。

`KSM_IOC_GET_CONFLICTS`（46，`0x8508532e`）读取最多 16 条、每条 80 字节的记录，
快照大小为 1288 字节。`KSM_IOC_ACK_CONFLICTS`（47，`0x4008532f`）接收 8 字节序号。
GET 不清除事件；ACK 仅清除不晚于用户确认快照最大序号的事件，新事件保留。零值不做操作，
未来序号返回 `EINVAL`。卸载准备期间仍可通过已持有的控制 fd 查询和确认。
事件保存到此 LKM 卸载为止。若 LKM 自身初始化被拒绝，其内存无法保留：加载器报告失败，
具体冲突目标记录在内核日志中。

## 主要能力

- 将可见路径重定向到普通文件、符号链接、目录、字符设备、块设备或 FIFO 源
- 隐藏路径、合并/注入目录树，以及生成不存在的中间虚拟目录
- 在支持的场景中保持可见路径、inode/dev 身份、SELinux context 与 exec file capabilities
- 将文件属性修改及目录 mutation 写穿到目录型真实源
- 按自动检测的 root provider 或显式 allow/deny UID 列表应用策略
- 按作用域生成 `/proc/<pid>/maps`、`smaps`、`mountinfo`、`mounts`、`mountstats`、`fdinfo` 及 statfs/statx mount 身份
- 配置 kstat、maps、mount hide、statfs 与 overlay xattr 功能

不支持 socket 源；无真实源的纯虚拟目录只读。

## CI 覆盖 KMI

默认 DDK release 为 `20260828`，当前工作流构建：

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`
- `android17-6.18`

对应工作流：`.github/workflows/build-lkm.yml`、`.github/workflows/ddk-lkm.yml`。

## 构建

### DDK

```bash
ddk build
ddk build android14-6.1
ddk build android15-6.6
ddk build android17-6.18
```

### 内核源码树

目标内核完成 `modules_prepare` 后执行：

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

## 加载与模块参数

```sh
insmod kasumi_lkm.ko
```

如果内核未导出所需符号，且已安装的 KernelSU 实现支持模块加载，也可以使用：

```sh
ksud insmod kasumi_lkm.ko
```

常用参数：

- `kasumi_skip_kallsyms=1`：通过逐符号 kprobe 解析符号
- `kasumi_fscaps=0|1`：关闭/启用 exec 时的源文件 capability 回放，默认 `1`
- `kasumi_device_sources=0|1`：关闭/启用 char/block/FIFO 源 wrapper，默认 `1`
- `kasumi_dummy_mode=1`：用于加载测试，在初始化早期退出
- `kasumi_dirhijack=0`：仅用于调试；关闭 VFS 路径视图，且不存在 TSR fallback
- `kasumi_dirhijack_force=1`：仅用于测试；绕过按观察者生效的可见性 policy

`kasumi_no_tracepoint` 仅作为历史兼容参数保留；API 17 已不存在 syscall redirect 路径引擎。

## 用户态接口

共享 ABI 定义在 [`src/include/kasumi_uapi.h`](./src/include/kasumi_uapi.h)。用户态必须使用匹配的头文件、将 ABI 结构体清零，并保证所有 reserved 字段为 0。

### 1. 获取控制 fd

GET_FD 仅允许 UID 0 调用。syscall 的第四个参数指向接收新 fd 的 `int`：

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

这些参数不是 Linux reboot magic，因此底层 `reboot` syscall 通常会返回错误。不要以 syscall 返回值判断 GET_FD 是否成功，应检查 task_work 写回的 `fd`。`fd` 指针必须保持有效，直到 syscall 返回。

### 2. 检查协议与能力

发送配置命令前先执行：

```c
int version = 0;
int features = 0;

if (ioctl(fd, KSM_IOC_GET_VERSION, &version) < 0 ||
    version != KSM_PROTOCOL_VERSION) {
    return -1; /* 用户态与内核 ABI 不兼容 */
}

if (ioctl(fd, KSM_IOC_GET_FEATURES, &features) < 0) {
    /* 能力查询失败 */
}
```

请求可选能力前必须检查 feature mask，尤其是 `KSM_FEATURE_QUIESCE` 与 `KSM_FEATURE_MOUNT_HIDE`。

### 3. API 19 事务配置

1. 获取独立控制 FD，确认协议严格等于 `KSM_PROTOCOL_VERSION`。
2. 查询 `KSM_IOC_GET_CAPABILITIES`，验证所需能力及事务容量。
3. 在同一个 FD 上执行 `KSM_IOC_BEGIN_TRANSACTION`。
4. 使用 `KSM_IOC_STAGE_TRANSACTION` 和 `KSM_IOC_STAGE_CONFIGURATION` 暂存规则及配置。
5. 使用 `KSM_IOC_COMMIT_TRANSACTION` 发布；失败时保留原状态，并通过 query/abort 或关闭 FD 收尾。

下面列出的单项规则接口仍属于 API 19，完整配置与重建使用上述事务流程。

`struct kasumi_syscall_arg` 字段含义：

- `src`：由 Kasumi 控制的可见路径。
- `target`：真实后端源路径。
- `type` 携带 `KSM_RULE_FLAGS_MASK`，零表示遵循已配置策略。

### 路径规则接口

| ioctl | 参数 | 含义 |
| --- | --- | --- |
| `KSM_IOC_ADD_RULE` | `struct kasumi_syscall_arg *` | 将可见 `src` 重定向到后端 `target`；同一 `src` 已存在时替换旧规则 |
| `KSM_IOC_ADD_MERGE_RULE` | `struct kasumi_syscall_arg *` | 将后端目录 `target` 合并到可见目录 `src` |
| `KSM_IOC_HIDE_RULE` | `struct kasumi_syscall_arg *` | 隐藏 `src`；不使用 `target` |
| `KSM_IOC_DEL_RULE` | `struct kasumi_syscall_arg *` | 按 `src` 删除 redirect/hide 规则 |
| `KSM_IOC_CLEAR_ALL` | 无参数 | 清空规则与 feature 状态；保留已配置的 policy |
| `KSM_IOC_LIST_RULES` | `struct kasumi_syscall_list_arg *` | 将当前规则列表写入调用方提供的 buffer |

ioctl 参数引用的字符串和 buffer 必须保持有效，直到该 ioctl 返回。

### Policy 接口

控制器应优先使用 `KSM_IOC_REPLACE_POLICY`，不要拆成多次增量更新。调用时设置 `version = KSM_POLICY_API_VERSION`、`size = sizeof(struct)`，并通过 `allow_uids`/`deny_uids` 传入用户态 UID 数组及对应 count。

- `AUTO`：使用自动检测到的 KernelSU 或 APatch provider。
- `MANUAL`：完全使用显式 UID 列表，且必须提供 allow list。
- `MAGISK`：只用于诊断报告；Magisk 环境应使用 `MANUAL`。
- deny 的优先级高于 allow；isolated UID 始终进入 concealment scope。
- `KSM_IOC_RESET_POLICY` 显式重置 policy；`KSM_IOC_CLEAR_ALL` 不会重置 policy。

读取一致快照时，先调用 `KSM_IOC_GET_POLICY`，再按需调用 `KSM_IOC_GET_POLICY_UIDS`；如果返回的 `generation` 不一致，则重新读取。

### Feature 与状态接口

| ioctl | 参数 |
| --- | --- |
| `KSM_IOC_GET_FEATURES` | `int *` feature mask |
| `KSM_IOC_GET_HOOKS` | `struct kasumi_syscall_list_arg *` 输出 buffer |
| `KSM_IOC_SET_MOUNT_HIDE` | `struct kasumi_mount_hide_arg *` |
| `KSM_IOC_ADD_MAPS_RULE` / `KSM_IOC_CLEAR_MAPS_RULES` | `struct kasumi_maps_rule *` / 无参数 |
| `KSM_IOC_SET_MAPS_SPOOF` | `struct kasumi_maps_spoof_arg *` |
| `KSM_IOC_SET_STATFS_SPOOF` | `struct kasumi_statfs_spoof_arg *` |
| `KSM_IOC_ADD_SPOOF_KSTAT` / `KSM_IOC_UPDATE_SPOOF_KSTAT` | `struct kasumi_spoof_kstat *` |
| `KSM_IOC_HIDE_OVERLAY_XATTRS` | `struct kasumi_syscall_arg *`，使用 `src` 字段 |
| `KSM_IOC_SELINUX_FIX` | 指向 enable 值的 `int *` |

SELinux Guard（`KSM_IOC_SELINUX_FIX`）对 SPOOF 作用域内的 proc `attr/current` 写入进行有界时序补偿。原生写入先执行；只有跳过 context 解析且返回 `EINVAL` 的输入才追加补偿。默认预算为 100 ns，上限为 200 ns 和 256 次自旋，需要调度时提前退出。保留原生 SELinux 权限检查与返回值。`KSM_IOC_GET_HOOKS` 报告可用性、预算和自旋次数；仅在写入代理不可用时，开启请求返回 `EOPNOTSUPP`。

对于参数结构体中带 `err` 字段的 ioctl，应同时检查 `ioctl()` 返回值与 `arg.err`。

### 卸载握手

当 `KSM_FEATURE_QUIESCE` 可用时，只保留一个控制 fd，并初始化：

```c
struct kasumi_quiesce_arg q = {
    .version = KSM_QUIESCE_API_VERSION,
    .size = sizeof(q),
};

ioctl(fd, KSM_IOC_PREPARE_UNLOAD, &q);
```

`KSM_IOC_PREPARE_UNLOAD` 是幂等的终止状态转换。`q.state == KSM_QUIESCE_STATE_DRAINING` 时，在同一 fd 上重复调用；状态变为 `READY` 后关闭 fd，再调用 `delete_module`，模块删除结果仍是最终存活性判断。进入 draining 后，新 GET_FD 与普通控制命令都会被拒绝，因此只有确定要卸载时才应调用该接口。

### 已移除或不支持的 ABI 槽位

- uname 与 `/proc/cmdline` spoof 已移除，旧 command/feature 编号仅保留占位。
- `KSM_IOC_SET_MIRROR_PATH` 只保留 ABI 编号，返回 `-EOPNOTSUPP`。
- LKM 不支持 `KSM_IOC_REORDER_MNT_ID`，调用会返回 `-EOPNOTSUPP`。

## 标准用户态控制器

[Kagami](https://github.com/Rouyashiki/Kagami) 是当前 Kasumi ABI 唯一的标准用户态控制器实现。接入 API 19 时，应以其中的 Kasumi client 与配套 UAPI 定义作为参考。

## 快速排障

- 无法加载：检查 `vermagic`、模块签名策略、符号可用性与 `dmesg`。
- ABI 不匹配：任何配置命令前先查询 `KSM_IOC_GET_VERSION`。
- 可选命令返回 `EOPNOTSUPP`：检查 `KSM_IOC_GET_FEATURES` 及上面的 ABI 说明。
- 使用 `KSM_IOC_GET_HOOKS` 与 `KSM_IOC_LIST_RULES` 检查当前运行状态和规则。
- 排查 merge/injection 时，同时比较 canonical 与 symlink 路径下的 `ls`、`ls -l`、`ls -Z` 和 `getfattr -n security.selinux`。

## 仓库结构

- `src/`：LKM 实现与共享 UAPI
- `scripts/`：自动化脚本
- `tools/`：诊断工具
- `.github/workflows/`：多 KMI 构建与发布流程

## 许可证

- SPDX：`Apache-2.0 OR GPL-2.0`
- 详见 `LICENSE`、`LICENSE-GPL-2.0` 与 `NOTICE`

## 规则绕过策略

API 19 将 `kasumi_syscall_arg.type` 的 bit 0 定义为
`KSM_RULE_BYPASS_POLICY`：`type = 0` 保持原有策略，显式传 `type = 1`
才让规则的显隐全局生效。控制器默认将该字段置零，普通规则
不会自动变成全局规则。结构大小和 ioctl 编码不变；该字段表示标志位，
不再用作目录项文件类型。

此位用于 `ADD_RULE`、`ADD_MERGE_RULE`、`HIDE_RULE`；未知位返回 `EINVAL`，
其他命令必须传零。合并目录生成的子规则继承此位。托管用户 hide 在
`kasumi_user_hide_arg.flags` 的同一位传入 UPSERT，QUERY 返回保存的标志。
其他托管 hide 请求的输入 flags 仍须为零；RETRY 和存储重新绑定保留原标志。

下发前必须检查 `KSM_FEATURE_RULE_BYPASS`（能力 bit 15，名称 `rule_bypass`）。
Kagami 会拒绝不支持该能力的 bypass 请求，不会静默退回普通规则。

bypass 对策略排除的进程也生效，包括特权进程和存储服务，但仍遵循 Kasumi
总开关、退出流程以及内部控制和解析的防递归保护。相邻普通规则继续遵循
原策略。此位不会改变 mount hide、maps spoof 等其他功能。

Manager 与独立 Kagami WebUI 提供模块、单条规则和用户 hide 开关，默认关闭。
模块开关作用于该模块下发的全部 Kasumi 规则；路径规则仍采用最长前缀匹配，
最终 bypass 为“模块开关或选中路径规则开关”。OverlayFS、Magic Mount 不消费
此设置。模块修改在下次重建规则时生效，例如 Kasumi 热挂载或下次启动；用户
hide 保存后立即下发，继续按现有绑定状态显示结果。

```sh
kagamid module set-bypass example on
kagamid module add-rule example /system/etc/example kasumi --bypass
kagamid hide add /data/local/tmp/example --bypass
kagamid hide list --details
```

YukiSU 集成版将命令前缀换成 `ksud kagami`。不带 `--bypass` 时写零；
`set-bypass example off` 关闭模块开关。模块路径规则保存布尔 `bypass`；
模块和用户 hide 的覆盖值分别在 `module_bypass.json`、`hide_bypass.json`
中保存为 `"on"`，缺省为关闭。`hide list` 保留字符串数组格式，
`--details` 返回 `{path, bypass}` 对象。`LIST_RULES` 的 ADD、MERGE、HIDE
记录末尾报告数值标志。
