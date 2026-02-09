# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Linux out-of-tree kernel module (`mx_dma.ko`) for XCENA MX-DMA PCI devices. Provides DMA transfer capabilities between host memory and CXL (Compute Express Link) memory devices. Supports both CXL-enabled and standalone (non-CXL) configurations.

## Build Commands

```bash
# Build with CXL support (default)
make

# Build without CXL support (standalone mode)
make WO_CXL=1

# Clean build artifacts
make clean

# Install (auto-detects CXL via /sys/firmware/acpi/tables/CEDT)
sudo ./install.sh

# Uninstall
sudo ./uninstall.sh

# Build against a specific kernel
make BUILDSYSTEM_DIR=/lib/modules/<version>/build
```

The module requires kernel headers at `/lib/modules/$(uname -r)/build`. There is no test suite in this repository; testing is done through userspace applications in the parent `sdk_release` repo.

## Architecture

### Module Structure

The driver registers as a PCI driver for vendor `0x20A6` (XCENA). Each PCI device creates 5 character devices under `/dev/mx_dma/`:

| Device Node | Purpose | Key Operations |
|---|---|---|
| `mx_dma{N}_data` | Bulk data DMA transfers | read/write (scatter-gather, parallel) |
| `mx_dma{N}_context` | Context/control transfers | read/write (single transfer) |
| `mx_dma{N}_ioctl` | Mailbox and control commands | ioctl |
| `mx_dma{N}_event` | MSI interrupt events | poll |
| `mx_dma{N}_bdf` | PCI BDF information | read |

### Hardware Revision Abstraction

The driver supports two hardware revisions selected at probe time via `pdev->revision`:

- **Revision 1** (`core_v1.c`): Custom mailbox protocol with direct BAR MMIO. Uses 1KB (`SINGLE_DMA_SIZE = 1 << 10`) DMA granularity. SQ/CQ are MMIO-mapped mailbox regions in BAR space.
- **Revision 2** (`core_v2.c`): NVMe-like admin/IO queue model with doorbell-based submission. Uses 4KB (`SINGLE_DMA_SIZE = PAGE_SIZE`) DMA granularity. SQ/CQ are DMA-coherent host memory buffers. Admin queue sets up IO queues via create/delete commands.

Both revisions implement `struct mx_operations` (init_queue, release_queue, create_command_sg, create_command_ctrl) registered via `register_mx_ops_v1/v2`.

### Source File Responsibilities

- **`init.c`** — Module init/exit, PCI probe/remove, character device creation, CXL device discovery. CXL mode uses `bus_register_notifier` on `pci_bus_type`; non-CXL mode uses standard `pci_register_driver`.
- **`fops.c`** — File operations for all 5 character device types. Routes reads/writes through `mxdma_device_prepare()` magic validation.
- **`transfer.c`** — DMA transfer lifecycle: user page pinning (`pin_user_pages_fast`), scatter-gather mapping, parallel transfer splitting, completion waiting, zombie cleanup. Module params: `timeout_ms` (default 60000), `parallel_count` (default 6).
- **`ioctl.c`** — IOCTL handlers for mailbox management (register, init, send/recv commands, read/write data). Defines `MX_IOCTL_MAGIC 'X'` with 7 ioctl commands.
- **`mbox.c`** — Mailbox ring buffer utilities (empty/full checks, index arithmetic with phase-bit wraparound).
- **`helper.c`** — Global transfer ID management via IDR with 16-bit cyclic allocation.
- **`core_v1.c` / `core_v2.c`** — Hardware-specific queue init, submit/complete handler threads, and command creation.

### Key Data Flow

```
User read/write → fops.c (magic validation)
  → transfer.c: alloc_mx_transfers() splits by pages (up to parallel_count)
  → transfer.c: map_user_addr_to_sg() pins pages + DMA maps
  → core_vN.c: create_command_sg() builds hw command with PRP/desc lists
  → transfer.c: mx_transfer_queue_parallel() enqueues to io_queue
  → core_vN.c: submit_handler thread pushes commands to hardware
  → core_vN.c: complete_handler thread polls completions
  → transfer.c: mx_transfer_wait() with interruptible timeout
```

### Concurrency Model

- **submit_thread / complete_thread** — Per-device kthreads that poll SQ/CQ with `swait_queue_head` and `POLLING_INTERVAL_MSEC` (4ms) timeout.
- **sq_lock** (spinlock) — Protects the submission queue list.
- **Mailbox mutexes** — Per-mailbox mutex in `struct mx_mbox` for ioctl command serialization.
- **IDR id_lock** (spinlock) — Protects global transfer ID allocation/lookup.
- **zombie_lock** (spinlock) — Protects zombie transfer list; zombie_cleanup_thread runs with 5-minute grace period.

### CXL vs Standalone Mode

Controlled by `CONFIG_WO_CXL` (set via `make WO_CXL=1`):
- **CXL mode** (default): Uses PCI bus notifier to detect CXL-bound devices. Device ID derived from CXL memory device name (`mem{N}`). Global device list tracks all probed devices.
- **Standalone mode** (`WO_CXL=1`): Uses standard `pci_register_driver`. Device IDs are auto-incremented.

### IOCTL Interface

Magic: `'X'`, commands defined in `ioctl.c`:
- `MX_IOCTL_REGISTER_MBOX` (1) — Register SQ/CQ mailbox pair (up to 80 pairs)
- `MX_IOCTL_INIT_MBOX` (2) — Reset mailbox context
- `MX_IOCTL_SEND_CMD_WITH_DATA` (3) — Send command with optional data write
- `MX_IOCTL_RECV_CMDS` (4) — Receive commands from CQ mailbox
- `MX_IOCTL_SEND_CMDS` (5) — Batch send commands to SQ mailbox
- `MX_IOCTL_READ_DATA` (6) / `MX_IOCTL_WRITE_DATA` (7) — Direct parallel data transfers

## Kernel Version Compatibility

The code handles multiple kernel versions with `LINUX_VERSION_CODE` checks:
- `< 6.1.6`: `mxdma_devnode` uses `struct device *`
- `>= 6.1.6`: `mxdma_devnode` uses `const struct device *`
- `< 6.3.3`: `class_create` takes `THIS_MODULE` argument
- `>= 6.3.3`: `class_create` takes only the name
- `< 6.12.0`: `match_mem_prefix` callback uses `void *data`
- `>= 6.12.0`: `match_mem_prefix` callback uses `const void *data`

## Critical Areas

Changes to the following require extra care:
- **DMA mapping/unmapping** (`transfer.c`) — Must maintain proper pin/unpin and map/unmap pairing to avoid memory corruption.
- **Zombie transfer handling** — Prevents use-after-free when transfers timeout or are interrupted.
- **PRP/descriptor list construction** (`core_v1.c`, `core_v2.c`) — Linked-list DMA descriptor chains must maintain correct bus addresses.
- **Mailbox index arithmetic** (`mbox.c`) — Phase-bit wraparound logic is subtle; `depth` must be power-of-2.
- **Kernel version ifdefs** — Must be kept in sync when targeting new kernel versions.
