# GM168SEC 533C Transport Contract

## Scope and Binary Identity

This note owns the Geneva MCU transport and device-control contract for
`27c6:533c`, including `GF5288_GM168SEC_APP_13016` and the bundled Windows APP
`13020`. Host addresses and structure offsets belong to the two binaries
identified here. The MCU subsection separately identifies addresses in their
embedded APP images and shared USB IAP10007. The [chip-ID mapping](CHIP-ID-PROFILE-MAPPING.md) owns the
fingerprint-family and algorithm-selection relationships above this transport.

**W** is `drivers/production/Windows10-x64/PID533C/Wbdi.dll` from Dell driver
package **600N5**, version **3.20.30.130, A05**:

- [Dell driver details](https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=600n5)
- Package filename: `Goodix-Fingerprint-Sensor-Driver_600N5_WIN64_3.20.30.130_A05_02.EXE`.
- Wbdi.dll SHA-256: `89f4d9fa141e5e8b118b4a3f1c1b1de0a90b525809bdb9ea5a719543b8be4068`.
- PID533C INF `DriverVer`: `06/08/2020,3.0.37.600`; this component version is
  distinct from the package version.
- PE image base: `0x180000000`.

**L** is `libfprint-tod-goodix-53xc-0.0.6.so`, installed by package
`libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb` under
`usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/`:

- [Package download](http://dell.archive.canonical.com/updates/pool/public/libf/libfprint-2-tod1-goodix/libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb)
- DEB SHA-256: `b921e155fd35b06341a453b9c6f6c4c7101f199aee314403826c517156a4b038`.
- ELF SHA-256: `bfa30696fbed9b86cfb5339293d458b9175d05b8895a8644d6b72615ffc9756b`.
- ELF build ID: `598f4a40b805dd4e225b20486cc553512c8c45a7`.
- Listed L addresses use analysis base `0x100000`; subtract `0x100000` to
  obtain ELF virtual addresses.

## MCU Selection and Dispatch

The W INF binds `USB\Vid_27C6&Pid_533C` and `USB\Vid_27C6&Pid_530C` without
an `MI_` suffix. Its initialized MCU pointer at `W:0x1801481a0` selects the
Geneva object at `W:0x18014a020`.

| Table | Offset | Target | Role |
| --- | --- | --- | --- |
| Object `0x18014a020` | `+0x00` | `0x180072370` | CreateContext |
| Object | `+0x10` | `0x18007bf50` | McuSetEventCallbacks |
| Object | `+0x18` | `0x18007bff0` | McuSetFp |
| Object | `+0x28` | `0x180149eb0` | I/O table |
| Object | `+0x30` | `0x180149ed0` | Parsing table |
| Object | `+0x38` | `0x180149f50` | MCU operations |
| I/O `0x180149eb0` | `+0x10` | `0x180072640` | SendCmd |
| I/O | `+0x18` | `0x1800724b0` | WriteTls |
| Operations `0x180149f50` | `+0x00` | `0x180072830` | RecvPackage |
| Operations | `+0x10` | `0x180072b90` | SelfCheck |
| Operations | `+0x40` | `0x18007a180` | McuGetChipId |
| Operations | `+0x48` | `0x18007a470` | McuGetFirmwareVersion |
| Operations | `+0x78` | `0x1800733f0` | UpdateFirmware |
| Operations | `+0x80` | `0x180072e40` | ProcessPsk |
| Operations | `+0x88` | `0x18007c360` | McuStartTls |

`McuDevLoader` at `W:0x18004ef70` creates the configured MCU, sets its
callbacks, wakes it, and requires SelfCheck to succeed. It then requires PSK
processing and the firmware-update decision to succeed. Unless the update
requests re-enumeration, it calls `McuResetFingerPrint`, sleeps 10 ms, reads
the chip ID, and installs the selected fingerprint object and logic callbacks.
Wake and fingerprint-reset failures are logged but do not stop this sequence;
SelfCheck, PSK, firmware-decision and chip-ID failures abort loading.

SelfCheck reads the firmware string through `McuGetFirmwareVersion`. A failed
read takes the wake/reset helper `W:0x180074158` and another read. Parser
`W:0x180079cdc` requires three underscore separators. L parser
`0x00118620` tests the three separator searches at `0x0011865e`,
`0x00118695` and `0x001186c9`; a missing separator fails parsing.
The parsed record is:

| Offset | Capacity | Content |
| --- | --- | --- |
| `+0x00` | 128 bytes | Full firmware string |
| `+0x80` | 32 bytes | Chip prefix, such as `GF5288` |
| `+0xa0` | 32 bytes | MCU platform |
| `+0xc0` | 32 bytes | Mode, such as `APP` or `IAP` |
| `+0xe0` | 32 bytes | Version |

SelfCheck accepts the platform only when `_stricmp` matches `GM168` or
`GM168SEC`. The two-entry array at `W:0x180149f28` points to these strings at
`W:0x1800eb458` and `W:0x1800eb460`. Other MCU implementations linked into
this DLL do not replace this selected Geneva dispatch.

In L, class initializer `L:0x00154d20` names the driver `goodix-tod` and
`Goodix Fingerprint Sensor 53xc`. Its USB ID table at `L:0x0020fa00` contains
PID `0x533c`, VID `0x27c6` at `L:0x0020fa90`, stored as two 32-bit values in
PID/VID order. Probe `L:0x001563b0` obtains the actual PID through
`g_usb_device_get_pid` for firmware checking.

L's initialized pointer `0x002493c0` selects object `0x00246dc0`. Its `+0x40`
points to Geneva operations `0x00246e20`; `+0x30` points to I/O table
`0x00246f80`. Loader `0x0012a0d0` reads that pointer at `0x0012a1a2`
and invokes object slot `+0x00` for construction. There is no in-binary
writer replacing this selection for PID `0x533c`.

| L table | Offset | Target | Role |
| --- | --- | --- | --- |
| Object `0x00246dc0` | `+0x00` | `0x0011ef50` | Geneva CreateContext |
| Operations | `+0x10` | `0x0011de20` | SelfCheck; accepts `GM168`/`GM168SEC` |
| Operations | `+0x40` | `0x00118eb0` | McuGetChipId |
| Operations | `+0x88` | `0x0011d770` | ProcessPsk |
| I/O | `+0x10` | `0x0011eb80` | SendCmd |
| I/O | `+0x18` | `0x0011f9d0` | WriteTls |

Loader `L:0x0012a0d0` uses this selected object for SelfCheck, PSK processing
and chip discovery. Its operation offsets are version-specific and differ
from W.

### Image and Reconnect Callbacks

The W chip lookup at `0x18005030c` matches `chip_id >> 8` against fingerprint
configuration `+0x3c`. For `0x220ca1`, key `0x220c` selects fingerprint object
`0x180149440`, configuration `0x1801491e0` and operations `0x180149330`.
Its series value `2` makes `GetLogic` at `0x180066a44` select logic object
`0x180149e10`, whose `+0x18` points to event table `0x180149dd8`.

| W table | Offset | Target | Role |
| --- | --- | --- | --- |
| Events `0x180149dd8` | `+0x10` | `0x180064390` | LogicEvtImage |
| Events | `+0x18` | `0x180065280` | LogicEvtTlsConn |
| Events | `+0x20` | `0x1800645e0` | LogicEvtMcuPowerLost |
| Fingerprint operations `0x180149330` | `+0xb0` | `0x180051a60` | FpMcuSwitchToFdtDown |
| Fingerprint operations | `+0xb8` | `0x180051bc0` | FpMcuSwitchToFdtUp |

`McuSetEventCallbacks` copies these event entries into MCU context `+0x60`,
`+0x68` and `+0x70`, with the opaque logic context at `+0x88`. These are the slots
used by the receive parser.

The selected HV `Start` at `W:0x18006b650` first calls `LogicCheckSensor`
at `W:0x180063d2c` when logic initialized flag `+0xd0` is zero. That helper
reads and checks OTP; failure aborts Start. The TLS branch follows, including
conditional PSK refresh and one TLS retry. Cold-start flag `start_args[0] != 0`
then selects `LogicDownloadChipConfig` at `W:0x1800641a0`. Base preparation
follows configuration: `UpdateAllBase` at `W:0x18006e3e8` runs unless
`start_args[0] == 0 && logic->base_valid_at_0xc0 != 0`, which instead reuses
the retained bases through preprocess initialization at `W:0x1800639d0`.
Config-download and base-update failures are logged; they do not independently
make Start return failure. Resume predicates are described under
[D0 exit and entry](#d0-exit-and-entry).

## USB Interface and Pipe Selection

`UsbDevicePrepareHardware` at `W:0x180088ee0` calls `SelectInterfaces` at
`W:0x180088990`. Selection enumerates interfaces and configured pipes,
accepts WDF pipe type `3` (bulk), tests each pipe's IN/OUT direction, and
stores the selected read and write handles. The relevant WDF function-table
offsets are `+0x760` for interface lookup, `+0x770` for pipe count, `+0x778`
for configured-pipe lookup, and `+0x6c8`/`+0x6d0` for direction predicates.

The reported XPS 13 9310 descriptor layout has one vendor-specific interface,
interface `0`, with bulk OUT `0x01` and bulk IN `0x83`, each with maximum
packet size 64. Those endpoint numbers describe the device layout; the W
selection routine discovers pipes by descriptors rather than hardcoding
those addresses or interface `0`.

`EvtDevicePrepareHardware` at `W:0x18004da00` selects the USB hardware table
`0x180148108` on its no-interrupt-resource branch and sets `DAT_180148160=1`.
`WakeUp` at `W:0x1800729a0` uses this discriminator to select the NOP wake
path. The selected USB sleep path likewise reaches the fingerprint sleep
operation described below.

L's `usbdevice_start` at `0x0014fef0` uses the stored interface setting.
`UsbReader_sendData` at `0x00151070` uses its stored transmit endpoint, permits
transfer lengths 1 through 64, and supplies a 1000 ms libusb bulk-transfer
timeout. Reader `0x00150500` uses the stored receive endpoint. These USB
transfer settings are separate from the MCU ACK/data timeouts below.

## Wrapped Command and TLS Framing

`SendCmd` at `W:0x180072640`, `WriteTls` at `W:0x1800724b0`, and
`_CheckPackageHeader` at `W:0x180074ca8` use a four-byte outer header:

| Byte offset | Encoding | Meaning |
| --- | --- | --- |
| `0` | `uint8` | Flags: `0xa0` command, `0xb0` TLS, `0xb2` TLS with prefix |
| `1..2` | Little-endian `uint16` | Payload length, excluding this header |
| `3` | `uint8` | `(byte[0] + byte[1] + byte[2]) & 0xff` |

Header validation requires high nibble `0xa` or `0xb` and the byte sum above.
The low flag bit mask `0x02` controls the TLS receive prefix handling.
L's `SendCmd` at `0x0011eb80` and `WriteTls` at `0x0011f9d0` build the same
`0xa0` and `0xb0` wrappers; receive routine `0x0011f1b0` checks the header sum.

For an ordinary command with `n` payload bytes, W builds an outer payload of
`n + 4` bytes and a complete wrapped packet of `n + 8` bytes:

```text
outer header[4]
command[1] | LE16(n + 1) | command payload[n] | inner checksum[1]
```

The enabled inner checksum subtracts the command, length bytes and payload
bytes from seed `0xaa`, modulo 256, through helper `W:0x180079ea8`. The
disabled-checksum form uses `0x88`. SendCmd owns its temporary wrapped buffer
and releases it after the I/O call.

`_RecvPackage` at `W:0x180074f4c` accepts an A-family wrapper when
`packet[0] >> 4 == 0xa`. It initializes DataIn with selector
`packet[4] & 0xfe` and the inner little-endian length at `packet + 5`.
Completed image-category data, `(selector & 0xfff0) == 0x20`, skips the
ordinary inner checksum. It still reaches the selected fingerprint image
validator through `_McuParsePackage`, as does decrypted B-family data.

### Wake, Reset, Sleep and EC Control

| Operation | W / L address | Command and payload |
| --- | --- | --- |
| McuSendNop | `0x18007bb50` / `0x00119f00` | `00 / 00 00 00 00` |
| McuResetFingerPrint | `0x18007b6f0` / `0x0011a1d0` | `a2 / 05 14`; four-byte IRQ-status reply |
| FpMcuSwitchToSleepMode | W `0x180051e90` | `60 / 01 00` |
| McuSetEcCtrl | `0x18007bdf0` / `0x0011af20` | `ae / enable mode enable`, three byte-sized fields |

W's reset is MCU operation `+0x30`; it passes a four-byte response buffer
and its length to `IoHubSend`. `McuSwitchToSleepMode` at `W:0x18007c7e0`
reaches fingerprint operation `+0xd0` on the USB branch, selecting the
two-byte sleep payload above. EC control is selected at W MCU operation
`+0xa8` and L operation `+0xb8`. Sleep and EC helpers return failure when
their transaction fails. Their explicit ACK budgets are listed under
[timeouts](#ackdata-completion-and-timeouts).

L configuration `0x00249388=1`, `0x00249398=1`, `0x002493a0=0` selects
the EC/power-button shield table `0x00249340` during logic construction
at `0x00143640`. Enable `0x0014fa60` and Disable `0x0014f900` reach
`McuSetEcCtrl` through worker `0x0014f7c0`. The selected enable command is
`ae / 01 00 01`; disable is `ae / 00 00 00`.

Libfprint open at `L:0x001566f0` calls `libgxfp_start_session` at
`0x00153070`. It enables the shield at `0x00153237`, after logic Start
and before engine-session initialization. Session stop disables it at
`0x001535aa`; scan cancellation disables it at `0x00153e94`.

### Register Read and Chip ID

The selected `McuGetChipId` at `W:0x18007a180` calls `_McuReadRegister` at
`W:0x18007dd98` with address `0`, size `4`. That builder calls
`IoHubSend` at `W:0x180060994` with command `0x82` (category `8`, command `1`)
and a five-byte payload:

```text
00 | addr_lo | addr_hi | size_lo | size_hi
00 |   00    |   00    |   04    |   00       chip-ID request
```

Address and size are little-endian 16-bit fields. The read helper swaps the
two bytes of each returned 16-bit word before returning the register data.
The command constant is loaded at `W:0x18007ddee`; the payload length at
`W:0x18007de0c` is `0x82 - 0x7d = 5`.

The separate `_FpMcuReadRegister` builder at `W:0x18005218c` uses the same
five-byte layout. Split-read builder `W:0x1800522c8` instead uses leading
byte `0x01` followed by an address list, with length `requested_bytes + 1`;
the loader's chip-ID call does not use that builder.

L's selected `McuGetChipId` at `0x00118eb0` calls register builder
`0x001183a0`, also sending five bytes with command `0x82`. Its length and
opcode loads are at `L:0x001183e0` and `L:0x001183e5`.

### TLS Image Prefix and Ownership

The W receive chain is `RecvPackage` (`0x180072830`) through `_RecvPackage`
(`0x180074f4c`) and `_RecvTlsPackage` (`0x1800753a0`), followed by queued
parsing through `0x180074d30` and `_McuParsePackage` (`0x18007d388`).

`_RecvTlsPackage` selects the prefix form when `flags & 0x02` is nonzero,
rather than requiring equality with `0xb2`. The outer payload then starts
with nine bytes. Offsets here are relative to that payload, after the
four-byte outer header:

| Payload offset | Host interpretation |
| --- | --- |
| `+0x00` | No semantic assignment in this contract |
| `+0x01` | Inner command selector used to initialize DataIn |
| `+0x02..+0x03` | No semantic assignment in this contract |
| `+0x04..+0x08` | Five metadata bytes prepended to decrypted data |
| `+0x09` onward | TLS bytes supplied to the receive ring |

For a packet pointer including the outer header, the receive routine reads
the command at `packet[5]`, feeds `packet + 13` for `outer_length - 9` bytes,
and retains five bytes from `packet + 8`. With flag mask `0x02` clear, it
feeds `packet + 4` for `outer_length` bytes and prepends no metadata.

Before TLS state `0x10`, reception signals the handshake event. At or above
that state, it allocates a temporary output buffer of twice the outer
payload length and calls `gf_tls_read` at `W:0x180047ae4`. A positive read
initializes DataIn through `W:0x18006359c`, with announced length cast to
`uint16`: `n + 5` for the prefix form, otherwise `n`. It appends the retained
metadata first through `W:0x180063678`, then decrypted bytes, bounded by
the announced length, and releases the temporary TLS output buffer.

The ring write at `W:0x180075431` precedes the signed TLS-state comparison
at `W:0x18007547b`. Both B0 and B2 therefore supply handshake input when
state is below `0x10`; the prefix flag does not reject an image-shaped pack
in that state. `_RecvPackage` requires MCU initialized flag `+0xb8 != 0`
for either B-family form and rejects an incomplete outer packet. A failed
application read queues recovery without immediately clearing that flag or
changing the routing state.

In image category `2`, `_McuParsePackage` passes `data + 5` and
`received_length - 5` to the selected fingerprint `ParseImage`. On success,
it sets the image event's leading 32-bit flag to `data[0] == 0xaa`, notifies
I/O processing through `W:0x180060f54`, and invokes the MCU `+0x60` image
callback if present. It frees the parsed image output after that callback;
the callback does not acquire ownership of the image allocation.

The selected `LogicEvtImage` at `W:0x180064390` checks the image size against
the expected size at logic context `+0x78`. The flag chooses only between
the log messages `get boot image` and `get image`; it does not select a
different image-processing branch in this callback. The firmware condition
that sets `0xaa` is not part of this contract.

Before that callback, selected `FpParseImage` at `W:0x180050e10` obtains the
raw sample size through fingerprint operation `+0x78`, `W:0x180050d80`.
After removing the five metadata bytes, the required length is exactly
`108 * 88 * 3 / 2 + 4 = 14260` bytes. Any other length returns failure.
`SgxFpParseImage` at `W:0x18004adb0` then checks the trailing four-byte CRC
through `W:0x18003b98c` before unpacking the 14,256 pixel bytes. CRC mismatch
returns `0xff6ffffb`; `FpParseImage` reports failure and frees its output.

For trailer bytes `b0..b3`, the stored CRC is
`(b0 << 8) | b1 | (b2 << 24) | (b3 << 16)`. CRC helper `W:0x18003ba54`
starts at `0xffffffff`, processes only `length - 4` bytes using a top-byte
table and left shifts, and applies no final XOR. Table generator
`W:0x18003b9f4` uses polynomial `0x04c11db7`. L's `FpParseImage`
at `0x0012b180`, `SgxFpParseImage` at `0x001102a0` and CRC checker
`0x0010f450` apply the same exact-length and trailer validation.

L receive routine `0x0011f1b0` uses the same command offset, nine-byte skip
and five-byte metadata prepend.

L requires initialized flag `MCU+0xb8 != 0` at `0x0011f678` and a complete
outer B-family packet. The `flags & 0x02` test at `0x0011f6ab` selects only
the nine-byte skip: prefixed bytes enter the TLS ring at `0x0011f6d6`,
unprefixed bytes at `0x0011f862`. Both writes precede the signed TLS-state
test at `0x0011f718`. State below `0x10` signals the handshake event at
`0x0011f8fe`; otherwise the routine calls `gf_tls_read` at `0x0011f74e`.
The prefix does not reject an image-shaped pack during a handshake.
A nonpositive read queues restart at `0x0011f989` without immediately
changing initialized or connected state.

## ACK/Data Completion and Timeouts

`_IoHubExec` at `W:0x1800613cc` treats ACK and data as separate events in its
command record:

| Offset | Field |
| --- | --- |
| `+0x38` | ACK timeout |
| `+0x40` | ACK event |
| `+0x48` | Data timeout |
| `+0x50` | Data event |
| `+0x58` | Processing-completion event |
| `+0x60` | Error code |

After a successful send, its wait order and error mutation are:

```c
if (cmd->ack_event) {
    if (!wait(cmd->ack_event, cmd->ack_timeout))
        cmd->error = 0xe0000004;
}
if (cmd->data_event) {
    cmd->error = 0;
    if (!wait(cmd->data_event, cmd->data_timeout))
        cmd->error = 0xe0000004;
}
```

The unconditional reset before the data wait discards an ACK timeout for a
command that expects data. An ACK-only command has no such reset. A data
reply does not synthesize an ACK: `_McuParsePackage` routes category `0xb`
to `IoHubNotifyAck` (`W:0x180060b94`), which signals `+0x40`; data notification
uses `IoHubNotifyDataIn` (`W:0x180060cd0`, implementation `0x180060d2c`) and
signals `+0x50`. The latter also checks command compatibility, using
`0xe0000001` for a mismatch, and propagates the received error field.

`CreateContext` calls `_McuCreateContext` at `W:0x18007d1fc`, which initializes
32-bit ACK and data timeout fields at MCU `+0x10` and `+0x14` to `0x5dc`
(1500 ms). Getters `W:0x1800637e4` and `W:0x180063838` supply these defaults
to the chip-ID transaction. `_IoHubExec` also has a 1500 ms
processing-completion wait. These are individual context/wait defaults,
not a universal timeout for every operation.

Geneva `CreateContext` at `W:0x180072370` calls `IoHubEnableRetry`
(`W:0x180060650`) with one, setting IoHub `+0x40`. `IoHubMcuSendCmd2`
at `W:0x1800609dc` permits `1 + (IoHub[+0x40] != 0)` executions and
retries only when the failed command record retains error `0xe0000004`.
There is no command-selector exclusion. An ACK-only timeout qualifies;
for a data command, the ACK timeout is cleared before the data wait, so
the data wait itself must time out, or the later 1500 ms processing wait
must time out, to qualify. A data notification carrying another error,
such as the `0xe0000001` mismatch, does not qualify. A failed write does
not assign this timeout error and does not qualify. Each resend destroys and recreates only the command
record, then invokes the same selected `SendCmd` at `W:0x180072640`.
`IoHubWriteTls` at `W:0x1800612d4` has no retry loop.

`_McuReqTlsConnection` at `W:0x18007ded4`, call site `W:0x18007df8b`,
sends `d0 / 00 00` through `IoHubSend` at `W:0x180060994` and that
retrying command path. It supplies the MCU ACK timeout, no reply buffer
and a zero data timeout, so `CmdOutCreate` at `W:0x180063244` creates an
ACK event but neither a data nor a processing-completion event. D0
therefore gets up to two
sends after an ACK timeout, with a default 1500 ms per ACK wait. TLS
initialization and ring replacement occur once before this transaction
in `McuStartTls`; its command resend performs no TLS reset, ring clear,
USB drain or resynchronization. TLS bytes received during either D0
execution remain in the same ring.

L `_IoHubExec` at `0x00114d00` has the same ACK-error reset before the data
wait. Its `_McuCreateContext` at `0x0011cc10` initializes both defaults to
1500 ms. The set of sensor commands that actually omit ACKs is outside this
host-side contract.

L's selected Geneva constructor `0x0011ef50`, object `0x00246dc0 + 0x00`,
does not enable command retries. `_McuCreateContext` creates the IoHub
through `IoHubCreate 0x00115550`, whose `galloc0 0x0010bb00` allocation
leaves retry flag `IoHub+0x48` zero. `IoHubMcuSendCmd2 0x00115dc0`
permits `1 + (IoHub[+0x48] != 0)` executions and retries only for retained
command error `-5`. Thus the selected Geneva path executes once, unlike W.
The allocation initializes the flag to zero; the sole explicit field writer
is `IoHubEnableRetry 0x00115a00`, store `0x00115a09`. Its only in-binary
code caller is the separate STM32 constructor `0x00121540`, call
`0x001215ae` with value one, not the selected Geneva constructor.
No later Geneva operation invokes this setter. `IoHubCreate` allocates
with `calloc(1, 0xa8)`; its other callers, Holtek `CreateContext
0x001282d0` (through `_McuCreateContext`) and `_FpCreateContext
0x0012ac20`, do not enable retries, and the STM32 and Holtek objects
`0x00246fc0` and `0x002471a0` have no code references.
With retries enabled, ACK-only, data and processing timeouts can qualify;
a data wait clears an earlier ACK timeout, and failed writes do not assign
`-5`. There is no D0 selector exclusion in the retry helper.

L `_McuReqTlsConnection 0x00118a50`, call site `0x00118ac7`, sends
`d0 / 00 00` through `IoHubSend 0x00116070` and that command helper,
with the MCU ACK timeout and zero data timeout and data buffer. Selected
Geneva therefore makes one D0 send and one 1500 ms ACK wait. It does not
resend D0 after a timeout. The optional retry loop recreates only the
command record and never resets TLS or its ring; TLS initialization in
`McuStartTls 0x0011bb00` precedes the D0 transaction.

W's chip-ID and fingerprint-reset helpers obtain both ACK and data budgets
from the MCU getters above. `FpMcuSwitchToSleepMode` instead supplies an
explicit 1500 ms ACK timeout, and `McuSetEcCtrl` supplies 500 ms. Both are
ACK-only transactions with no data buffer or data wait.
L's `McuSetEcCtrl` instead supplies a 1500 ms ACK timeout.

ACK payload byte 1 also carries a general configuration-loss notification.
`McuParseMsg` at `W:0x18007aef0` sets event field `+0x08` to one when
`ack_flags & 0x02` is nonzero. `_McuParsePackage` at `W:0x18007d388`
dispatches that field to MCU event callback `+0x70`, selected
`LogicEvtMcuPowerLost` at `W:0x1800645e0`, independently of the acknowledged
command. The handler sets logic PSK-refresh flag `+0xe0=1`. When logic
`+0xd0 != 0` and recursion guard `DAT_180173cd4 == 0`, it sets the guard,
calls `LogicDownloadChipConfig` at `W:0x1800641a0`, logs failure if returned,
and clears the guard. L's `LogicEvtMcuPowerLost` at `0x00145670` sets
logic `+0xec=1` at `0x001456d8`, before its initialization/recursion-gated
restore call at `0x001457ac` to `LogicDownloadChipConfig 0x00144980`.
Neither callback arms FDT. The flag's Stop/Start lifetime is described
under [D0 exit and entry](#d0-exit-and-entry).

W sets `logic+0xe0` on every nonzero loss event, including events received
while the restore recursion guard is set. Assembly at `W:0x18006464a`
tests event `+0x08`; `W:0x180064660` stores one before either the guard
branch at `W:0x180064666` or the initialization test at
`W:0x18006466c`. There is no prior-loss transition test and no filter on
the acknowledged command, including D0, E4 or 90. The recursion guard
suppresses nested configuration downloads, not flag mutation. The callback
does not maintain separate persistent configuration-lost, restore-pending
or restore-active fields. `LogicDownloadChipConfig` itself neither reads
nor clears `logic+0xe0`; the callback clears only the recursion guard on
return, including after a failed download.

L has the same level-triggered setter. Selected `McuParseMsg` at
`L:0x00119580`, parsing table `0x00246f20 + 0x08`, accepts ACK subcommand
zero with payload length greater than one and sets event `+0x08` when
`payload[1] & 0x02` is nonzero. It does not require status bit zero or
restrict `payload[0]`, the acknowledged selector. Parser dispatcher
`L:0x0011c090` invokes MCU callback `+0x70` for that event. In
`LogicEvtMcuPowerLost`, store `L:0x001456d8` sets `logic+0xec=1` on every
nonzero loss event, before testing global restore-recursion guard
`0x0024c1c4` and initialized flag `logic+0xdc`. No prior-loss transition
test gates the store. When the guard is zero and logic is initialized,
the callback sets the guard and synchronously calls `LogicDownloadChipConfig`;
the download transaction can wait for the IoHub mutex. It clears only the
guard on return. Loss ACKs observing the guard set still set `logic+0xec`
but skip another restore. The global guard uses ordinary loads/stores,
not an atomic test-and-set or a mutex. This callback has no separate
configuration-lost or restore-pending field; neither it nor
`LogicDownloadChipConfig` clears `logic+0xec` after a successful restore.

## TLS Configuration and Connection Lifetime

The W initialization chain is:

```text
McuStartTls       0x18007c360
tlslib_server_init 0x180047998
SecTlsInit        0x180005fe0
tls_init          0x180007ad0
```

The wrapper supplies endpoint type `2`, mapped to mbedTLS server endpoint
`1`, and authentication type `1` for PSK. The retained host key and its
length come from `W:0x18007cb48`.

| Configuration | Value |
| --- | --- |
| Host role | TLS server |
| Authentication | PSK |
| Minimum and maximum version | TLS 1.2, protocol major/minor `3,3` |
| Ciphersuite | `0x00ae`, `TLS_PSK_WITH_AES_128_CBC_SHA256` |
| PSK identity | `Client_identity`, 15 bytes |

`tls_init` copies the identity from `W:0x18012fae8`, stores a 64-bit `0xae`
at `W:0x180218658` (suite followed by a zero 32-bit terminator), and writes
`0x03030303` to version configuration at `W:0x180217fd8`.

The ClientKeyExchange PSK-identity parser at `W:0x180024c30` reads a
big-endian 16-bit identity length. Missing length bytes, zero length or an
identity extending past the message end returns `-0x7c00`. The configured
PSK path has no identity callback. Its check at `W:0x180024d40` requires
the wire length to equal configuration `+0xf0`, exactly 15, then XORs
each wire byte against configuration `+0xe8` and ORs all differences.
There is no case folding, NUL-terminated comparison or terminator byte in
the configured identity. Length or byte mismatch logs `Unknown PSK
identity`, calls alert sender `W:0x18000c890` with description `0x73`
loaded at `W:0x180024e6c` and called at `W:0x180024e6f`, and returns
`-0x6c80`. The alert sender writes level 2, fatal, then writes and flushes
the record through `W:0x18000bd10` and `W:0x18000ba70`. The installed
send callback `W:0x18007cfd0` sends it through `IoHubWriteTls` at
`W:0x1800612d4`, using the selected B0 wrapper. This is an immediate
transmission attempt, not merely a buffered alert. The parser ignores
the alert sender's return value and still returns `-0x6c80` if alert
transmission fails. A match advances the input
cursor by 15 and returns zero. After a match, the selected pure-PSK
ClientKeyExchange caller `W:0x180024ee0` requires that cursor to equal
the message end at `W:0x180025255`; trailing message bytes return
`-0x7c00`. Missing length bytes, zero length, an out-of-bounds identity
and these trailing bytes do not take the unknown-identity alert branch.

L's selected TLS wrapper `0x00111240` supplies authentication type `1`
and endpoint type `2` through `SecTlsInit 0x001ce090` to
`tls_init 0x001ccc50`. The latter configures `Client_identity` at
`0x002135d8`, length `0x0f`, through `mbedtls_ssl_conf_psk 0x001bece0`;
configuration `+0xe8` owns a copy of exactly those bytes and `+0xf0` holds
their length. No PSK-identity callback is installed.
The server handshake function `0x001c7800`, ClientKeyExchange branch,
reads the big-endian 16-bit length at `0x001c896e`. Missing length bytes,
zero length or an identity extending past the message end returns
`-0x7c00`. The length comparison at `0x001ca361` requires exactly 15,
then `0x001ca375..0x001ca388` XORs corresponding bytes and ORs every
difference. This is case-sensitive, length-delimited comparison without
a NUL terminator. A length or byte mismatch logs `Unknown PSK identity`,
calls alert sender `0x001bd660` at `0x001ca3cc` with fatal level `2` and
description `0x73`, and returns `-0x6c80`. After a match, pure PSK also
requires the identity to end exactly at the ClientKeyExchange message end
at `0x001c89ba`; trailing message bytes return `-0x7c00`.
Alert sender `0x001bd660` writes a type-`0x15` record through
`0x001bcd20`, which flushes through `0x001bcb40` to the configured send
callback `0x0011b850`. That callback uses `IoHubWriteTls 0x00116090`
and selected Geneva `WriteTls 0x0011f9d0` to attempt B0 transmission before
the parser returns. After each successful nonempty write, this callback
sleeps 2 ms (`usleep(2000)`) before returning the byte count, in addition
to `WriteTls`'s own 1 ms sleep. The parser ignores the alert sender's
result and still returns `-0x6c80` if the send fails. Missing length bytes, zero
length, an out-of-bounds identity and trailing message bytes do not
take this unknown-identity alert branch.

`McuStartTls` closes and recreates the handshake event at MCU `+0xc0`,
replaces the `0x40000`-byte ring backing at `+0xd8`, and recreates the ring
object at `+0xd0`. If initialized flag `+0xb8` is set, it first calls TLS
cleanup at `W:0x180047978`. It clears initialized/connected state, initializes
TLS again, marks initialized, and requests the sensor-side TLS start through
`W:0x18007ded4`. `tls_init` also clears its previous TLS context through
`W:0x180007850` and creates fresh handshake/session structures. This explicit
restart does not preserve a session for resumption or perform in-session
renegotiation. Other inbound renegotiation behavior is outside this contract.

Ring constructor `W:0x180041f88` zeroes the new ring's 0x40-byte object,
including its read/write indices. This discards TLS bytes already buffered
before restart. Its entry helper `IoHubEnterLock` at `W:0x18006069c` only
enters the critical section at IoHub `+0x18`; it performs no receive flush.
`McuStartTls` does not drain the USB receive stream or
identify old-session B-family packets. The ring is replaced before the
old context's cleanup clears `+0xb8`, and cleanup does not touch the
ring. Late B0 or B2 data therefore enters the replacement ring whenever
`+0xb8` is set, both in that interval and after re-initialization, and
follows the state-based route described above. `_RecvPackage` drops
B-family packs only while `+0xb8` is zero. The TLS receive callback `W:0x18007ce30` is a
ring reader, not the handshake initializer: while connected flag `+0xc8`
is zero it waits up to 50 ms on handshake event `+0xc0`, reads the ring
through `W:0x180041f10`, and resets that event when the ring is empty.

The outer handshake loop starts its counter at zero and permits at most ten
calls total. It continues only for `-0x60000c` or `-0x400401`. Return `0`
sets MCU connected flag `+0xc8` to `1`, sleeps 100 ms, and returns success;
other results terminate the loop as failures. Ten calls is the outer limit,
independent of work internal to each handshake call.

The counted W call is `SecTlsHandshake` at `W:0x180006090`, reached
through `W:0x180047990`, not a receive callback or an individual TLS
state step. Its inner loop calls `mbedtls_ssl_handshake` at
`W:0x18000e290` up to ten times for `-0x6900` or `-0x6880`, returning
`-0x400401` when those retries are exhausted. That mbedTLS function
itself advances successive handshake states until blocked, failed or
complete. Input fetcher `W:0x18000b760` repeatedly calls the configured
receive callback until its requested byte count is satisfied. Record
reader `W:0x18000c3b0` fetches a five-byte header and then the record
body separately, so one outer call can contain multiple receive waits.

An empty receive callback returns zero. The input fetcher maps this to
`-0x7280`, and `SecTlsHandshake` maps it to `-0x60000c`; this consumes
one outer iteration and preserves handshake progress. Nonempty reads
do not independently consume the outer budget. If ClientHello is
available on the first call, that same call can consume it, send the
server flight and perform the first 50 ms wait for the next client
flight. If no further bytes arrive, ten empty waits remain available
from that point, nominally 500 ms, not nine waits or 450 ms. Prior empty
waits reduce the remaining count. Positive partial reads can add waits
within a call, so ten calls do not impose a universal 500 ms wall-clock
deadline. The selected initialization installs no receive-timeout or
handshake-timer callback; the 1500 ms D0 ACK waits precede this loop,
and W's 100 ms sleep follows successful completion. Neither installed
callback returns `-0x6900` or `-0x6880`: receive callback
`W:0x18007ce30` returns zero, `-1` or a positive byte count, and send
callback `W:0x18007cfd0` returns zero, `-1` or the requested length.

L `McuStartTls` at `0x0011bb00` also has the ten-call outer limit. Its success
branch sets connected and returns without W's 100 ms success sleep.

L counts calls to `SecTlsHandshake 0x001ce140`, through wrapper
`0x00111300`, with remaining count ten at `0x0011bc27`. Continuation
results `-0x60000c` and `-0x400401` decrement it at `0x0011bdef`;
exhaustion exits without another call. `tls_handshake 0x001cd6f0`
internally retries `mbedtls_ssl_handshake 0x001ca980` up to ten times
for `-0x6900` or `-0x6880`, then returns `-0x400401`. The mbedTLS
handshake advances successive states until blocked, failed or complete.
Input fetcher `0x001bc890` repeats positive receive callbacks until its
requested byte count is satisfied; record reader `0x001bd780` separately
fetches the five-byte header and body. Positive reads and individual
handshake states do not independently consume an outer call.

An empty `RecvTlsPackage 0x0011b6a0` wait returns zero; the input fetcher
maps this to `-0x7280`, and `tls_handshake` maps it to `-0x60000c`.
Thus an empty 50 ms wait consumes an outer call without resetting TLS
progress. If ClientHello is available on the first call, that call can
process it, send the server flight and perform the first wait for the
next client flight. With no further bytes, ten empty waits are available
from that point, nominally 500 ms, rather than nine waits or 450 ms.
Earlier empty waits reduce this remaining count. Positive partial reads
can add waits within a call, so the limit is not a universal 500 ms
wall-clock deadline. TLS initialization installs neither a timed receive
callback nor a handshake timer. The selected 1500 ms D0 ACK wait occurs
before the loop; successful completion has no extra sleep.

L restart also recreates handshake event `MCU+0xc0`, replaces the
`0x40000`-byte backing at `+0xd8`, and replaces ring object `+0xd0`
through constructor `0x0010ef10`. The constructor zeroes the read/write
indices, discarding previously buffered TLS bytes. The restart cleans up
the old TLS context, clears initialized `+0xb8` and connected `+0xc8`,
initializes fresh TLS, then sets `+0xb8=1` before requesting sensor TLS.
It does not drain USB input or tag B-family packs by session. A late B0
or B2 pack received after reinitialization therefore enters the fresh
ring and, while TLS state is below `0x10`, supplies handshake input.
The TLS receive callback `0x0011b6a0` waits up to 50 ms on `+0xc0` while
`+0xc8` is zero, reads the ring through `0x0010f170`, and resets the event
when the ring becomes empty. It does not filter old-session records.

The selected Geneva handshake requests TLS with `d0 / 00 00` through
`W:0x18007ded4`, then exchanges B0-wrapped TLS records. Its success tail
releases the host critical section through `IoHubLeaveLock` at
`W:0x1800608e4`; it sends no category-D/subcommand-2 command, wire byte `d4`.
L's selected operation `0x00246e20 + 0x90 -> 0x0011f070` calls
`McuStartTls 0x0011bb00` and likewise sends no D4 success command.
L's separate `StmMcuStartTls` at `0x00120a20` contains `_StmMcuTlsUnlock`,
which sends `d4 / 00 00` through `IoHubSend 0x00116070` at `0x00120c57`.
That STM32 operation is outside the selected Geneva dispatch.

W `McuStartTls` holds the IoHub critical section at `IoHub+0x18` across
the request and handshake, entering through `IoHubEnterLock 0x18006069c`
at `W:0x18007c400` and leaving at `W:0x18007c634`. `_IoHubExec
0x1800613cc` uses that same critical section for ordinary commands,
including the callback's `FpMcuDownloadChipConfig 0x1800512c0`, command
`0x90`. `IoHubNotifyAck 0x180060b94` signals the sender before
`_McuParsePackage` invokes the loss callback. Calling the restore
synchronously inside that callback therefore does not mean the download
finishes before the TLS attempt returns; its command can wait for the
handshake's lock. The ACK callback's flag store precedes that wait.

The callback runs in a queued parser worker, not in the thread holding
the handshake lock. `LogicDownloadChipConfig` is entered at
`W:0x1800646af` even during a handshake; configuration construction can
run there, but `_IoHubExec` cannot send `0x90` until the outer
`McuStartTls` lock is released. The restore guard remains set throughout
this wait and the download. Other loss callbacks still store
`logic+0xe0=1`, but skip their own download while that guard is set.
The guard is a plain global integer, not a lock or completion barrier.

An E4 loss ACK follows the same worker path. `PresetPskReadG
W:0x180074438` sends E4 through `IoHubSend` at `W:0x18007460b`.
Its ordinary `_IoHubExec` holds the IoHub lock through ACK and data
waits, releases it at `W:0x180061987`, then performs any
processing-completion wait at `W:0x1800619c1`. `ProcessPsk
W:0x180072e40`, its hash comparison in `PresetPskIsVaildG
W:0x180049538`, and the caller-owned flag clear hold no lock across
that whole sequence. A waiting restore can therefore send after the E4
command releases the lock, before or after the PSK check and its clear.
There is likewise no join that requires the restore to complete before
Start's retry acquires the handshake lock. A restore blocked by that
retry cannot send until the retry releases it.

Neither a successful restore nor its recursion guard filters later loss
ACKs. The restore's own `0x90` ACK, an E4 ACK or a retry D0 ACK with bit
`0x02` still sets `logic+0xe0`. ACK notification precedes the loss store,
and separate parser jobs can run concurrently, so a loss store can also
occur after the command it acknowledges has completed. This host code
does not establish when firmware stops reporting the loss bit. It does
not guarantee that configuration restore precedes the last PSK flag clear
or prevents a subsequent flag setter in the same Start sequence.

L has the same lock separation. `_McuParsePackage 0x0011c090` runs in
parser worker `0x0011eb50`, on the two-worker MCU pool. It calls
`IoHubNotifyAck 0x00116170` at `L:0x0011c303` before parsing the ACK and
invoking the loss callback. ACK notification takes the separate mutex at
`IoHub+0x80`; it does not wait for the command mutex at `+0x18`.
`McuStartTls 0x0011bb00` holds the recursive `+0x18` mutex from
`L:0x0011bb68` through `L:0x0011bd01`, across D0 and the handshake.
`IoHubCreate 0x00115550` initializes `+0x18` with mutex type 1, recursive,
and `+0x80` with default attributes. `IoHubEnterLock`'s only callers are
`McuStartTls`, `StmMcuStartTls` and `McuSwitchToSleepMode 0x0011b0b0`.
Handshake records leave through raw writes at `0x001188a0`, not
`_IoHubExec`, and inbound B0 handshake records bypass the parser pool, so
a pool worker blocked on `+0x18` does not stall the handshake.
The loss worker can set `logic+0xec` and start building configuration, but
its `FpMcuDownloadChipConfig 0x0012bd80`, command `0x90`, cannot send
until that handshake releases the mutex. The global restore guard stays
set while the worker waits and throughout its download.

An E4 loss ACK has the same callback ordering. `_IoHubExec 0x00114d00`
holds `+0x18` through the E4 ACK and data waits, then releases it before
waiting for processing completion. `ProcessPsk 0x0011d770` holds no lock
across its whole firmware/key/hash sequence. After a failed first TLS
attempt releases the mutex, the waiting restore competes with ProcessPsk's
individual commands and the TLS retry; no join or priority orders the
restore before the PSK check, its caller-owned flag clear, or the retry.
Successful restore does not suppress later loss ACKs: every subsequently
parsed ACK with bit `0x02` still sets the flag, and an initialized callback
observing the guard clear starts another restore. This host code does not
establish when the sensor stops emitting that bit.

### D0 Exit and Entry

`EvtDeviceD0Exit` at `W:0x18004d6f0` calls selected HV Stop at
`W:0x18006c040`. Stop's S0-idle branch, `stop_args[0] == 1`, skips the TLS
shutdown branch. For the initialized, TLS-enabled non-idle path, MCU
operation `+0x90` calls `McuStopTls` at `W:0x18007c690`. It clears initialized
and connected flags, cleans up TLS, closes handshake event `+0xc0`, frees
ring backing `+0xd8`, destroys ring object `+0xd0`, and nulls those handles
and pointers.

L Stop at `0x0014c310` likewise calls MCU StopTLS slot `+0x98` on an
initialized non-S0-idle transition. Stop leaves the configuration-loss/
PSK-refresh flag `logic+0xec` set. Start at `0x0014c610` reads it at
`0x0014c8f4`, calls ProcessPsk at `0x0014c955`, then clears it at
`0x0014c963`. W retains its corresponding `logic+0xe0` flag across Stop.

On D0 entry, `InitThread` at `W:0x18004e680` reuses an existing logic
context and calls HV Start at `W:0x18006b650`. In Start, argument
`start_args[2] == 1` with PSK-refresh flag `+0xe0 == 0` skips the TLS,
configuration and base-preparation block. Otherwise the enabled TLS branch
can refresh PSK and starts a fresh handshake. On a warm start,
`start_args[0] == 0`, PSK refresh is selected by
`start_args[2] == 3 || start_args[1] != 0 || logic[+0xe0] != 0`.
A failed first handshake gets one retry, with an intervening PSK refresh
when `+0xe0 == 1`. Configuration download uses the cold-start predicate;
base reuse uses the retained-validity predicate described under
[image and reconnect callbacks](#image-and-reconnect-callbacks).
The independent ACK configuration-loss callback can also download configuration.
L Start has the same first TLS call plus one retry under the selected
defaults; its repeated-reset option at `0x00249384` is zero.

W HV Start clears `logic+0xe0` after successful ProcessPsk at
`W:0x18006b8ff` and `W:0x18006ba07`. It also clears the flag after a
successful first StartTls call at `W:0x18006ba25`, and after a successful
explicit cold-start configuration download at `W:0x18006bb17`. The retry
StartTls call at `W:0x18006ba1d` jumps past the first-handshake clear, so a
successful retry alone does not clear a flag set during that retry.
These caller-owned clears are distinct from the ACK callback's
configuration download, which has no corresponding flag clear.

L HV Start at `0x0014c610` likewise owns the clears, not `ProcessPsk` or
`McuStartTls` themselves. Successful ProcessPsk clears `logic+0xec` at
`L:0x0014c963` or `L:0x0014ccd0`; failure retains it. Successful first
StartTls, called at `L:0x0014c9c1`, clears the flag at `L:0x0014cc30`.
The retry call at `L:0x0014ca1b` branches directly to `L:0x0014cc3a`
on success, bypassing that clear. Successful explicit configuration
download on the cold-start branch, `start_args[0] != 0`, clears at
`L:0x0014cb65`. An ACK-callback restore has no equivalent clear. Thus a
warm retry can retain a loss flag raised during that retry, even if the
callback restored configuration. With TLS enabled on a warm Start, L
selects ProcessPsk when `start_args[1] != 0`, `logic+0xec != 0`, or the
queried MCU TLS-connected state is zero. Its early skip requires
`start_args[2] == 1`, `logic+0xec == 0` and `start_args[1] == 0`.
After the first failed handshake, the intervening ProcessPsk uses the exact
equality `logic+0xec == 1` at `L:0x0014c9d3`, rather than a nonzero test.

### Failed TLS Read

In the application-data branch of `_RecvTlsPackage`, the first
`gf_tls_read <= 0` calls `_McuStartTlsAsync` at `W:0x18007e018`. It validates
the MCU context and queues `StartTlsThread` (`W:0x18007d100`) on the work
queue at MCU `+0x48`. The worker calls `McuStartTls` directly and logs a
failure if it fails. There is no intervening second-failure threshold.
Scheduling recovery does not wait for the replacement handshake to finish.

The worker makes exactly one `McuStartTls` call, with no whole-handshake
retry or PSK refresh. That call still includes the ordinary D0 ACK-timeout
resend and the ten-call outer handshake loop described above.

Neither W `StartTlsThread` nor `McuStartTls` consumes or clears the logic
power-loss/PSK-refresh flag. The latter updates MCU-local TLS initialized
and connected state, not `logic+0xe0`. Consequently a successful
failed-read restart does not repair an already-set logic flag. In the
separate reconnect callback, successful ProcessPsk clears `logic+0xe0`
at `W:0x180065374` or `W:0x180065445`; neither successful TLS call has an
additional flag clear. Its nonzero-event down-arm at `W:0x1800654da`
does not test `logic+0xe0`.

L receive routine `0x0011f1b0` likewise sends its first nonpositive TLS read
to restart helper `0x0011bfa0`. Its worker `0x0011be70`, like W's worker,
only starts TLS and does not arm FDT. The capture-handler continuation is
separate, as described below.

L's failed-read worker calls `McuStartTls 0x0011bb00` directly. Neither
function processes PSK nor reads or clears `logic+0xec`, including after a
successful handshake. The MCU-local connected flag `+0xc8` is separate
from the logic power-loss flag.

Worker call site `L:0x0011bed0` makes exactly one whole-handshake attempt,
with no retry after failure. That attempt has the ten-call TLS budget
above and, unlike W, no D0 resend because selected Geneva command retries
are disabled.

### Reconnect Event and Finger-Detect Re-arm

`McuParseTlsConn` at `W:0x18007b4a0` is parsing-table slot
`0x180149ed0 + 0x38`. It initializes the event value to zero and sets it to
one exactly when `(command & 0x0e) == 0`. `_McuParsePackage` at
`W:0x18007d388` dispatches category D/subcommand 0 through that parser,
then invokes MCU event callback `+0x68`, the selected `LogicEvtTlsConn`.
Thus the incoming D0 protocol message is a reconnect notification distinct
from B0-wrapped TLS bytes. L uses `McuParseTlsConn 0x00119c60` at selected
parsing table `0x00246f20 + 0x38`, dispatched by `0x0011c090` to
`LogicEvtTlsConn 0x00145340`.

`LogicEvtTlsConn` at `W:0x180065280` is a separate path from the failed-read
worker. Before inspecting the event value, it calls ProcessPsk when logic
flag `+0xe0 != 0`. A successful ProcessPsk clears that flag at
`W:0x180065374`; failure logs and continues. For a nonzero event value,
it calls MCU `StartTls` at `W:0x1800653bf`. On failure it checks `+0xe0`
again, conditionally calls ProcessPsk and clears the flag only on success
at `W:0x180065445`, then calls `StartTls` once more at `W:0x180065488`.
Neither TLS result clears the flag. It then calls fingerprint
operations `+0xb0` with the retained base pointer at logic `+0xf8` and base
size from fingerprint configuration `+0x44`.

The selected target is `FpMcuSwitchToFdtDown` (`W:0x180051a60`), which passes
mode `1` to `W:0x18005243c`, sending wire command `0x32` with mode byte
`(DAT_180173868 << 4) | 0x0c`, a base-present byte, and the base when present.
The event handler neither reads nor updates logic waiting-up field `+0xcc`.
It does not inspect a retained
up/down mode or call the distinct up-operation slot `+0xb8`. It does not
test the second TLS call's result before the down-arm call at
`W:0x1800654da`, and ignores the down-arm's return value. A zero event
value skips both TLS start and this re-arm.

W's USB continuous-reader callback `EvtReadComplete` at `0x1800886f0`
calls selected MCU operation `RecvPackage` at `0x180072830`. Completed
DataIn objects are detached from MCU `+0x40` and scheduled as separate
`0x180074d30` jobs on MCU `+0x48`; each job invokes `_McuParsePackage`
and frees its DataIn afterward. `_McuCreateContext` at `0x18007d1fc`
creates this pool with `ThreadPoolCreate(8, 5000)` at `0x18004263c`.
`ThreadPoolSchedule` at `0x1800428f8` creates workers on demand, up to the
configured limit of eight, when the existing workers are all active. It
inserts a function/argument record through `0x18003b7c0` and signals the
pool event. Insertion prepends to
the list, and workers at `0x180042ac0` remove its head through
`0x18003b738`, so pending work is LIFO, with up to eight concurrent
workers. There is no reconnect-specific deduplication or counter, but
there is a real shared work queue; arrival-order restart/arm pairs are
not guaranteed. Pool teardown at `0x180042780` signals exit, waits up to
500 clock ticks, terminates remaining workers and frees unselected work
through `0x18003b698` and `0x18003b5ec` without invoking its callbacks.

`LogicEvtTlsConn` tests neither logic initialized/running flags, requested
capture mode, waiting-up state nor the logic exit/cancel events. It does
not hold a lock across the refresh/restart/retry/arm sequence.
`McuStartTls` takes the IoHub critical section at IoHub `+0x18` through
`0x18006069c` and releases it through `0x1800608e4` after the whole
handshake. `_IoHubExec` at `0x1800613cc` uses the same recursive critical
section for individual command send and ACK/data waits, then releases it
before processing-completion wait. Other capture commands, down-arms and
TLS starts therefore serialize against an individual handshake, not an
entire reconnect callback. Another worker can start a new handshake
between one callback's handshake and its arm, or between its attempts.
Each completed nonzero callback still attempts its own down-arm;
interleaving does not combine multiple callbacks into one arm. Failed-read
restart jobs use this same pool and handshake lock.
`McuStopTls` at `0x18007c690` itself takes no IoHub lock and checks no
reconnect state; it clears TLS state and destroys the event/ring.

Before category dispatch, `_McuParsePackage` calls `IoHubNotifyDataIn`
for D0 as for other non-ACK packets. Its implementation at `0x180060d2c`
exempts exactly selector `0xd0` from command-mismatch rejection at
`W:0x180060e58..0x180060e60`. The notification supplies error zero,
overwrites an active command's error field `+0x60`, and signals its data
event `+0x50` when present. This notification does not consume the packet:
the D0 reconnect callback still follows even with no pending command.
`McuParseTlsConn` interprets the selector, not a payload status or an ACK
for the host's TLS request. The host independently sends `d0 / 00 00`
through `_McuReqTlsConnection` at `0x18007ded4` on every `McuStartTls`.

The failed-read `StartTlsThread` calls neither this event handler nor the
down-arm operation. The reconnect handler owns its down-arm independently
of `McuStartTls`.

L `LogicEvtTlsConn` at `0x00145340` also calls its down-operation slot
`+0xa8`, using retained base at logic `+0x108`. Its two TLS call sites are
`0x00145489` and `0x001454de`, followed by down-arm at `0x00145530`.
For chip key `0x220c`, fingerprint object `0x00248540`, configuration
`0x002484e0` and operations `0x002485a0` select `FpMcuSwitchToFdtDown
0x0012c0e0`. Configuration base size `+0x44` is 24 bytes. The helper calls
`_FpMcuSwitchToFdtMode 0x0012b800` with mode 1, sending command `0x32`,
mode byte `0x0c`, a base-present byte and the retained base when present.
The reconnect callback neither reads nor updates waiting-up `logic+0xd8`.

L reconnect clears `logic+0xec` only after successful ProcessPsk, at
`L:0x00145440` before checking the event value, or `L:0x00145614` after a
failed first handshake. Failed ProcessPsk logs and retains the flag, but
continues to the corresponding TLS attempt. Neither TLS success has an
additional clear. For a nonzero event the down-arm runs without checking
`logic+0xec` or the retry's result. The handler also ignores the down-arm's
return value at `L:0x00145530`; it guarantees an attempt, not a successful arm.

L USB reader `usbreader_worker 0x00150500` invokes `EvtReadComplete
0x00151630` on a successful bulk receive. Registration is in
`usbdevice_prepare 0x001518a0` through `0x00151010`. The callback requires
nonzero stored reader and MCU contexts, an unsignaled receive-exit event,
and a running reader, then calls the selected MCU `RecvPackage` slot.
It has no foreground scan-cancellation check.
L's completed DataIn path in `RecvPackage 0x0011f1b0` detaches MCU `+0x40`
and schedules a separate `0x0011eb50` job on MCU `+0x48`. The job calls
`_McuParsePackage 0x0011c090`, frees its DataIn through `0x00114990`, then
frees its argument record. `_McuCreateContext 0x0011cc10` creates the pool
with `ThreadPoolCreate(2, 5000)` at `0x0010e750`. Scheduling at
`0x0010ec50` prepends each function/argument record through `0x0010da10`;
workers at `0x0010e0e0` remove that same head through `0x0010daf0`.
Pending work is LIFO, with up to two concurrent workers, not an
arrival-ordered reconnect stream. There is no reconnect-specific
deduplication. Failed-read restart jobs share this pool. Pool stop at
`0x0010e8e0` signals exit and waits up to 500 ms before terminating
remaining workers; workers test exit before selecting another job. Pool
free at `0x0010eb50` discards pending records without invoking callbacks.

L's D0 dispatch has an additional command-routing gate. Before category
dispatch, `IoHubNotifyDataIn 0x00116500` calls `IoHubNotifyDataIn2
0x001162d0`. With an active command, it accepts the selector only when it
equals that command's expected selector at `+0x68` or opcode at `+0x0c`,
the command opcode or received selector has category 3, or the received
selector is `0x20`. The category-3 exception does not test the expected
selector at `+0x68`.
There is no D0 exception in L. A mismatching D0 writes `-10` to the active
command's error field `+0x60`, signals its data event if present, and
causes `_McuParsePackage` to skip the reconnect callback through its command
error test at `L:0x0011c19c..0x0011c1a1`. No active command, or a passing
compatibility predicate, allows the callback.
`McuParseTlsConn 0x00119c60` uses the selector's `(command & 0x0e) == 0`,
not a payload status; dispatch already requires category D/subcommand 0.

L `LogicEvtTlsConn` tests no initialized/running flag, pending capture
request, waiting-up state, or exit/cancel event, and takes no lock around
its complete refresh/restart/retry/arm sequence. `McuStartTls 0x0011bb00`
holds the recursive IoHub mutex at `+0x18` through `IoHubEnterLock
0x00115860` and `IoHubLeaveLock 0x00115930` across one complete handshake.
`_IoHubExec 0x00114d00` uses the same mutex for individual command send
and ACK/data waits, releasing it before the processing-completion wait.
Other command operations and TLS restarts serialize against a handshake,
not a whole reconnect callback; another restart can intervene between its
attempts or between its TLS completion and down-arm. Each completed nonzero
callback still attempts its own down-arm; interleaving does not combine
multiple callbacks into one arm. `McuStopTls
0x0011b990` itself takes no IoHub mutex and checks no reconnect state.

TOD cancellation `cancel 0x00155730` calls `libgxfp_scan_cancel
0x00153e00`, then fails the foreground task SSM. The latter calls
`EAadapter_cancel_capture 0x0014f4f0`, which marks adapter cancellation,
clears the logic pending-request field `+0x88`, and signals its capture
event at `+0x10`. It neither removes MCU parser jobs nor changes the
reconnect callback's predicates. The selected shield deactivate slot is
`0x0014fe70`, a no-op; scan cancellation separately disables the shield.

Capture failure has an independent continuation. L `HandleFdt` at
`0x0014aff0` requests up to two image acquisitions. The call at
`L:0x0014b35b` returns immediately to the failure continuation on the first
failed acquisition; it does not require two failures. Only a successful
first acquisition advances to the second. Failure reaches `0x0014bc38`.
Configuration-loss/PSK-refresh flag `logic+0xec != 0` suppresses the arm.
Otherwise waiting-up `logic+0xd8` selects up slot `+0xb0` with retained
base `logic+0x110`, or down slot `+0xa8` with retained base `logic+0x108`
when clear. Ordinary failed capture reaches this continuation before
setting waiting-up and therefore arms down. The successful-capture path
sets waiting-up at `L:0x0014b3a1` and tests the same flag at
`L:0x0014b3ac` before its up-arm, so a set flag also suppresses that arm.

Capture-request handler `ReqOnCaptureData 0x0014d5a0` arms again for each
new request without testing `logic+0xec`. Under logic mutex `+0x90`, with
logic initialized, it returns without arming only when the request is
processed through `LogicSubmitPovCb 0x00145a40`. Otherwise logic
`+0xe8 != 0` first clears `+0xe8` and `+0xd8`; `+0xd8 != 0` or
`+0xd0 == 0` selects up slot `+0xb0`
with base `+0x110`, and otherwise it waits up to 3000 ms on global event
`0x002493d8` and selects down slot `+0xa8` with base `+0x108`. A
flag-suppressed capture arm therefore persists only until the next capture
request, a nonzero reconnect event or the next Start.

This continuation does not repair a retained power-loss flag. If a loss
ACK arrives after the last caller-owned clear, the ACK callback can
successfully restore configuration while leaving `logic+0xec=1`. A later
capture failure then skips both arms, and a successful failed-read TLS
restart does not change that decision. The separate nonzero reconnect
event still performs its unconditional down-arm.

The warm-Start retry admits this state without a late sensor power loss.
A D0 loss callback can remain blocked on `IoHub+0x18` after the first
handshake fails, while Start's ProcessPsk commands and retry acquire that
mutex first. Successful ProcessPsk clears the flag, but a loss ACK during
the retry, or the pending restore's own `0x90` ACK afterward, sets it again.
Retry success and ACK-driven restore have no subsequent clear. Even if
the sensor stops reporting loss once that download completes, the already
set host flag remains. There is no host-side barrier excluding this order.
A successful first handshake does not exclude it either: when the D0 ACK
is the first loss report, W Start's clear at `W:0x18006ba25` needs no
command and follows the lock release, while the blocked restore must
still send `0x90` and parse its ACK. If that ACK carries bit `0x02`, it
sets `logic+0xe0` after the last caller-owned clear. A restore triggered
by an earlier ACK, outside a handshake, can instead complete before
Start's ProcessPsk and first-handshake clears. L has the same ordering:
the first-handshake clear at `L:0x0014cc30` is a plain store after
`McuStartTls` releases `+0x18` at `L:0x0011bd01`, while the blocked restore
still sends `0x90` through `_IoHubExec`. L Start's only other setter, the
retry-failure store `logic+0xec=1` at `L:0x0014ca4e`, is reachable only
when `0x00249384 != 0`. On W USB devices, prepare
hardware `W:0x18004da00` sets `DAT_180148160=1` and `DAT_180148164=0`, so
Start sends no NOP before TLS and has no reset loop.

W `HandleFdtDown` at `0x18006cee4` reaches continuation `0x18006d4a7`.
Its guard is `logic+0xe0`; waiting-up `+0xcc` selects up slot `+0xb8`
with base `+0x100`, or down slot `+0xb0` with base `+0xf8`. This arm
belongs to the capture handler, not the asynchronous TLS worker.
The continuation is the handler's common tail, not a failure-only path:
successful two-image capture (`W:0x18006d473`, after setting `+0xcc=1`),
zero-base reset (`W:0x18006d0e6`), no pending request or invalid image
base (`W:0x18006d136`), base update (`W:0x18006d26e`) and acquisition
failure (`W:0x18006d48d`) all reach it. A set flag therefore suppresses
the up-arm after a successful capture as well.

The display-on branch of `LogicEvtScreenOnOff` at `W:0x180064c80`
re-arms without testing `logic+0xe0`: `+0xcc` at `W:0x18006511b` selects
the up slot `+0xb8` (`W:0x180065160`) or the down slot `+0xb0`
(`W:0x1800651cd`). Display-on is thus a native host path out of the
flag-set, unarmed state, alongside the reconnect event and the next Start.

At `W:0x18006d4ae`, a nonzero flag jumps directly to cleanup at
`W:0x18006d5b2`, skipping both arms. There is no configuration-status,
TLS-connected or restore-recursion test at this continuation. A loss ACK
after the last caller-owned flag clear can leave `logic+0xe0=1` even after
the ACK callback successfully downloads configuration. In particular,
warm Start's successful retry does not clear a loss flag raised during
that retry, and the warm branch skips the explicit cold-start download
and its clear. A subsequent capture failure suppresses both arms, while
the failed-read TLS worker retains the flag. The separate nonzero
reconnect event still owns an unconditional down-arm.

## PSK Validation and Provisioning

### Validation and IAP Transition

`PresetPskIsVaildG` at `W:0x180049538` reads slot `0xbb010002` through
`W:0x18004a128`, unseals the host key with `CryptUnprotectData`, and hashes
the recovered key with SHA-256 helper `W:0x180007380`. It reads slot
`0xbb020001` with requested length `0x20`, compares all 32 bytes against the
computed hash, and installs a matching host key through `W:0x18007ccbc`.
Read, unseal or hash-mismatch failures do not install that key.

The loader-selected `ProcessPsk` at `W:0x180072e40` first tries validation
three times. If validation succeeds, it keeps the existing key. Otherwise,
outside `IAP`/`TESTIAP`, it erases APP through `W:0x180079ed0` with argument
`0x32`, retries the erase once on failure, sleeps 1000 ms after success,
and recurses. In IAP it reaches `PresetPskWriteKey` and revalidation, with
up to three provisioning attempts.

The zero-filled 32-byte sample passed to `GfSealData` (`W:0x1800477dc`)
at `W:0x180072ff5` determines sealed-buffer length `N`. ProcessPsk passes
that length to validation at `0x180073087..0x18007308e`. It is not the key
passed to the Windows provisioning writer.

`PresetPskReadSpecDataG` at `W:0x18004a128` passes capacity `N+9` and
selector `[slot, 0]` to `PresetPskReadG` at `W:0x180074438`. The read
transaction uses command `0xe4` with four LE32 fields; its reply is:

```text
request: LE32(count) | LE32(offset) | LE32(slot) | LE32(0)
reply:   status[1] | LE32(slot) | LE32(fragment_length) | fragment
```

The reader computes `ceil((N+9)/256)` iterations at
`W:0x18007452b..0x18007453a`. Count starts at 256; offset advances by the
previous reply's fragment length at `0x180074590`. The last request uses
`N-offset` at `0x180074598..0x18007459e`; count and offset are stored at
`0x1800745b0/0x1800745b4`, and `0x18007460b` sends the 16-byte payload.
A nonzero reply status fails the read.

At `W:0x1800746cf..0x1800746e4`, the first copy takes `reply+1` for
`fragment_length+8` bytes, retaining the slot and first-fragment length.
Later copies take only `reply+9` for `fragment_length` bytes into
`assembled+8+offset`. The wrapper strips the retained header at
`0x18004a347`, copying exactly `N` value bytes. The reply carries no total
length, and the wrapper neither discovers nor updates `N` from it.
The returned value is the DPAPI blob, without the provisioning TLV header.

### Windows Random PSK

`PresetPskWriteKey` at `W:0x18004a6e0` allocates a zero-initialized 32-byte
local key, then fills that same buffer through `GeneratePsk` at
`W:0x1800472dc`. `GeneratePsk` acquires Windows provider type `1` with
container `MyKeyContainer`; on missing-container error `0x80090016`, it
creates the container with flag `8`. It calls `CryptGenRandom` for the
requested 32 bytes and releases the provider. Random-generation failure
aborts provisioning.

The writer passes the generated key to `CryptProtectData` for host slot
`0xbb010002` and to sensor wrapper `W:0x180006780` for slot `0xbb010003`.
Each wrapped value is encoded as a 32-bit tag, 32-bit length, and value.
For `0xbb010002`, the writer stores the tag at `W:0x18004a857`, selects
TLV `+8` for the blob at `0x18004a8d9`, and stores its LE32 length at
TLV `+4` at `0x18004a961`.
Both representations contain the same generated PSK. The selected Windows
provisioning policy is therefore a random key, while successful validation
preserves an existing key.

Both the sample seal and actual-key seal call `CryptProtectData` with
flags zero, no optional entropy, and description string
`This is the description string.` at `W:0x1800eadc0`. The calls are at
`0x18004784b` and `0x18004a8b0`. Provisioning TLV `0xbb010003` carries the
sensor-wrapped representation, not a DPAPI blob; its retention and readback
are governed by the [MCU reader](#mcu-application-and-preset-reader-handoff).

### Geneva Write Fragments

For platform `GM168` or `GM168SEC`, the writer dispatches to
`PresetPskWriteG` at `W:0x180074880`. It prefixes the concatenated wrapped
TLVs with ten bytes:

```text
LE32(0x95bba556) | LE32(0x9e8d7c6b) | LE16(0)
```

For total prefixed length `N`, it emits `ceil(N / 256)` fragments. Each
command payload is:

```text
LE32(N) | LE32(fragment_length) | LE32(fragment_offset) | fragment
```

The primary command is `0xe0` (category `0xe`, command `0`). If that
transaction fails, it retries with `0xe4` (category `0xe`, command `2`) and
the same write-shaped payload. The constants are loaded at
`W:0x180074ade` and `W:0x180074b38`. A nonzero first response byte is an
error. Allocation and transport failures propagate, and the writer frees
its prefixed-data and fragment allocations.

The ordinary slot-read path also uses `0xe4` with a different payload;
the opcode alone does not distinguish that read from the write fallback.
L's selected `PresetPskWriteG` at `0x00120130` likewise uses `0xe0`.

L's writer has the same ten-byte prefix, 256-byte fragmentation and `0xe4`
fallback. It accepts only a zero first response byte and returns
`0xffdffffc` on transaction or MCU-status failure. Neither this builder nor
`PresetPskWriteKey` checks the firmware mode. The selected caller supplies
the IAP restriction; this host-side restriction does not establish whether
APP firmware accepts or rejects the write command.

### Linux TOD Zero-Filled PSK

L `ProcessPsk` at `0x0011d770` reaches `PresetPskWriteKey` at `0x001137c0`
in IAP. This writer passes a zero-filled 32-byte key to both its host and
sensor wrapping functions. Its random-generation and hash operations use
different stack buffers:

| Stack range in `L:0x001137c0` | Use |
| --- | --- |
| `rsp + 0x20..0x3f` | Zero-filled PSK supplied to both wrappers |
| `rsp + 0x40..0x5f` | Random-byte processing buffer |
| `rsp + 0x60` onward | Hash output from that processing |

The two zero stores are at `L:0x001137ec` and `L:0x001137f1`. The hash call
at `L:0x00113a67` receives output `rsp + 0x60`. The host-wrapper call at
`L:0x00113b1f` instead receives `rsp + 0x20`, length `0x20`, and the
sensor-wrapper call at `L:0x00113b73` receives that same key pointer and
length. Host wrapper `L:0x00112c10`, through `L:0x001d9a50`, seals its input
without replacing the key. Sensor wrapper `L:0x001ce3f0` also receives the
zero-filled input, not the separate hash result.

L `ProcessPsk` reads and parses the firmware version, determines the host-seal
length using a zero sample, and calls validation `0x00112cb0` up to three
times before examining the mode. The IAP/TESTIAP comparisons at
`0x0011da36` and `0x0011da4f` select at most three write-and-revalidate
attempts. Other modes call `McuEraseApp 0x0011a8d0` with `0x32`, once plus
one retry, wait 1,000 ms, and recursively restart PSK processing.
`McuEraseApp` sends `a4 / 00 32`; it returns the transaction result rather
than independently interpreting its two-byte response. Failure after erase
does not restore APP in `ProcessPsk`.

Validation reads `bb010002` through `PresetPskReadSpecDataG 0x00112610`,
unseals it through `GfUnsealData 0x00112b90` and `0x001da030`, hashes the
recovered bytes, and reads `bb020001`. A matching hash installs the host
key through `0x0011d1b0`. Failure to read or unseal the host copy therefore
prevents the hash comparison; a matching zero-key hash alone does not
short-circuit this vendor path.

SHA-256 of this 32-byte zero key is:

```text
66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
```

These are provisioning policies of the identified binaries. The untouched
factory PSK and the current key of an arbitrary device are outside this
contract.

### Sensor-wrapped key representation

L `SecWhiteEncrypt 0x001ce3f0`, used for the `bb010003` TLV, selects
AES-128-CBC and SHA-256. The output is a 16-byte IV, PKCS#7-padded
ciphertext, and a 32-byte HMAC-SHA256. For a 32-byte PSK the representation
is 96 bytes. The IV comes from the first 16 bytes of
`SHA256(LE32(input_length) || "123GOODIX")`, with its final low nibble
replaced by `input_length & 0x0f`. A fixed 16-byte seed is generated by
`0x001ce1a0`; this helper uses rotations of the six bytes `Goodix`,
hash/AES helpers, a fixed HMAC input and CRC arithmetic, with no device,
Windows or user-secret input. Hashing `IV || zero[48] || seed[16]` supplies
the AES key's first 16 bytes and the HMAC key's full 32 bytes. HMAC covers
the ciphertext.

For this 32-byte input, L's host seal `0x001d9a50` has a 54-byte prefix
and 48 encrypted bytes, including the padding block produced by
`0x001d5730`, for 102 bytes total. The two TLVs and Geneva prefix therefore
occupy `8 + 102 + 8 + 96 + 10 = 224` bytes. The single E0 fragment adds its
12-byte fragment header; the PSK write is not a raw 32-byte zero payload.

L also contains `SecWhiteDecrypt 0x001ced10`. It regenerates the same seed,
reads the IV from the input, derives the same keys, decrypts the ciphertext
and compares all 32 trailing HMAC bytes. It returns `-0x400106` on HMAC
mismatch. The exported driver entry point does not expose this helper;
the references at `0x00222dec` and `0x002418e0` are data references, not a
PSK-read caller. The selected validation path uses the host-sealed
`bb010002`, not this decryptor.

W sensor wrapper `0x180006780` uses the same IV/ciphertext/HMAC layout and
fixed-input seed generator `0x180009460`. Its seed generator rotates
`Goodix` right by 1, 3, 5 and 7 bits; L rotates left by 7, 5, 3 and 1.
Neither wrapper receives the Windows DPAPI master key. The DPAPI seal is
the separate `bb010002` representation.

L `PresetPskReadSpecDataG 0x00112610` accepts the caller's 32-bit selector
without an allowlist; `PresetPskReadG 0x0011fc60` copies it into the generic
`e4` read request. This establishes only that the host can encode a read
for a selector. The [MCU reader](#mcu-application-and-preset-reader-handoff)
retains but rejects direct reads of `bb010003` in the selected IAP10007.

## Bundled Firmware and Update Decision

W's selected firmware pointer at `0x1801481b0` points to `0x1800ec890`:
length byte `0x19`, followed by `GF5288_GM168SEC_APP_13020`. The same string
appears inside the bundled firmware at `0x1800ee33e`. L contains
`GF5288_GM168SEC_APP_13016` at `0x0020a3f6`.

L's selected APP descriptor at `0x002493f0` points to `0x00208720`, has
blob length `0x6756`, and USB discriminator zero at descriptor `+0x0c`.
The blob starts with length byte `0x19` and
`GF5288_GM168SEC_APP_13016`. Configuration `0x00249384=0` selects the
bundled `MILAN_GM168SEC_IAP_10007` at `0x001f6fa0` for the USB path.

The W loader calls `UpdateFirmware` at `0x1800733f0` after `ProcessPsk`.
In APP mode, nonzero `ForceFirmwareUpdate` at configuration `+0x42c` selects
APP erase, PSK processing and recursive update. Otherwise `UpdateInApp`
at `0x180075d78` returns one of three outcomes: `0` means success without
update; `1` selects erase, PSK processing and recursive update; other values
fail the update operation. Erase uses argument `0x32` and one retry on
failure.

`UpdateInApp` parses the selected bundled APP and one of two bundled IAPs:
`10007` at `W:0x1800f81e0`, or `20003` at `W:0x1800fd880`, selected by
`W:0x180148164`. Its decision uses these predicates:

1. Current and bundled APP platform tokens must match case-insensitively.
2. If chip prefixes match, equal version strings **after the first
   character** return no-update: `_stricmp(current_version + 1,
   app_version + 1) == 0`.
3. If chip prefixes differ, chip-name helper `W:0x180075ac8` must return the
   bundled APP prefix; failure or mismatch returns error `4`.
4. The bundled IAP must pass the `MILAN`/`GM168SEC` compatibility check at
   `W:0x180075cb4`.
5. `CheckNewAppVersionOk` at `W:0x18007591c` receives current, bundled APP
   and bundled IAP version strings, with mode argument `0`.

For this mode, `CheckNewAppVersionOk` first requires equal first characters
in the current and bundled APP versions, the USB/SPI discriminator. Its
remaining predicate is:

```c
if (strlen(iap_version) < strlen(app_version)) return true;
if (strlen(iap_version) > strlen(app_version)) return false;
if (_stricmp(iap_version, app_version) == 0) return true;
return _stricmp(iap_version + 2, app_version + 2) <= 0;
```

This is a string-compatibility decision, not numeric `current < bundled`.
`GF5288_GM168SEC_APP_13016` versus bundled APP `13020` has different version
tails, the same transport discriminator, and qualifying bundled IAP suffix
`007` or `003` versus APP suffix `020`. It therefore takes the update path
without requiring the force setting, subject to the preceding operations
succeeding.

In IAP mode, helpers `W:0x18007622c` and `W:0x180076ae8` check/update IAP;
`W:0x18007675c` writes the bundled APP. This restore path obtains APP from
the host binary rather than requiring an APP readback from the sensor.
The firmware-side conditions under which APP readback responds or times
out are outside this host-side contract.

### Embedded image layout

The APP blobs contain uncompressed little-endian MSP430 instructions. L's
`0x6756`-byte APP13016 blob has a 26-byte version prefix, `0x6738` image
bytes and a four-byte trailing checksum. W's descriptor at `0x1801481b0`
has length `0x5c9a`; its APP13020 image has `0x5c7c` bytes with the same
prefix/checksum layout. Host image starts are L `0x0020873a` and W
`0x1800ec8aa`. The version prefix is metadata, not an MCU vector table.
L `CheckFirmware 0x00118820` compares the final LE32 against the CRC of
all preceding blob bytes. CRC helper `0x0010f2e0`, with table producer
`0x0010f270`, uses initial `0xffffffff`, polynomial `0x04c11db7`,
most-significant-bit-first processing and no final XOR.

### MCU application and preset-reader handoff

Firmware addresses in this subsection are MCU addresses, not L/W host
addresses. APP13016 occupies `0x4000..0xa737`; APP13020 occupies
`0x4000..0x9c7b`. Both enter at `0x4000`. The selected
`MILAN_GM168SEC_IAP_10007` image is byte-identical in L and W, with
`0x5691` total blob bytes, a 25-byte version prefix, `0x5674` image bytes
and four checksum bytes. L `WriteIap 0x00126550` and W
`WriteIap 0x180076ae8` select that size for USB. Its image occupies
`0xa98c..0xffff`; the reset-vector word at `0xfffe` is `0xa98c`.
Reset initializes SP to `0x3b00` and branches to `0xaa08`. Boot entry
`0xaa08` calls APP `0x4000` after its APP-acceptance branch.

Both APP main loops dispatch category state byte `0x0587 == 0x0e` to
IAP10007 `0xc6ec` when pending flag `0x058c == 1`, clearing that flag
before the call. APP13020 calls at `0x4152`; APP13016 calls at `0x40d6`.
The APP reuses resident IAP code without entering the IAP main
loop. IAP main's category-E handler `0xca2e` distinguishes subcommand
byte `0x0588`: zero enters provisioning, two calls `0xc6ec` for reading.
There is no read-versus-write payload-shape fallback in this IAP handler.

IAP10007 `0xc6ec` loads the preset record with `0xbb78`, first from
address `0x00002000` and, on a return greater than one, from
`0x00012000`. If both fail it responds with bytes `01 00`; otherwise it
calls selector dispatcher `0xc3a8`. That dispatcher accepts exactly
`bb010002`, returning the host-wrapped representation, and `bb020001`,
returning SHA-256 after decrypting the stored `bb010003` representation.
A direct `bb010003` selector reaches the failure response `01 00`.
The stored TLV is therefore consumed by the hash path but is not exposed
by this reader. A host builder accepting arbitrary selectors does not
override this firmware allowlist.

`0xbb78` reads a LE32 length at region base `+0x200` through `0xadba`.
It rejects a nonzero high word or a low word above `0x1000`, reads
`length + 8` bytes into RAM `0x0866`, and compares the trailing CRC
against `0xe062(buffer, length + 4)`. Failure returns `3`; success
returns zero. The loaded layout is `LE32(length) | Geneva prefix[10] |
TLVs | CRC32`; TLVs begin at RAM `0x0874`. Flash reader `0xadba` sets
controller register `0x01d4` and calls `0xac00` with flash opcode `0x03`.
`0xac00` sends the opcode and three address bytes, clocks the requested
bytes into RAM, then deselects the controller. This load/fallback path
does not erase, program or repair either stored copy.

Selector comparisons at `0xc428..0xc434` and `0xc4d2..0xc4d6` implement
the two-case allowlist. All other selectors go directly to `0xc4d8`,
which sends the two-byte failure through response builder `0xbf28`.
The response builder forms the protocol checksum and wrapped reply,
then uses transport sender `0xba88`. Rejected selectors do not invoke
the decryptor or an authentication-attempt counter.

For host slot `bb010002`, request offset zero scans the TLV list and
caches the value offset in RAM word `0x055e`; subsequent fragments reuse
it. The scanner stops if its 32-bit running offset overflows the low
word or reaches the loaded length. Success copies the requested low-word
count from `TLV value + request offset` into the reply after its
nine-byte header. This is a fragment reader for the selected host TLV,
not a separate raw-storage read interface.

For `bb020001`, the scanner selects stored TLV `bb010003`.
`0xedb2` produces a fixed seed using `Goodix` rotations and local crypto
helpers. Key derivation `0xefc2` hashes `IV[16] | zero[48] | seed[16]`
through `0xe782`. `0xf02a` uses that derivation and compares all 32 HMAC
bytes; nonzero comparison returns the same failure response.
`0xf0e0` decrypts the ciphertext into RAM `0x0c70`. The caller subtracts
the final padding byte from `wrapped_length - 0x30`, stores the resulting
low-byte key length at `0x0415`, and calls SHA-256 helper `0xe782`.
It returns a 41-byte response, comprising status zero, selector
`bb020001`, length 32 and the hash. The plaintext remains an internal
RAM input, not the reply value.

Provisioning preserves the sensor-wrapped TLV. Writer `0xca2e` collects
the prefixed TLVs at RAM `0x086a`, calls `0xc770` to copy the ten-byte
Geneva prefix and complete `bb010003` TLV into a separate 512-byte
record, then calls `0xc902` to append the complete-record CRC. The
sensor-only record has a CRC over its first 508 bytes and is programmed
at flash `0x2000/0x2100` through `0xaf08`; the complete record begins
at `0x2200`. `0xc96c` copies the primary region to the backup at
`0x12000`. These program/erase calls belong to subcommand zero's writer,
not to `0xc6ec` or its selector-rejection branch.

APP13016 and APP13020 supply the same reader call target and shared RAM
protocol fields. The reader contract above belongs to the identified
IAP10007 image; an APP version string alone does not identify the actual
resident IAP bytes. Neither APP image contains the MCU reset-vector
table. That table belongs to IAP10007 at `0xffc0..0xffff`.

### Linux probe call path

L `dev_probe 0x001563b0` calls `libgxfp_init 0x001529b0`, then
`libgxfp_check_firmware 0x00152e60` with the USB PID. The latter invokes the
selected loader; `McuDevLoader 0x0012a0d0` calls ProcessPsk through MCU
operations `+0x88`, then `UpdateFirmware 0x0011e160` through `+0x80`.
Thus provisioning and firmware writes belong to probing, before an
enrollment or verification action.

`UpdateFirmware` first checks the configured USB/SPI discriminator against
the bundled firmware descriptor. Its APP branch calls
`UpdateInApp 0x00126840`; result zero preserves APP, one selects APP erase,
PSK processing and recursive firmware update, and other results fail.
The version comparison uses `strcmp(current_version + 1,
bundled_app_version + 1)`, not a numeric upgrade-only predicate. Platform
and chip checks precede `CheckNewAppVersionOk 0x00125f80`, which applies the
transport-character and bundled-IAP compatibility rules.

For IAP, `UpdateInIap 0x00126d40` parses the bundled APP and selected IAP.
Matching current/bundled IAP platform, chip and full version, platform
`GM168SEC`, and a passing compatibility check return `2`, selecting
`WriteApp 0x00126110`. Matching platform/chip with different IAP versions
whose first characters match returns `3`, selecting
`WriteIap 0x00126550` and another update pass. TESTIAP has its own check
at `0x00127070` before WriteIap. These are distinct from the key writer.

WriteApp checks the bundled blob's trailing CRC through `0x00118820` before
streaming. It removes the length-prefixed version string and trailing CRC,
then constructs `LE32(header_crc) | LE32(image_length) | LE32(image_crc) |
image`. `_WriteFw 0x00125c50` sends consecutive `f0` transactions with
payload `LE32(offset) | LE32(count) | LE32(kind) | bytes`, at most 256
image bytes each; kind is `2` for APP and `0` for IAP. It stops on a failed
transaction without rolling back earlier chunks.

After APP streaming, WriteApp derives a 32-byte authentication key through
`GetPmkHmac 0x00114160` from the installed host PSK, computes HMAC-SHA256
over the complete constructed image, and sends the 32-byte result using
`f4`. The four-byte reply must be nonzero. It then calls
`McuResetMcu 0x0011a060`, sending `a2 / 02 32`, and waits up to 10,000 ms
on the re-enumeration event at MCU `+0x180`. It does not branch on the reset
helper's return value; the event wait supplies the subsequent failure check.
If GetPmkHmac or HMAC-SHA256 fails after streaming, the error branches at
`0x001264d0` and `0x001264b0` log and free the buffer but retain the successful
`_WriteFw` result in `r12d`. They return success without sending `f4` or
resetting. This differs from the explicit failure returns on `f4` failure,
a zero firmware-check reply or a failed re-enumeration wait.
WriteIap similarly checks and constructs its bundled image, streams kind
zero, resets and waits for re-enumeration, without the APP `f4` step.

The restore source is the bundled image, not a backup read from the sensor.
These paths provide no host-side rollback of an erased APP or partially
written APP/IAP. Their flash commands do not specify physical erase ranges
or establish preservation of OTP, calibration, PSK storage or boot-ROM
recovery behavior after interruption.

### Current source boundary

`drivers/goodix53x5/family/gm168sec/open.c:goodix_gm168sec_open_handler`
loads the local PSK and checks the sensor's `bb020001` hash through
`goodix_require_current_psk`; it has no counterpart to the native host-seal
unwrapping, provisioning or firmware-update branches.
`family/gm168sec/gm168sec.c:goodix_cmd_writes_sensor` identifies the blocked
PSK/flash/erase command forms for the family's command-admission callback.
The Windows import tool handles `bb010002` separately from driver open.
