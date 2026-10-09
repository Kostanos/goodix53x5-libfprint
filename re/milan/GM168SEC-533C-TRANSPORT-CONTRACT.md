# GM168SEC 533C Transport Contract

## Scope and Binary Identity

This note owns the Geneva MCU transport and device-control contract for
`27c6:533c`, including `GF5288_GM168SEC_APP_13016` and the bundled Windows APP
`13020`. Addresses and structure offsets below belong to the two binaries
identified here. The [chip-ID mapping](CHIP-ID-PROFILE-MAPPING.md) owns the
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
`W:0x180079cdc` splits the underscore-separated string into this record:

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
`0x00246f80`.

| L table | Offset | Target | Role |
| --- | --- | --- | --- |
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

L `_IoHubExec` at `0x00114d00` has the same ACK-error reset before the data
wait. Its `_McuCreateContext` at `0x0011cc10` initializes both defaults to
1500 ms. The set of sensor commands that actually omit ACKs is outside this
host-side contract.

W's chip-ID and fingerprint-reset helpers obtain both ACK and data budgets
from the MCU getters above. `FpMcuSwitchToSleepMode` instead supplies an
explicit 1500 ms ACK timeout, and `McuSetEcCtrl` supplies 500 ms. Both are
ACK-only transactions with no data buffer or data wait.

ACK payload byte 1 also carries a general configuration-loss notification.
`McuParseMsg` at `W:0x18007aef0` sets event field `+0x08` to one when
`ack_flags & 0x02` is nonzero. `_McuParsePackage` at `W:0x18007d388`
dispatches that field to MCU event callback `+0x70`, selected
`LogicEvtMcuPowerLost` at `W:0x1800645e0`, independently of the acknowledged
command. The handler sets logic PSK-refresh flag `+0xe0=1`. When logic
`+0xd0 != 0` and recursion guard `DAT_180173cd4 == 0`, it sets the guard,
calls `LogicDownloadChipConfig` at `W:0x1800641a0`, logs failure if returned,
and clears the guard. L's corresponding repair route is
`LogicEvtMcuPowerLost 0x00145670 -> LogicDownloadChipConfig 0x00144980`.

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

`McuStartTls` closes and recreates the handshake event at MCU `+0xc0`,
replaces the `0x40000`-byte ring backing at `+0xd8`, and recreates the ring
object at `+0xd0`. If initialized flag `+0xb8` is set, it first calls TLS
cleanup at `W:0x180047978`. It clears initialized/connected state, initializes
TLS again, marks initialized, and requests the sensor-side TLS start through
`W:0x18007ded4`. `tls_init` also clears its previous TLS context through
`W:0x180007850` and creates fresh handshake/session structures. This explicit
restart does not preserve a session for resumption or perform in-session
renegotiation. Other inbound renegotiation behavior is outside this contract.

The outer handshake loop starts its counter at zero and permits at most ten
calls total. It continues only for `-0x60000c` or `-0x400401`. Return `0`
sets MCU connected flag `+0xc8` to `1`, sleeps 100 ms, and returns success;
other results terminate the loop as failures. Ten calls is the outer limit,
independent of work internal to each handshake call.

L `McuStartTls` at `0x0011bb00` also has the ten-call outer limit. Its success
branch sets connected and returns without W's 100 ms success sleep.

The selected Geneva handshake requests TLS with `d0 / 00 00` through
`W:0x18007ded4`, then exchanges B0-wrapped TLS records. Its success tail
releases the host critical section through `IoHubLeaveLock` at
`W:0x1800608e4`; it sends no category-D/subcommand-2 command, wire byte `d4`.
L's selected operation `0x00246e20 + 0x90 -> 0x0011f070` calls
`McuStartTls 0x0011bb00` and likewise sends no D4 success command.
L's separate `StmMcuStartTls` at `0x00120a20` contains `_StmMcuTlsUnlock`,
which sends `d4 / 00 00` through `IoHubSend 0x00116070` at `0x00120c57`.
That STM32 operation is outside the selected Geneva dispatch.

### D0 Exit and Entry

`EvtDeviceD0Exit` at `W:0x18004d6f0` calls selected HV Stop at
`W:0x18006c040`. Stop's S0-idle branch, `stop_args[0] == 1`, skips the TLS
shutdown branch. For the initialized, TLS-enabled non-idle path, MCU
operation `+0x90` calls `McuStopTls` at `W:0x18007c690`. It clears initialized
and connected flags, cleans up TLS, closes handshake event `+0xc0`, frees
ring backing `+0xd8`, destroys ring object `+0xd0`, and nulls those handles
and pointers.

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

### Failed TLS Read

In the application-data branch of `_RecvTlsPackage`, the first
`gf_tls_read <= 0` calls `_McuStartTlsAsync` at `W:0x18007e018`. It validates
the MCU context and queues `StartTlsThread` (`W:0x18007d100`) on the work
queue at MCU `+0x48`. The worker calls `McuStartTls` directly and logs a
failure if it fails. There is no intervening second-failure threshold.
Scheduling recovery does not wait for the replacement handshake to finish.

L receive routine `0x0011f1b0` likewise sends its first nonpositive TLS read
to restart helper `0x0011bfa0`.

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
worker. It can first refresh PSK state when logic flag `+0xe0` is set. For a
nonzero event value, it calls MCU `StartTls`; if that fails, it can refresh
PSK state and calls `StartTls` once more. It then calls fingerprint
operations `+0xb0` with the retained base pointer at logic `+0xf8` and base
size from fingerprint configuration `+0x44`.

The selected target is `FpMcuSwitchToFdtDown` (`W:0x180051a60`), which passes
mode `1` to `W:0x18005243c`. The event handler does not inspect a retained
up/down mode or call the distinct up-operation slot `+0xb8`. It does not
test the second TLS call's result before the down-arm call. A zero event
value skips both TLS start and this re-arm.

The failed-read `StartTlsThread` calls neither this event handler nor the
down-arm operation. Thus down re-arming belongs to the nonzero reconnect
event path, not to every invocation of `McuStartTls`.

L `LogicEvtTlsConn` at `0x00145340` also calls its down-operation slot
`+0xa8`, using retained base at logic `+0x108`.

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

The zero-filled sample passed to `GfSealData` (`W:0x1800477dc`) in
`ProcessPsk` determines sealed-buffer length. It is not the key passed to
the Windows provisioning writer.

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
Both representations contain the same generated PSK. The selected Windows
provisioning policy is therefore a random key, while successful validation
preserves an existing key.

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

SHA-256 of this 32-byte zero key is:

```text
66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
```

These are provisioning policies of the identified binaries. The untouched
factory PSK and the current key of an arbitrary device are outside this
contract.

## Bundled Firmware and Update Decision

W's selected firmware pointer at `0x1801481b0` points to `0x1800ec890`:
length byte `0x19`, followed by `GF5288_GM168SEC_APP_13020`. The same string
appears inside the bundled firmware at `0x1800ee33e`. L contains
`GF5288_GM168SEC_APP_13016` at `0x0020a3f6`.

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
