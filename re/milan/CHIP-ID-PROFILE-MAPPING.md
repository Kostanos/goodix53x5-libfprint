# Chip ID, Profile, And Algorithm Sensor Type

## Identity And Scope

Unless a package is named explicitly, addresses below belong to the
2.0.310.900 reference driver, with image base
`0x180000000` in both `usbinterface.dll` and `GoodixEngineAdapter.dll`.
The [reference-driver note](REFERENCE-DRIVER.md) provides the Dell download
and exact DLL identities.
USB product IDs do not select profiles. The USB layer calls its profile field
`sensorType` in log messages; that field is not the algorithm sensor-type enum.

## Complete USB Chip Identification

`usbinterface.dll!FUN_180017ef8` is called by `device_enable`
(`FUN_18000e9b0`). It takes a context pointer, reads four bytes from register
zero through `FUN_18001a604(0, buffer, 4, 200)`, and decodes:

Before this call, `device_enable` resets the sensor through
`FUN_18001b6c8(0, NULL)` and unconditionally sleeps 10 ms. `FUN_18001a604`
sends category 8, command 1 with payload `00 00 00 04 00`, an ACK budget of
500 ms, and the supplied 200-ms response budget. A successful first attempt
returns immediately after copying four response bytes; there is no post-read
sleep.

```text
chip_id = (b2 << 24) | (b3 << 16) | (b0 << 8) | b1
family = chip_id >> 8
```

The full unsigned chip ID is stored at context `+0x24`. Exact family comparisons
at `0x180017f61..0x180017f7f` select the 32-bit profile at `+0x28`:

| Chip ID predicate | Algorithm sensor type | Profile |
| --- | --- | --- |
| `(chip_id & 0xffffff00) == 0x00220200` | 0 | 0 |
| `(chip_id & 0xffffff00) == 0x00220700` | 6 | 1 |
| `(chip_id & 0xffffff00) == 0x00220800` | 7 | 2 |
| `(chip_id & 0xffffff00) == 0x00220c00` | 12 | 9 |

These are all successful branches of this chip-identification function. The low
byte is ignored for selection. Do not derive algorithm sensor type from the
low byte of `family`: for example, family `0x2202` selects type 0, not type 2.

A null context returns -1 without a read. Failed reads and unrecognized families
call `FUN_18001b6c8(0, status)` and sleep 100 ms before the next attempt. There
are at most six read attempts; exhaustion returns -1. A successful register read
stores the chip ID even when its family is unknown. The identification function
does not clear or assign the profile on failure; successful selection returns 0.
Each `FUN_18001a604` call itself repeats the same command once only when the
first generic sender result is zero; two zero results become that outer failed
read. The retry budgets are restarted by the second sender invocation.

`device_enable` supplies context `0x18005e790`, dispatches profiles 0, 1, and 2
to `FUN_1800112ac`, and profile 9 to `FUN_1800162ac`. After successful profile
initialization it copies the profile to device context `+0x5c`. Identification,
dispatch, profile-initialization, or subsequent `FUN_18000e138` failure assigns
13 (`0x0d`) to both the global profile and device field. Invalid device arguments
or failed device-context lookup return -1 before those assignments. The value
13 is a failure sentinel, not a successful algorithm sensor type or
profile-table entry.

## Profile-To-Type Table

`GoodixEngineAdapter.dll!ppp_param_init` (`0x180002710`) takes a profile index
and accepts unsigned indices 0 through 12. Larger values return `0x81` without
loading a row. Its table is `0x1800e4590`, with 32-byte rows and 32-bit fields:
profile at `+0x00`, rows at `+0x14`, columns at `+0x18`, and algorithm sensor
type at `+0x1c`. It loads those last three fields into globals `0x180218e54`,
`0x180218e68`, and `0x180218e50`, respectively.

| Profile | Algorithm sensor type | Rows | Columns | Chip family selected by this USB identification path |
| --- | --- | --- | --- | --- |
| 0 | 0 | 88 | 108 | `0x002202xx` |
| 1 | 6 | 64 | 176 | `0x002207xx` |
| 2 | 7 | 54 | 176 | `0x002208xx` |
| 3 | 2 | 112 | 132 | Not selected |
| 4 | 1 | 60 | 128 | Not selected |
| 5 | 8 | 88 | 108 | Not selected |
| 6 | 4 | 64 | 176 | Not selected |
| 7 | 63 | 68 | 118 | Not selected |
| 8 | 62 | 96 | 96 | Not selected |
| 9 | 12 | 88 | 108 | `0x00220cxx` |
| 10 | 10 | 64 | 80 | Not selected |
| 11 | 0 | 88 | 108 | Not selected |
| 12 | 17 | 64 | 80 | Not selected |

Rows without a chip-selection branch do not establish any chip-ID mapping or
hardware support. Multiple profiles can share an algorithm sensor type. These
are image dimensions from the native profile table, not physical dimensions.

## Cross-Layer Selection Path

USB `OnGetSensorInfo` (`FUN_1800222a0`) copies device context `+0x5c` to offset
`+0x28` in the 48-byte sensor-info response. Engine `_GetSensorINFO`
(`FUN_18001d3b0`) obtains that response via IOCTL `0x442004`, requiring exactly
48 returned bytes. `EngineAdapterAttach` (`FUN_18001e5b0`) writes the response
at engine context `+0x48`, placing its profile at context `+0x70`.

`_LoadAlgorithmLibrary2` (`FUN_180030c40`) copies that profile into global
`0x1800f5ce0` and passes a local copy to `_Attach_E` (`FUN_18002b240`).
`_Attach_E` calls `ppp_param_init` with the same profile. It does not reinterpret
the profile as an algorithm type.

`preprocessor_init` (`0x1800027b0`) packs the loaded algorithm type into chip
metadata starting at bit 3, with row and column fields starting at bits 14 and
23. The algorithm-side subtype extraction is `(packed >> 3) & 0x3f`; see
`functions/FUN_180037c80.md`. Thus profile 9's table value 12 is the algorithm
sensor type, whereas the USB/engine transport field remains profile 9.

## Dell 600N5 Profile-9 Branch

### Binary Identity

Dell **600N5**, package **3.20.30.130, A05**, contains the PID533C, PID538D,
and PID532D branches under `drivers/production/Windows10-x64/`. All DLL
addresses in this section use image base `0x180000000`. Unqualified Wbdi
addresses below refer to PID533C; reference functions refer to 2.0.310.900.

- [Dell package details](https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=600n5)
- [Package download](https://dl.dell.com/FOLDER06350043M/3/Goodix-Fingerprint-Sensor-Driver_600N5_WIN64_3.20.30.130_A05_02.EXE)
- Package SHA-256: `25798a0b2a249a1850519d86146c0a5204aef18d0c2430f00ae10c7b6e629280`

| Branch | INF DriverVer | DLL | SHA-256 |
| --- | --- | --- | --- |
| PID533C | `06/08/2020,3.0.37.600` | `Wbdi.dll` | `89f4d9fa141e5e8b118b4a3f1c1b1de0a90b525809bdb9ea5a719543b8be4068` |
| PID533C | same | `GoodixEngineAdapter.dll` | `0ccc561df01a01643ba619bc2f43ccbf4072a0b35180755fd4b00dc055792e32` |
| PID538D | `06/08/2020,3.0.38.600` | `Wbdi.dll` | `82e710309a3e028e2e4e84506a40888918f1cc0d3af0ddb8fe5ce2f4fb80b60a` |
| PID538D | same | `GoodixEngineAdapter.dll` | `9785a98a5ad64e101476cce25a5621d4ca78bbdcacc1f60f7eb5d37b40687695` |
| PID532D | `06/08/2020,3.0.39.300` | `Wbdi.dll` | `257feb9c9c486fe972b1b03978906e2844e08bcb69ff5999c81cc1e3e58169ee` |
| PID532D | same | `GoodixEngineAdapter.dll` | `ea75f3aa468c82a88467988dbb433c30fe73361cd875de6c54d9c559d1025a3c` |

The comparison PID5395 binary belongs to Dell **6CPKF**, package
**2.1.32.400, A03**, with INF DriverVer `01/18/2019,2.1.32.400` and an
explicit `USB\VID_27C6&PID_5395&MI_00` match:

- [Dell package details](https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=6cpkf)
- [Package download](https://downloads.dell.com/FOLDER05491034M/4/Goodix-Fingerprint-Sensor-Driver_6CPKF_WIN64_2.1.32.400_A03_02.EXE)
- Package SHA-256: `b283e29faaae295f8bc1d5b56bd3932bec3423969aa23be63a469d3f976010a4`
- `drivers/production/Windows10-x64/usbinterface.dll` SHA-256:
  `4bf0d283eb226e7e8d9cfeb42cb593872bb00d5a4d05a92fe295a0be8ebc1f9e`

The 2.0.310.900 binary identities are in
[REFERENCE-DRIVER.md](REFERENCE-DRIVER.md). The engine version strings are:

| Engine | Installed algorithm string | Installation site |
| --- | --- | --- |
| 600N5 PID533C/PID538D | `Milan_v_3.01.09.11` | `FUN_180055e90`, object `+0x88b4`, source `0x1800dc0e0` |
| 600N5 PID532D | `Milan_v_3.01.09.11` | `FUN_180056090`, object `+0x88b4` |
| 2.0.310.900 | `Milan_v_3.01.09.10.50` | `FUN_180037c80`, object `+0x88b4` |

### Selected GF5288 Descriptor

The addresses in this subsection are PID533C `Wbdi.dll` addresses.
Loader `FUN_18004ef70` passes `chip_id >> 8` to `FUN_18005030c`; the shift
and call are at `0x18004f44e..0x18004f451`. The selector walks the pointer
list at `0x1801481e0`, comparing its argument with the dword at property
`+0x3c`. Family `0x220c`, including chip `0x220ca1`, selects object
`0x180149440`, whose `+0x20` points to property record `0x1801491e0`:

| Property field | Type | Value |
| --- | --- | --- |
| `+0x00` | dword | descriptor index/profile 9 |
| `+0x04` | dword | class 2 |
| `+0x08` | dword | logic-series 2 |
| `+0x0c` | string | `GF5288` |
| `+0x3c` | dword | chip family `0x220c` |
| `+0x40`, `+0x41` | unsigned bytes | columns 108, rows 88 |
| `+0x44` | dword | FDT byte count 24 |
| `+0x48` | dword | OTP byte count 32 |

Constructor `FUN_180059800` calls `FUN_1800510f4`, retaining the selected
object at fingerprint-context `+0x20`. Object `+0x28` points to fingerprint
method table `0x180149330`:

| Method slot | Function and role |
| --- | --- |
| `+0x38` | `FUN_180059a10`, `GetChipConfig` |
| `+0x40` | `FUN_1800512c0`, `FpMcuDownloadChipConfig` |
| `+0x50` | `FUN_180059930`, OTP validation through `FUN_18005fe84` |
| `+0x70` | `FUN_18005f030`, image acquisition through `FUN_18005f8d0` |
| `+0x78` | `FUN_180050d80`, raw image byte count |
| `+0x88` | `FUN_18005ece0`, manual FDT acquisition |
| `+0xa0` | `FUN_18005da80`, up-base translation from a down event |
| `+0xa8` | `FUN_18005d9a0`, down-base translation |
| `+0xb0`, `+0xb8` | `FUN_180051a60`, `FUN_180051bc0`, down/up arm |

The loader passes property `+0x08` to `FUN_180066a44`. Value 2 selects
HV-series logic descriptor `0x180149e10`, constructed by
`FUN_18006b500 -> FUN_180065fac`. The logic context retains fingerprint
context at `+0x50`, fingerprint methods at `+0x58`, and properties at
`+0x68`. Its event table is `0x180149dd8`.

The same GF5288 property record and profile-9 branch exist in PID538D and
PID532D. Selection within each DLL still depends on chip family, not its
containing PID directory. The
[GM168SEC transport contract](GM168SEC-533C-TRANSPORT-CONTRACT.md) owns the
533C transport and chip-ID request.

### Profile Publication To The Engine

PID533C `Wbdi.dll!FUN_18006fed0` dispatches IOCTL `0x442004` to
`FUN_180071604` (`ReqOnGetSensorAttribute`). The latter publishes a 24-byte
sensor-attribute response: selected property index at byte `+4`, rows at
`+5`, columns at `+6`, and zero at `+0x17`.

In PID533C `GoodixEngineAdapter.dll`, `_GetSensorAttribute`
(`FUN_18000abe0`) obtains that response for `AlgCreateInit`
(`FUN_18003c3a0`). Configuration callbacks `FUN_18000dcf0` and
`FUN_18000df90`, supplied by `FUN_18000dce0`, retain its profile byte.
Response byte `+0x17 == 0` selects the software-context table at
`0x1800f7350` through `FUN_18001e530 -> FUN_180034ee0`. Its first callback,
`FUN_18000e400`, copies the configuration and calls `ppp_param_init` with
that profile byte.

PID533C engine `ppp_param_init` is `0x1800544f0`, with 32-byte rows at
`0x1800db6b0`. Profile 9 selects `0x1800db7d0`; its eight dwords are
`[9, 1, 0, 0, 800, 88, 108, 12]`. Row fields `+0x14`, `+0x18`, `+0x1c`
populate rows `0x18013aee0`, columns `0x18013aee4`, and algorithm type
`0x18013aee8`. The Wbdi copy of `ppp_param_init` is `0x180098250`, with
the same profile-9 row at `0x180129280`.

| Binary | `ppp_param_init` | Profile-9 row |
| --- | --- | --- |
| 600N5 PID538D Wbdi | `0x180098250` | `0x1801294c0` |
| 600N5 PID532D Wbdi | `0x180098640` | `0x180129550` |
| 2.0.310.900 engine | `0x180002710` | `0x1800e46b0` |

These rows have the same eight dword values. The 6CPKF PID5395 USB path
also selects profile 9 for family `0x220c` in `FUN_180015e48`, then
`FUN_180013c7c` dispatches it to `FUN_180005380`.

### Shared Calibration And Image Contracts

PID533C `Wbdi.dll!FUN_18005fe84` requires 32 OTP bytes and checks byte 25
against the complemented CRC of `otp[0..24]` followed by `otp[26..31]`.
Its helper `FUN_18003baac` and table `0x1800e7330` implement the same
zero-initialized polynomial-`0x07` CRC as the
[reference OTP owner](functions/usbinterface-FUN_180004a40.md).
The 256 table bytes match the reference table and
`device/calibration.c:otp_hash_table`. The Wbdi verifier returns 1 on
success and 0 on failure; the reference verifier uses zero for success.

`FUN_18005df70` supplies unsigned-word TCODE, packed high/low DAC and
five-bit-difference arithmetic corresponding to that reference note. In
the selected fingerprint context, outputs occupy:

| Offset | Word |
| --- | --- |
| `+0x68` | raw scaled down difference, zero for zero five-bit OTP difference |
| `+0x6a` | TCODE |
| `+0x88` | low DAC |
| `+0x90` | high DAC |
| `+0x98` | scaled FDT difference |

Its invalid-packed-DAC branch writes literal high `0x97` and low `0xd0`.
The reference owner's high-DAC fallback instead reads its retained global,
as described in that note. `FUN_18005de1c` separately writes down/up/image/
navigation thresholds at `+0x80/+0x82/+0x84/+0x86`; zero five-bit difference
produces 13/11/200/40. `GetBrokenImage` (`FUN_18004b020`) selects
`0xc83 / TCODE` for property class 2, index 9, using unsigned division only
when TCODE is nonzero.

The selected image callback `FUN_18005f030` writes word `0x1006` to request
parameters `+0x10` and DAC count 1 at `+0x12`. `FUN_18005f8d0` therefore
builds four bytes: flags, HV, DAC low, DAC high. TX enabled/disabled gives
`0x01/0x81`, with `0x40` for a finger image; HV enabled/disabled gives
`6/0x10`. The shared payload layout and reference caller are documented in
[the base-acquisition owner](functions/usbinterface-FUN_180015c60.md#image-command-producer).
Unlike this Wbdi index-9 selection's literal 6, the reference producer reads
its enabled HV byte from configuration `+0x426`.

`FUN_180050d80` uses the selected property dimensions to return
`108*88*3/2 + 4 = 14260` raw bytes. Image parsing follows
`FUN_180050e10 -> FUN_18004adb0 -> FUN_1800529b0`; property index 9 selects
unpacker `FUN_180052834`. Its six-byte/four-word order is exactly the
[reference unpacker contract](functions/usbinterface-FUN_180009a64.md),
including the 14256-byte pixel input after removing four overhead bytes.
Current counterparts are `device/calibration.c:goodix_device_parse_otp`,
`device/commands.c:goodix_build_image_request`, and
`device/image.c:goodix_device_decode_image`.

### Configuration Source And Low-DAC Predicate

PID533C `GetChipConfig` (`Wbdi.dll!FUN_180059a10`) allocates 256 bytes and
copies source `0x180149230` (file offset `0x147a30`). All source bytes,
including trailer `61 4f`, equal the reference profile-9 template
`0x18005fca0` and `device/calibration.c:default_config`. PID538D and PID532D
use the same source bytes at VA `0x180149230`; 6CPKF PID5395 uses them at
`0x18006dc60`. Section/tag layout and checksum arithmetic are owned by
[the reference configuration note](functions/usbinterface-FUN_180005094.md).
The source trailer is repaired to `0x0f53` before calibration edits.

`LogicDownloadChipConfig` (`FUN_1800641a0`) requires nonzero logic-context
OTP-valid dword `+0xbc`. It calls selected method `+0x38` with retained OTP
and property OTP length, then method `+0x40` with the returned buffer and
length. It frees the allocated configuration after the downloader returns,
on both download success and failure, and returns that result.

`GetChipConfig` parses calibration, copies and repairs the source, patches
nonzero TCODE, patches the down threshold, then conditionally patches low
DAC in sections 2 and 3. Define the packed inputs from a valid 32-byte OTP:

```text
V = otp[17] != 0 && otp[22] != 0 && otp[31] != 0
if V:
    H = ((otp[17] << 8) | otp[22]) & 0x1ff
    L = ((otp[17] & 0x40) << 2) | otp[31]
else:
    H = 0x97
    L = 0xd0
```

The Wbdi patch predicate is **`L != 0xd0 && H != 0x97`**, not `V`.
At `0x180059bd5..0x180059be5`, either 16-bit equality branches directly
past both patches. Helpers `FUN_180056df0` and `FUN_1800571f0` select
sections 2 and 3 through `FUN_180050120`, replacing tag `0x0220` with
`uint16((L << 4) | 8)` and repairing the checksum.

The reference `FUN_180005094` instead tests packed-valid byte
`0x1800606fe`, set from `V` by `FUN_180004a40`. The 6CPKF PID5395 parser
`FUN_1800059d4` and configuration owner `FUN_180006048` use packed-valid
byte `0x18006f01e` in the same way. PID538D `FUN_180059a10` and PID532D
`FUN_180059de0` share the two-sentinel Wbdi predicate.

For the same valid OTP, source template and other calibration fields, the
resulting configurations differ exactly when:

```text
V && (L == 0xd0 || H == 0x97) && L != 0xd8
```

`L == 0xd0` requires OTP byte 31 equal to `0xd0` and bit 6 of byte 17
clear. `H == 0x97` requires byte 22 equal to `0x97` and bit 0 of byte 17
clear. The additional `L != 0xd8` term excludes an executed patch that
writes the unchanged template value `0x0d88`. The two LE16 value locations
are configuration offsets `0xcb..0xcc` and `0xe7..0xe8`; checksum occupies
`0xfe..0xff`. A differing body need not produce a differing modular checksum.
The current `goodix_device_patch_config` uses `dac_from_otp`, corresponding
to the packed-valid predicate.

### Configuration Response Status

The selected Wbdi downloader `FUN_1800512c0` passes the configuration to
`FUN_180060994` with command `0x90`, a zero-initialized two-byte response
buffer and response capacity 2. It compares the first response byte with
exactly 1 (`0x1800513c8`). Equality returns the transport result; inequality
logs the status and returns 0. Successful transport completion and status
byte 1 are therefore both required.

PID538D uses the same function address and predicate; PID532D uses
`FUN_180051690`. The reference `Dlcfg` (`FUN_18001aed8`) and receiver
`FUN_18001a7ec` instead complete category 9 / command 0 without testing
that status byte, as detailed in
[configuration response publication](functions/usbinterface-FUN_180005094.md#configuration-response-publication).
The 6CPKF PID5395 equivalents are `FUN_180017720` and `FUN_180017038`,
with sender `FUN_1800186e8`; they also use status-agnostic completion.
The current command-0 completion in `device/transport.c` follows the
reference rule. A status byte of 1 satisfies both branches' predicates.

### Zero-Difference FDT Event Failure

The Wbdi down-base callback `FUN_18005d9a0` copies the 24-byte input and
calls `FUN_18005dcac`. Each LE16 sample becomes
`uint16((sample & 0xfffe)*0x80 + (sample >> 1))`. The up-base wrapper
`FUN_18005da80` instead requires fingerprint-context word `+0x68` to be
nonzero, before copying or calling `FUN_18005dce8`. The word was produced
by `FUN_18005df70`:

```text
diff = (otp[17] >> 1) & 31
D = diff == 0 ? 0 : (((diff + 5)*50) >> 4) / 3
```

At `0x18005db0e..0x18005db12`, zero logs `Fdt diff not set` and returns 0.
For nonzero `D`, `FUN_18005dce8` duplicates `(sample >> 1) + D` into each
word using `uint16(value*0x100 | value)`; untouched channels receive
`uint16((D-2)*0x100 | (D-2))`. That arithmetic helper contains zero-`D`
fallback arguments, but the selected wrapper rejects zero before invoking it.

The failure is on the selected down-event path:

1. Loader `FUN_18004ef70` uses MCU descriptor `0x18014a020` through pointer
   `0x1801481a0`. Its `+0x18` callback `FUN_18007bff0` (`McuSetFp`) receives
   the selected GF5288 object and fingerprint context. It stores properties
   at MCU-context `+0x98`, fingerprint methods at `+0xa0`, parser hooks at
   `+0xa8`, and fingerprint context at `+0xb0`.
2. Descriptor `+0x30` selects parser table `0x180149ed0`. Its first callback
   is `FUN_18007a9f0` (`McuParseFdt`), called for category 3 by packet
   dispatcher `FUN_18007d388`.
3. After interrupt parsing, event bits `0x48` together clear down bit
   `0x08`. A retained down bit selects fingerprint method `+0xa0`, hence
   `FUN_18005da80`, with the touch mask, raw base, selected FDT length and
   allocated translated-base output. Other base-bearing events select
   method `+0xa8`, the down-base translator.
4. A zero callback result logs failure, frees both temporary base buffers,
   clears the entire 32-byte parsed-event record, and returns 0.
5. Dispatcher `FUN_18007d388` tests that return at
   `0x18007d6fc..0x18007d6fe`. Failure takes its logging/exit branch before
   response publication or the logic FDT callback at MCU-context `+0x50`.
   The selected HV logic callback `FUN_18006c970` and its down handler
   `FUN_18006cee4` therefore receive no event. On parser success, that
   down handler consumes the already translated base.

Thus zero five-bit difference suppresses this down-event notification;
the check does not reject the OTP CRC or the manual-base request.
PID538D `FUN_18005da80` and PID532D `FUN_18005de50` share this rejection.

The reference up-base translator `FUN_180004918` instead substitutes
context `+0x318` for zero raw difference and `+0x31a` for untouched
channels. Those defaults are 13 and 11, set by `FUN_180004a40`. Its
[down-event consumer](functions/usbinterface-FUN_180014e10.md) retains the
translated up-base before notification. The 6CPKF PID5395 translator
`FUN_180005894` has the same fallback, reading raw difference
`0x18006f01c` and default context words `+0x318/+0x31a`. Current
`device/calibration.c:goodix_device_generate_fdt_up_base` uses the parsed
down/up defaults without the Wbdi zero-difference rejection.

## Current Driver Boundary

The current `goodix_milan_runtime_subtype_for_chip` accepts only `0x00220cxx`
and publishes subtype 12. Recognizing other table entries for detector labels
does not establish support for their calibration, processing, matching, or
device lifecycle.

See `functions/usbinterface-FUN_180004a40.md` for profile-9 OTP admission and
`functions/usbinterface-FUN_180005094.md` for profile-selected configuration.

Profile-0/type-0 behavior relative to profile 9/type 12 is owned by
[the USB contract](PROFILE0-USB-CONTRACT.md) and
[the engine contract](PROFILE0-ENGINE-CONTRACT.md), with extraction, matching,
study and storage in [the template contract](PROFILE0-MATCH-TEMPLATE-CONTRACT.md).
Shared raw dimensions do not imply shared calibration, capture sequencing,
or preprocessing dispatch.
