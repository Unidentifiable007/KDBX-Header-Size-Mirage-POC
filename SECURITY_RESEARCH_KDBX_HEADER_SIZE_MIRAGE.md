# KDBX Header Parsing Allows Excessive Memory Allocation from Truncated Input

## Summary

During KDBX header parsing, an attacker-controlled field length is passed directly to `new byte[nCount]` before the stream is verified to contain the declared bytes. A 23-byte file can therefore cause KeePass to execute a 1 GiB allocation based solely on an attacker-controlled length field, despite the file containing only one byte of the declared field data.

The problem is not that large values are accepted. It is the ordering: allocation happens before the parser has established that the declared number of bytes is actually present. The attacker's declared length reaches the CLR allocator while the stream remains unchecked.

The finding does **not** claim that the KDBX format's maximum field size is itself unsafe. The issue is that the implementation uses the attacker-controlled declared size as an immediate allocation size before establishing that the corresponding data exists.

## Affected Code Path

```text
Load()
 ↓
LoadHeader()
 ↓
ReadHeaderField()  (loop until end-of-header marker)
 ↓
BinaryReaderEx.ReadBytes(attacker-controlled size)
 ↓
MemUtil.Read()
 ↓
new byte[attacker-controlled size]
```

**File:** `KeePassLib/Serialization/KdbxFile.Read.cs`

* `Load()` line ~75 – calls `LoadHeader()`
* `LoadHeader()` line 266 – loops through fields, calls `ReadHeaderField()`
* `ReadHeaderField()` line 319 – reads field size, calls `ReadBytes(cbSize)` with attacker value

**File:** `KeePassLib/Serialization/BinaryReaderEx.cs`

* `ReadBytes()` line 54 – calls `MemUtil.Read()`, validates result only after allocation

**File:** `KeePassLib/Utility/MemUtil.cs`

* `Read()` line 649 – allocates `byte[nCount]` before read loop

## Root Cause

In `ReadHeaderField()`, the sequence is:

```csharp
int cbSize = MemUtil.BytesToInt32(brSource.ReadBytes(4));  // Attacker-controlled
if(cbSize < 0) throw new FormatException(...);            // Only negative check
byte[] pbData = brSource.ReadBytes(cbSize);               // <- Calls allocation
```

`BinaryReaderEx.ReadBytes()` passes `cbSize` to `MemUtil.Read()`:

```csharp
byte[] pb = MemUtil.Read(m_s, nCount);  // nCount is attacker-controlled
```

`MemUtil.Read()` allocates immediately:

```csharp
byte[] pb = new byte[nCount];  //Allocation happens here
int iOffset = 0;
while(nCount > 0)
{
    int iRead = s.Read(pb, iOffset, nCount);
    if(iRead == 0) break;  
    iOffset += iRead;
    nCount -= iRead;
}
```

The allocation is performed before the parser has established that the declared number of bytes is available in the input. EOF/short-read detection occurs only after the allocation has been attempted.

This is fundamentally an ordering problem:

```text
attacker-controlled length → allocator → read → EOF detection
```

rather than:

```text
attacker-controlled length → establish available data → allocate/read → validate
```

## Why the 2 GB Boundary Matters

Field size is read as a 32-bit signed `Int32`, capping positive values at 2,147,483,647 bytes (`0x7FFFFFFF`). The test case uses `0x40000000` (1 GiB), well within this range.

This cap is not a weakness in the finding—it is simply the data type. An attacker can still request hundreds of MB to approximately 2 GB from a substantially smaller file.

The finding does **not** claim that the KDBX format's theoretical maximum field size should be reduced. Legitimate KDBX files may require large header fields. The issue is that a malformed file can declare a very large field without containing the corresponding data, while KeePass uses that unverified declaration directly as an allocation size.

## Minimal Reproduction

**Test file (hex):**

```text
03D9A29A67FB4BB5010004000200000040FF00000000
```

**Structure:**

| Bytes | Hex           | Field         | Value                   |
| ----- | ------------- | ------------- | ----------------------- |
| 0–3   | `03 D9 A2 9A` | Signature 1   | `0x9AA2D903`            |
| 4–7   | `67 FB 4B B5` | Signature 2   | `0xB54BFB67`            |
| 8–11  | `01 00 04 00` | Version       | `0x00040001` (KDBX 4.1) |
| 12    | `02`          | Field ID      | CipherID (`0x02`)       |
| 13–16 | `00 00 00 40` | Declared size | `0x40000000` (1 GiB)    |
| 17    | `FF`          | Field data    | Only 1 byte             |
| 18    | `00`          | Field ID      | End of header           |
| 19–22 | `00 00 00 00` | Size          | 0                       |

**File size:** 23 bytes

**To create the test file (PowerShell):**

```powershell
$hex = "03D9A29A67FB4BB5010004000200000040FF00000000"
$bytes = [byte[]]@(0..($hex.Length/2-1) | ForEach-Object { [convert]::ToByte($hex.Substring($_*2,2), 16) })
[System.IO.File]::WriteAllBytes("test.kdbx", $bytes)
```

When opened, the parser calls `ReadBytes(0x40000000)`. This causes `MemUtil.Read()` to execute `new byte[0x40000000]` while the input file is only 23 bytes and contains only one byte of the declared field data.

The parser subsequently discovers the truncated stream during the read operation and rejects the file.

## Observed Result

Opening the test file in KeePass 2.61.1 (by double-clicking the `.kdbx` file or using File → Open) triggered the normal master-password/key-provider credential dialog. Process memory usage remained normal at this stage.

After entering an arbitrary password and pressing OK, KeePass continued processing the malformed file. Process memory usage increased substantially during header parsing. The file was then rejected with the error:

> The file header is corrupted. Less data than expected could be read from the file.

Closing this error dialog did **not** immediately restore memory usage to its previous level. Elevated memory consumption persisted while KeePass remained open. Only after completely exiting the KeePass process did memory usage return to normal levels.

This behavior is consistent with the identified code path: `MemUtil.Read(stream, 0x40000000)` is reached during header parsing before the truncated-field error is reported, and in testing the elevated process memory usage persisted after the error dialog was closed and returned to normal only after the KeePass process was exited.

## Observed UI / Reproduction Flow

```text
Double-click malicious .kdbx file
 ↓
KeePass displays Master Password / Key Provider dialog
 (Memory usage normal)
 ↓
User enters arbitrary password/selects key provider, presses OK
 (User submits an arbitrary credential)
 ↓
KeePass processes malformed KDBX header
 ↓
Large memory allocation occurs during header field parsing
 (Process memory usage spikes)
 ↓
KeePass displays corruption error dialog
 ↓
User closes error dialog
 (Memory usage remains elevated)
 ↓
KeePass stays open
 (Elevated memory persists)
 ↓
Exit KeePass completely
 (Process memory released, usage returns to normal)
```

## Why Successful Authentication Is Not Required

The vulnerable allocation does not require successful database authentication.

In the observed workflow, KeePass presents the normal credential dialog before the malformed-file error. The password entered does not need to be correct. Pressing OK with an arbitrary or incorrect value allows processing to continue.

The attacker-controlled header length is then processed during `LoadHeader()`, and the file is rejected as corrupted without requiring successful authentication.

The important distinction is that the allocation is triggered by the attacker-controlled header field size, not by the outcome of authentication. Successful authentication is not a prerequisite.

The victim must still interact with the credential dialog, so this should not be interpreted as claiming that no user interaction is required.

## Security Impact

The attack requires the victim to open a malicious `.kdbx` file, for example by double-clicking it. The normal credential dialog appears and the victim submits a credential, but the supplied password does not need to be correct.

The attacker can cause KeePass to attempt an allocation of up to approximately 2 GiB from a substantially smaller malformed file.

Depending on available memory and system conditions, this can cause:

* significant memory pressure;
* allocation failure;
* process failure or termination;
* system degradation.

No data corruption, code execution, confidentiality impact, or authentication bypass was observed. The malformed file is eventually rejected.

**Potential weakness classification:**

* CWE-789 — Memory Allocation with Excessive Size Value
* CWE-400 — Uncontrolled Resource Consumption

The issue is primarily an availability/resource-consumption concern.

## Parser Validation and Ordering

> The parser eventually rejects the file ≠ the parser safely handles the file.

The rejection occurs **after** the allocation, not before it.

The relevant distinction is:

```text
Safer:
attacker-controlled length
        ↓
establish that the declared data is available
        ↓
allocate/read
        ↓
validate
```

versus the current behavior:

```text
attacker-controlled length
        ↓
allocate complete declared size
        ↓
read stream
        ↓
discover EOF / short read
        ↓
reject
```

The malformed input therefore receives the expensive allocation side effect before the parser establishes that the claimed data actually exists.

## Possible Mitigation

The finding does not require reducing the KDBX specification's theoretical maximum field size.

Possible implementation approaches include:

* Avoiding unconditional allocation of the complete attacker-declared size before the corresponding data has been established as available.
* Checking the remaining stream length before allocation where the stream supports reliable length information.
* Using bounded or incremental reads where the stream length is unavailable.
* Applying an implementation-level safety limit if appropriate, while preserving support for legitimate large fields where required.
* Restructuring the read helper so that attacker-controlled lengths do not automatically translate into equally sized allocations before the input has been sufficiently validated.

`Stream.Length` is not a universal solution because some stream types may not provide a known length. The mitigation therefore depends on the characteristics of the input stream.

The key security property is that an attacker-controlled declaration of a large field should not, by itself, be sufficient to force an allocation of the entire declared size when the corresponding data is not present.

## Comparison with KeePassXC

The same malformed KDBX input was also tested with KeePassXC.

KeePassXC rejected the file during header parsing with an error indicating that the declared field size did not match the available data. No corresponding large memory increase was observed during this test.

This comparison is not intended to establish that KeePassXC's implementation is necessarily the only or correct mitigation. It demonstrates that the malformed length can be detected and rejected during parsing rather than treating the attacker's declared size as proof that the corresponding data exists.

## Source References

| Component            | File                                         | Method              | Line |
| -------------------- | -------------------------------------------- | ------------------- | ---- |
| Header parsing start | `KeePassLib/Serialization/KdbxFile.Read.cs`  | `Load()`            | ~75  |
| Header field parsing | `KeePassLib/Serialization/KdbxFile.Read.cs`  | `LoadHeader()`      | ~266 |
| Field size read      | `KeePassLib/Serialization/KdbxFile.Read.cs`  | `ReadHeaderField()` | ~319 |
| Allocation call      | `KeePassLib/Serialization/BinaryReaderEx.cs` | `ReadBytes()`       | ~54  |
| Allocation point     | `KeePassLib/Utility/MemUtil.cs`              | `Read()`            | ~649 |

## Reproduction Environment

* **KeePass Version:** 2.61.1
* **OS:** Windows 11
* **Test Type:** Isolated VM
* **Input File:** 23 bytes
* **Input Hex:** `03D9A29A67FB4BB5010004000200000040FF00000000`
* **Declared Field Size:** 1 GiB (`0x40000000`)
* **Actual Field Data:** 1 byte
* **Result:** Parser attempts the attacker-controlled allocation before detecting the truncated stream

## Conclusion

A 23-byte malformed KDBX file causes KeePass to execute a 1 GiB array allocation based on an attacker-controlled field length, even though the file contains only one byte of the declared field data.

The allocation occurs before EOF/short-read detection and before the parser establishes that the declared data exists.

The issue is therefore not that KeePass supports large KDBX header fields. The security-relevant behavior is that an attacker-controlled length can cause a large memory allocation independently of the amount of corresponding data actually supplied by the attacker.

The attack requires the victim to open the malicious KDBX file and submit the credential dialog, but successful authentication is not required. The observed impact is excessive memory consumption with potential availability/resource-consumption consequences.

**Potential classification:** CWE-789 / CWE-400 — excessive memory allocation / uncontrolled resource consumption.
