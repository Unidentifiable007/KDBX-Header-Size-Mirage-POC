# KDBX Header Size Mirage

## Summary

During KDBX header parsing, an attacker-controlled field length is passed directly to `new byte[nCount]` before the stream is verified to contain the declared bytes. This allows a 23-byte file to request a 1 GiB allocation—a 46.7 million:1 amplification ratio.

The problem is not that large values are accepted. It's the ordering: allocation happens before EOF is discovered, not after. The attacker's declared length reaches the CLR allocator while the stream remains unchecked.

## Affected Code Path

```
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
- `Load()` line ~75 – calls `LoadHeader()`
- `LoadHeader()` line 266 – loops through fields, calls `ReadHeaderField()`
- `ReadHeaderField()` line 319 – reads field size, calls `ReadBytes(cbSize)` with attacker value

**File:** `KeePassLib/Serialization/BinaryReaderEx.cs`
- `ReadBytes()` line 54 – calls `MemUtil.Read()`, validates result only after allocation

**File:** `KeePassLib/Utility/MemUtil.cs`
- `Read()` line 649 – allocates `byte[nCount]` before read loop

## Root Cause

In `ReadHeaderField()`, the sequence is:

```csharp
int cbSize = MemUtil.BytesToInt32(brSource.ReadBytes(4));  // Attacker-controlled
if(cbSize < 0) throw new FormatException(...);            // Only negative check
byte[] pbData = brSource.ReadBytes(cbSize);               // <- Calls allocation
```

`BinaryReaderEx.ReadBytes()` passes cbSize to `MemUtil.Read()`:

```csharp
byte[] pb = MemUtil.Read(m_s, nCount);  // nCount is attacker-controlled
```

`MemUtil.Read()` allocates immediately:

```csharp
byte[] pb = new byte[nCount];  // <- Allocation happens here
int iOffset = 0;
while(nCount > 0)
{
    int iRead = s.Read(pb, iOffset, nCount);
    if(iRead == 0) break;  // <- EOF discovered only during read loop
    iOffset += iRead;
    nCount -= iRead;
}
```

The allocation happens before the read loop discovers EOF. By the time `ReadBytes()` detects the short read, the CLR has already processed the allocation request.

This is fundamentally an ordering problem: attacker-controlled length → allocator → read → EOF detection.

## Why the 2 GB Boundary Matters

Field size is read as a 32-bit signed int32, capping positive values at 2,147,483,647 bytes (0x7FFFFFFF). The test case uses 0x40000000 (1 GiB), well within this range.

This cap is not a weakness in the finding—it's simply the data type. An attacker can still request hundreds of MB to ~2 GB from a tiny file.

## Minimal Reproduction

**Test file (hex):**
```
03D9A29A67FB4BB5010004000200000040FF00000000
```

**Structure:**

| Bytes | Hex | Field | Value |
|-------|-----|-------|-------|
| 0–3 | `03 D9 A2 9A` | Signature 1 | 0x9AA2D903 |
| 4–7 | `67 FB 4B B5` | Signature 2 | 0xB54BFB67 |
| 8–11 | `01 00 04 00` | Version | 0x00040001 (KDBX 4.1) |
| 12 | `02` | Field ID | CipherID (0x02) |
| 13–16 | `00 00 00 40` | Declared size | 0x40000000 (1 GiB) |
| 17 | `FF` | Field data | Only 1 byte |
| 18 | `00` | Field ID | End of header |
| 19–22 | `00 00 00 00` | Size | 0 |

**File size: 23 bytes**

**To create the test file (PowerShell):**
```powershell
$hex = "03D9A29A67FB4BB5010004000200000040FF00000000"
$bytes = [byte[]]@(0..($hex.Length/2-1) | ForEach-Object { [convert]::ToByte($hex.Substring($_*2,2), 16) })
[System.IO.File]::WriteAllBytes("test.kdbx", $bytes)
```

When opened, the parser calls `ReadBytes(0x40000000)` before discovering only 1 byte exists. This triggers a gigabyte allocation request from a 23-byte file.

## Observed Result

Opening the test file in KeePass 2.61.1 (by double-clicking the .kdbx file or using File → Open) triggered the normal master-password/key-provider credential dialog. Process memory usage remained normal at this stage.

After entering an arbitrary password and pressing OK in the credential dialog, KeePass continued processing the malformed file. Process memory usage increased substantially during header parsing. The file was then rejected with the error:

> The file header is corrupted. Less data than expected could be read from the file.

Closing this error dialog did NOT immediately restore memory usage to its previous level. Elevated memory consumption persisted while KeePass remained open. Only after completely exiting the KeePass process did memory usage return to normal levels.

This confirms the code path: `MemUtil.Read(stream, 0x40000000)` is called after the credential dialog but before the file-rejection error, and in testing the elevated process memory usage persisted after the error dialog was closed and returned to normal only after the KeePass process was exited.

## Observed UI / Reproduction Flow

```
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

The vulnerable allocation does not require successful password authentication. In the observed workflow above, KeePass presents the normal credential dialog before the malformed-file error. The password entered does not need to be the correct database password. Pressing OK with an arbitrary or incorrect value allows processing to continue. The attacker-controlled header length is then processed during `LoadHeader()`, and the file is rejected as corrupted without requiring successful authentication.

The important distinction: the allocation is triggered by the attacker-controlled header field size, not by the outcome of authentication. Successful authentication is not a prerequisite.

## Security Impact

Requires victim to open the malicious .kdbx file (for example, by double-clicking). The normal credential dialog appears and the user enters a password, but successful authentication is not required to trigger the allocation. Pressing OK with any value allows processing to continue and the vulnerable header parsing to proceed.

Results in excessive memory allocation during header parsing, potentially causing:
- memory pressure / process failure / system degradation

No data corruption, code execution, or auth bypass. File is eventually rejected.

## Parser Validation and Ordering

"The parser eventually rejects the file" ≠ "The parser safely handles the file"

Rejection comes after the allocation, not before. The ordering is the issue: validate → check → allocate (safe) vs. allocate → read → validate (current).

## Possible Fix Direction

Consider approaches such as:

- Validating a sensible maximum header field size before allocation
- Checking remaining stream length where possible before calling `ReadBytes()`
- Restructuring the read implementation to avoid trusting attacker-controlled sizes directly for allocation

The exact approach would depend on the KDBX specification requirements and legitimate header field sizes in real-world use.

## Source References

| Component | File | Method | Line |
|-----------|------|--------|------|
| Header parsing start | `KeePassLib/Serialization/KdbxFile.Read.cs` | `Load()` | ~75 |
| Unauthenticated parse | `KeePassLib/Serialization/KdbxFile.Read.cs` | `LoadHeader()` | 266 |
| Field size read | `KeePassLib/Serialization/KdbxFile.Read.cs` | `ReadHeaderField()` | 319 |
| Allocation call | `KeePassLib/Serialization/BinaryReaderEx.cs` | `ReadBytes()` | 54 |
| Allocation point | `KeePassLib/Utility/MemUtil.cs` | `Read()` | 649 |

## Reproduction Environment

- **KeePass Version:** 2.61.1
- **OS:** Windows 11
- **Test Type:** Isolated VM
- **Input File:** 23 bytes (hex: `03D9A29A67FB4BB5010004000200000040FF00000000`)
- **Declared Field Size:** 1 GiB (0x40000000)
- **Result:** Parser attempts allocation before detecting truncated stream

## Conclusion
A 23-byte file triggers a 1 GiB allocation request, an approximately 46.7-million-to-1 ratio between input size and requested allocation. before successful authentication is established. The allocation happens before EOF is detected.

Also tried this in KeyPassXC but it rejected the file stating what field size it was expecting but only seeing a tiny one, no increased allocation was observed.
Possible review points:
1. Is this allocation-before-validation ordering intentional?
2. Is a reasonable max field size appropriate?
3. Could stream length be checked before `ReadBytes()`?
4. Does this pattern exist in other parsers?

