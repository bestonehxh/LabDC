/// MS-FSCC information structures for QUERY_INFO and QUERY_DIRECTORY.
enum FileInfo {
    /// FileBasicInformation (4): four times, attributes, reserved = 40 bytes.
    static func basic(_ t: SMB2FileTimes) -> [UInt8] {
        var b: [UInt8] = []
        b.put64(t.creation)
        b.put64(t.lastAccess)
        b.put64(t.lastWrite)
        b.put64(t.change)
        b.put32(t.attributes)
        b.put32(0)
        return b
    }

    /// FileStandardInformation (5): AllocationSize, EndOfFile, NumberOfLinks, DeletePending,
    /// Directory, Reserved(2) = 24 bytes.
    static func standard(_ t: SMB2FileTimes, isDirectory: Bool, deletePending: Bool = false) -> [UInt8] {
        var b: [UInt8] = []
        b.put64(t.allocationSize)
        b.put64(t.endOfFile)
        b.put32(1)
        b.append(deletePending ? 1 : 0)
        b.append(isDirectory ? 1 : 0)
        b.put16(0)
        return b
    }

    /// FileNameInformation / FileNormalizedNameInformation: FileNameLength(4) | FileName.
    static func name(_ n: String) -> [UInt8] {
        let u = UTF16LE.encode(n)
        var b: [UInt8] = []
        b.put32(UInt32(u.count))
        b += u
        return b
    }

    /// FileAllInformation (18): Basic(40) Standard(24) Internal(8) Ea(4) Access(4) Position(8)
    /// Mode(4) Alignment(4) Name(4+n).
    static func all(_ t: SMB2FileTimes, isDirectory: Bool, index: UInt64, access: UInt32, name n: String) -> [UInt8] {
        var b = basic(t) + standard(t, isDirectory: isDirectory)
        b.put64(index)
        b.put32(0)            // EaSize
        b.put32(access)
        b.put64(0)            // CurrentByteOffset
        b.put32(0)            // Mode
        b.put32(0)            // AlignmentRequirement (byte)
        b += name(n)
        return b
    }

    /// FileNetworkOpenInformation (34): four times, AllocationSize, EndOfFile, attributes, reserved = 56 bytes.
    static func networkOpen(_ t: SMB2FileTimes) -> [UInt8] {
        var b: [UInt8] = []
        b.put64(t.creation)
        b.put64(t.lastAccess)
        b.put64(t.lastWrite)
        b.put64(t.change)
        b.put64(t.allocationSize)
        b.put64(t.endOfFile)
        b.put32(t.attributes)
        b.put32(0)
        return b
    }

    /// FileAttributeTagInformation (35): FileAttributes, ReparseTag.
    static func attributeTag(_ t: SMB2FileTimes) -> [UInt8] {
        var b: [UInt8] = []
        b.put32(t.attributes)
        b.put32(0)
        return b
    }

    /// FileStreamInformation (22): the unnamed data stream of a file; nothing for a directory.
    static func streams(_ t: SMB2FileTimes, isDirectory: Bool) -> [UInt8] {
        if isDirectory { return [] }
        let n = UTF16LE.encode("::$DATA")
        var b: [UInt8] = []
        b.put32(0)
        b.put32(UInt32(n.count))
        b.put64(t.endOfFile)
        b.put64(t.allocationSize)
        b += n
        return b
    }

    static func u32(_ v: UInt32) -> [UInt8] {
        var b: [UInt8] = []
        b.put32(v)
        return b
    }

    static func u64(_ v: UInt64) -> [UInt8] {
        var b: [UInt8] = []
        b.put64(v)
        return b
    }

    /// The fixed part of each class, below which the answer is STATUS_INFO_LENGTH_MISMATCH.
    static func minimumSize(_ cls: UInt8) -> Int {
        switch cls {
        case FileInfoClass.basic: 40
        case FileInfoClass.standard: 24
        case FileInfoClass.all: 100
        case FileInfoClass.networkOpen: 56
        case FileInfoClass.name, FileInfoClass.normalizedName: 4
        case FileInfoClass.internal, FileInfoClass.position: 8
        case FileInfoClass.attributeTag: 8
        default: 4
        }
    }

    // MARK: directory entries

    /// One QUERY_DIRECTORY entry of class `cls` (MS-FSCC §2.4), NextEntryOffset left 0.
    /// Returns nil for classes that are not implemented.
    static func directoryEntry(cls: UInt8, name n: String, times t: SMB2FileTimes, fileID: UInt64) -> [UInt8]? {
        let u = UTF16LE.encode(n)
        var b: [UInt8] = []
        b.put32(0)            // NextEntryOffset
        b.put32(0)            // FileIndex
        if cls == FileInfoClass.names {
            b.put32(UInt32(u.count))
            return b + u
        }
        b.put64(t.creation)
        b.put64(t.lastAccess)
        b.put64(t.lastWrite)
        b.put64(t.change)
        b.put64(t.endOfFile)
        b.put64(t.allocationSize)
        b.put32(t.attributes)
        b.put32(UInt32(u.count))
        switch cls {
        case FileInfoClass.directory:
            break
        case FileInfoClass.fullDirectory:
            b.put32(0)        // EaSize
        case FileInfoClass.idFullDirectory:
            b.put32(0)        // EaSize
            b.put32(0)        // Reserved
            b.put64(fileID)
        case FileInfoClass.bothDirectory, FileInfoClass.idBothDirectory:
            b.put32(0)        // EaSize
            b.append(0)       // ShortNameLength
            b.append(0)       // Reserved1
            b.zeros(24)       // ShortName
            if cls == FileInfoClass.idBothDirectory {
                b.put16(0)    // Reserved2
                b.put64(fileID)
            }
        default:
            return nil
        }
        return b + u
    }

    // MARK: file system information

    /// FileFsVolumeInformation (1): VolumeCreationTime(8) SerialNumber(4) LabelLength(4)
    /// SupportsObjects(1) Reserved(1) Label.
    static func fsVolume(label: String, serial: UInt32, created: UInt64) -> [UInt8] {
        let l = UTF16LE.encode(label)
        var b: [UInt8] = []
        b.put64(created)
        b.put32(serial)
        b.put32(UInt32(l.count))
        b.append(0)
        b.append(0)
        return b + l
    }

    /// FileFsSizeInformation (3): Total(8) Available(8) SectorsPerAllocationUnit(4) BytesPerSector(4).
    static func fsSize(total: UInt64, free: UInt64, blockSize: UInt32) -> [UInt8] {
        var b: [UInt8] = []
        b.put64(total)
        b.put64(free)
        b.put32(max(1, blockSize / 512))
        b.put32(512)
        return b
    }

    /// FileFsFullSizeInformation (7): Total(8) CallerAvailable(8) ActualAvailable(8) Sectors(4) BytesPerSector(4).
    static func fsFullSize(total: UInt64, free: UInt64, blockSize: UInt32) -> [UInt8] {
        var b: [UInt8] = []
        b.put64(total)
        b.put64(free)
        b.put64(free)
        b.put32(max(1, blockSize / 512))
        b.put32(512)
        return b
    }

    /// FileFsDeviceInformation (4): DeviceType FILE_DEVICE_DISK (7), Characteristics
    /// FILE_DEVICE_IS_MOUNTED (0x20).
    static func fsDevice() -> [UInt8] { u32(7) + u32(0x20) }

    /// FileFsAttributeInformation (5): attributes (case preserved, Unicode, ACLs, read-only
    /// volume), MaximumComponentNameLength 255, "NTFS".
    static func fsAttribute() -> [UInt8] {
        let n = UTF16LE.encode("NTFS")
        var b: [UInt8] = []
        b.put32(0x0000_0002 | 0x0000_0004 | 0x0000_0008 | 0x0008_0000)
        b.put32(255)
        b.put32(UInt32(n.count))
        return b + n
    }

    /// FileFsSectorSizeInformation (11): 512-byte sectors, 4 KiB physical, flags 0x3
    /// (aligned device / partition), offsets 0 = 28 bytes.
    static func fsSectorSize() -> [UInt8] {
        var b: [UInt8] = []
        b.put32(512)
        b.put32(4096)
        b.put32(4096)
        b.put32(4096)
        b.put32(0x3)
        b.put32(0)
        b.put32(0)
        return b
    }

    /// FileFsObjectIdInformation (8): ObjectId(16) ExtendedInfo(48).
    static func fsObjectID(_ guid: [UInt8]) -> [UInt8] { guid + [UInt8](repeating: 0, count: 48) }
}
