package mm64;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.task.TaskMonitor;

public class Mm64Game {
    public N64Rom mRom;
    public String mBuildName;
    public Mm64Version mVersion;
    public int mDmaDataOff;
    public List<Mm64File> mFiles;

    public Mm64Game(N64Rom rom, boolean loadFs, TaskMonitor monitor) throws Mm64Exception {
        mRom = rom;
        Load();
        mFiles = null;
        if (loadFs)
            mFiles = GetFs(monitor);
    }

    public Mm64Game(byte[] data, boolean loadFs, TaskMonitor monitor) throws Mm64Exception, N64RomException {
        this(new N64Rom(data), loadFs, monitor);
    }

    private void Load() throws Mm64Exception {
        int off = FindBuildNameOffset();
        if (off == -1)
            throw new Mm64Exception("Could Not Find Build Name");

        mDmaDataOff = off + 0x30;
        try {
            BinaryReader br = new BinaryReader(new ByteArrayProvider(mRom.RawRom), false);
            String build = br.readAsciiString(off, 0x30);
            mBuildName = build.replaceAll("\0+$", "").replace('\0', ' ');
            mVersion = Mm64Version.FromString(mBuildName);
        } catch (Exception ex) {
            throw new Mm64Exception("Could Not Read Build Name");
        }
    }

    public int getCodeVrom() {
        switch (mVersion) {
        case Japan10:
            return 0xb5f000;
        case Japan11:
            return 0xb5f000;
        case USADemo:
            return 0xb3d000;
        case USA10:
            return 0xb3c000;
        case Europe10:
            return 0xc8a000;
        case Europe11Debug:
            return 0xc95000;
        case Europe11:
            return 0xc8a000;
        case USADebug:
        default:
            return -1;
        }
    }

    public long getCodeDst() {
        switch (mVersion) {
        case Japan10:
            return 0x800a76a0;
        case Japan11:
            return 0x800a75e0;
        case USADemo:
            return 0x800a6120;
        case USA10:
            return 0x800a5ac0;
        case Europe10:
            return 0x800a5d60;
        case Europe11Debug:
            return 0x800b6ac0;
        case Europe11:
            return 0x800a5fe0;
        case USADebug:
        default:
            return -1;
        }
    }

    public long getGraphOvlCountAddr() {
        switch (mVersion) {
        case Japan10:
            return 0x801B88F0;
        case Japan11:
            return 0x801B8B30;
        case USADemo:
            return 0x801BD2C0;
        case USA10:
            return 0x801BDA60;
        case Europe10:
            return 0x801be1f0;
        case Europe11Debug:
            return 0x80206970;
        case Europe11:
            return 0x801BE590;
        case USADebug:
        default:
            return -1;
        }
    }

    public long getActorOvlTableAddr() {
        switch (mVersion) {
        case Japan10:
            return 0x801a9e60;
        case Japan11:
            return 0x801aa0a0;
        case USADemo:
            return 0x801ae830;
        case USA10:
            return 0x801aefd0;
        case Europe10:
            return 0x801af760;
        case Europe11Debug:
            return 0x801f7510;
        case Europe11:
            return 0x801afb00;
        case USADebug:
        default:
            return -1;
        }
    }

    public long getEffectSS2OvlTableAddr() {
        switch (mVersion) {
        case Japan10:
            return 0x801a9330;
        case Japan11:
            return 0x801a9570;
        case USADemo:
            return 0x801add00;
        case USA10:
            return 0x801ae4a0;
        case Europe10:
            return 0x801aefc0;
        case Europe11Debug:
            return 0x801f69e0;
        case Europe11:
            return 0x801af360;
        case USADebug:
        default:
            return -1;
        }
    }

    private int FindBuildNameOffset() {
        String pattern = "zelda@srd44";
        for (int i = 0x1000; i < mRom.RawRom.length - pattern.length(); i++) {
            boolean valid = true;
            for (int j = 0; j < pattern.length(); j++) {
                if (mRom.RawRom[i + j] != (byte) pattern.charAt(j)) {
                    valid = false;
                    break;
                }
            }
            if (valid)
                return i;
        }

        return -1;
    }

    public List<Mm64File> GetFs(TaskMonitor monitor) {
        List<Mm64File> files = new ArrayList<Mm64File>();
        int filecount = 3; // dmadata file

        ByteBuffer buff = ByteBuffer.wrap(mRom.RawRom);
        buff.position(mDmaDataOff);

        for (int i = 0; i < filecount; i++) {
            if (monitor != null) {
                if (monitor.isCancelled())
                    break;
                if (i > 2)
                    monitor.setProgress(i);
            }

            DmaDataEntry entry = new DmaDataEntry(buff);
            Mm64File file = entry.ToFile(this);
            files.add(file);
            if (entry.Valid() && entry.Exist()) {
                if (i == 2) // dmadata
                {
                    filecount = file.Data.length / 0x10;
                    if (monitor != null)
                        monitor.initialize(filecount);
                }
            }
        }

        return files;
    }

    public Mm64File GetFile(int vrom) {
        if (mFiles == null)
            return null;
        for (Mm64File file : mFiles) {
            if (file.VRomStart == vrom)
                return file;
        }
        return null;
    }

    public static class DmaDataEntry {
        private int VRomStart;
        private int VRomEnd;
        private int RomStart;
        private int RomEnd;

        public boolean Valid() {
            return (VRomStart != 0 || VRomEnd != 0 || RomStart != 0 || RomEnd != 0);
        }

        public boolean Exist() {
            return RomStart != -1 && RomEnd != -1;
        }

        public boolean Compressed() {
            return RomEnd != 0;
        }

        public DmaDataEntry(ByteBuffer buff) {
            VRomStart = buff.getInt();
            VRomEnd = buff.getInt();
            RomStart = buff.getInt();
            RomEnd = buff.getInt();
        }

        public int GetSize() {
            if (!Valid() || !Exist())
                return 0;
            return Compressed() ? RomEnd - RomStart : VRomEnd - VRomStart;
        }

        public Mm64File ToFile(Mm64Game mm64) {
            if (!Valid())
                return new Mm64File(null, -1, -1, false, 0);

            if (!Exist())
                return Mm64File.DeletedFile(VRomStart, RomStart, VRomEnd - VRomStart);

            int len = GetSize();

            ByteBuffer buff = ByteBuffer.wrap(mm64.mRom.RawRom);
            buff.position(RomStart);
            byte[] data = new byte[len];
            buff.get(data);

            if (Compressed())
                data = Yaz0.DecodeBuffer(data);

            return new Mm64File(data, VRomStart, RomStart, Compressed(), len);
        }
    }
}
