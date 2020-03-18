package zelda64;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.task.TaskMonitor;

public class Zelda64Game {
    public N64Rom mRom;
    public String mBuildName;
    public Zelda64Version mVersion;
    public int mDmaDataOff;
    public List<Zelda64File> mFiles;

    public Zelda64Game(N64Rom rom, boolean loadFs, TaskMonitor monitor) throws Zelda64Exception {
        mRom = rom;
        Load();
        mFiles = null;
        if (loadFs)
            mFiles = GetFs(monitor);
    }

    public Zelda64Game(byte[] data, boolean loadFs, TaskMonitor monitor) throws Zelda64Exception, Zelda64RomException {
        this(new N64Rom(data), loadFs, monitor);
    }

    private void Load() throws Zelda64Exception {
        int off = FindBuildNameOffset();
        if (off == -1)
            throw new Zelda64Exception("Could Not Find Build Name");

        mDmaDataOff = off + 0x30;
        try {
            BinaryReader br = new BinaryReader(new ByteArrayProvider(mRom.RawRom), false);
            String build = br.readAsciiString(off, 0x30);
            mBuildName = build.replaceAll("\0+$", "").replace('\0', ' ');
            mVersion = Zelda64Version.FromString(mBuildName);
        } catch (Exception ex) {
            throw new Zelda64Exception("Could Not Read Build Name");
        }
    }

    public boolean IsOot() {
        switch (mVersion) {
        case OotEurope10:
        case OotEurope11:
        case OotEuropeGC:
        case OotEuropeMq:
        case OotEuropeMqDbg:
        case OotJPUS10:
        case OotJPUS11:
        case OotJPUS12:
        case OotJapanGC:
        case OotJapanGcZeldaCollection:
        case OotJapanMq:
        case OotUSAGC:
        case OotUSAMq:
            return true;
        default:
            return false;

        }
    }

    public boolean IsMm() {
        switch (mVersion) {
        case MmEurope10:
        case MmEurope11:
        case MmEurope11Debug:
        case MmJapan10:
        case MmJapan11:
        case MmUSA10:
        case MmUSADebug:
        case MmUSADemo:
            return true;
        default:
            return false;
        }
    }

    public boolean IsKnown() {
        return IsOot() || IsMm();
    }

    public String GetVersionLongName() {
        String gameName = IsOot() ? "Ocarina Of Time" : IsMm() ? "Majora's Mask" : "???";

        switch (mVersion) {
        case Invalid:
            return gameName + " Invalid";
        case MmEurope10:
            return gameName + " Europe 1.0";
        case MmEurope11:
            return gameName + " Europe 1.1";
        case MmEurope11Debug:
            return gameName + " Europe 1.1 Debug";
        case MmJapan10:
            return gameName + " Japan 1.0";
        case MmJapan11:
            return gameName + " Japan 1.1";
        case MmUSA10:
            return gameName + " USA 1.0";
        case MmUSADebug:
            return gameName + " USA Debug";
        case MmUSADemo:
            return gameName + " USA Kiosk Demo";
        case OotEurope10:
            return gameName + " Europe 1.0";
        case OotEurope11:
            return gameName + " Europe 1.1";
        case OotEuropeGC:
            return gameName + " Europe GameCube";
        case OotEuropeMq:
            return gameName + " Europe Master Quest";
        case OotEuropeMqDbg:
            return gameName + " Europe Master Quest Debug";
        case OotJPUS10:
            return gameName + " JP/US 1.0";
        case OotJPUS11:
            return gameName + " JP/US 1.1";
        case OotJPUS12:
            return gameName + " JP/US 1.2";
        case OotJapanGC:
            return gameName + " Japan GameCube";
        case OotJapanGcZeldaCollection:
            return gameName + " Japan GameCube Zelda Collection";
        case OotJapanMq:
            return gameName + " Japan Master Quest";
        case OotUSAGC:
            return gameName + " USA GameCube";
        case OotUSAMq:
            return gameName + " USA Master Quest";
        default:
            return "Invalid or unknown version";
        }

    }

    private int FindBuildNameOffset() {
        String pattern = "zelda@srd";
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

    public List<Zelda64File> GetFs(TaskMonitor monitor) {
        List<Zelda64File> files = new ArrayList<Zelda64File>();
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
            Zelda64File file = entry.ToFile(this);
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

    public Zelda64File GetFile(int vrom) {
        if (mFiles == null)
            return null;
        for (Zelda64File file : mFiles) {
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

        public Zelda64File ToFile(Zelda64Game mm64) {
            if (!Valid())
                return new Zelda64File(null, -1, -1, false, 0);

            if (!Exist())
                return Zelda64File.DeletedFile(VRomStart, RomStart, VRomEnd - VRomStart);

            int len = GetSize();

            ByteBuffer buff = ByteBuffer.wrap(mm64.mRom.RawRom);
            buff.position(RomStart);
            byte[] data = new byte[len];
            buff.get(data);

            if (Compressed())
                data = Yaz0.DecodeBuffer(data);

            return new Zelda64File(data, VRomStart, RomStart, Compressed(), len);
        }
    }
}
