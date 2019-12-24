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

    public long getCodeDst() {
        switch (mVersion) {
        // Ocarina Of Time
        case OotEurope10:
            return 0x800116e0;
        case OotEurope11:
            return 0x800116e0;
        case OotEuropeMqDbg:
            return 0x8001CE60;
        case OotEuropeGC:
            return 0x80010f00;
        case OotEuropeMq:
            return 0x80010f00;
        case OotJPUS10:
            return 0x800110a0;
        case OotJPUS11:
            return 0x800110a0;
        case OotJPUS12:
            return 0x800116e0;
        case OotJapanGC:
            return 0x80010ee0;
        case OotJapanMq:
            return 0x80010ee0;
        case OotJapanGcZeldaCollection:
            return 0x80010ee0;
        case OotUSAGC:
            return 0x80010ee0;
        case OotUSAMq:
            return 0x80010ee0;
        // Majora's Mask
        case MmJapan10:
            return 0x800a76a0;
        case MmJapan11:
            return 0x800a75e0;
        case MmUSADemo:
            return 0x800a6120;
        case MmUSA10:
            return 0x800a5ac0;
        case MmEurope10:
            return 0x800a5d60;
        case MmEurope11Debug:
            return 0x800b6ac0;
        case MmEurope11:
            return 0x800a5fe0;
        default:
            return -1;
        }
    }

    public int getCodeVrom() {
        switch (mVersion) {
        // Ocarina Of Time
        case OotEurope10:
            return 0xa89000;
        case OotEurope11:
            return 0xa89000;
        case OotEuropeMqDbg:
            return 0xa94000;
        case OotEuropeGC:
            return 0xa88000;
        case OotEuropeMq:
            return 0xa88000;
        case OotJPUS10:
            return 0xa87000;
        case OotJPUS11:
            return 0xa87000;
        case OotJPUS12:
            return 0xa87000;
        case OotJapanGC:
            return 0xa86000;
        case OotJapanMq:
            return 0xa86000;
        case OotJapanGcZeldaCollection:
            return 0xa86000;
        case OotUSAGC:
            return 0xa86000;
        case OotUSAMq:
            return 0xa86000;
        // Majora's Mask
        case MmJapan10:
            return 0xb5f000;
        case MmJapan11:
            return 0xb5f000;
        case MmUSADemo:
            return 0xb3d000;
        case MmUSA10:
            return 0xb3c000;
        case MmEurope10:
            return 0xc8a000;
        case MmEurope11Debug:
            return 0xc95000;
        case MmEurope11:
            return 0xc8a000;

        default:
            return -1;
        }
    }

    public long getActorOvlTableAddr() {
        switch (mVersion) {
        // Ocarina Of Time
        case OotEurope10:
            return 0x800e6480;
        case OotEurope11:
            return 0x800e64c0;
        case OotEuropeMqDbg:
            return 0x801162a0;
        case OotEuropeGC:
            return 0x800e53a0;
        case OotEuropeMq:
            return 0x800e5380;
        case OotJPUS10:
            return 0x800e8530;
        case OotJPUS11:
            return 0x800e86f0;
        case OotJPUS12:
            return 0x800e8b70;
        case OotJapanGC:
            return 0x800e7a40;
        case OotJapanMq:
            return 0x800e7a20;
        case OotJapanGcZeldaCollection:
            return 0x800e7a20;
        case OotUSAGC:
            return 0x800e7a20;
        case OotUSAMq:
            return 0x800e7a00;
        // Majora's Mask
        case MmJapan10:
            return 0x801a9e60;
        case MmJapan11:
            return 0x801aa0a0;
        case MmUSADemo:
            return 0x801ae830;
        case MmUSA10:
            return 0x801aefd0;
        case MmEurope10:
            return 0x801af760;
        case MmEurope11Debug:
            return 0x801f7510;
        case MmEurope11:
            return 0x801afb00;

        default:
            return -1;
        }
    }

    public long getGraphOvlTableAddr() {
        switch (mVersion) {
        // Ocarina Of Time
        case OotEurope10:
            return 0x800ef290;
        case OotEurope11:
            return 0x800ef2d0;
        case OotEuropeMqDbg:
            return 0x8011f830;
        case OotEuropeGC:
            return 0x800ee1b0;
        case OotEuropeMq:
            return 0x800ee190;
        case OotJPUS10:
            return 0x800f1340;
        case OotJPUS11:
            return 0x800f1500;
        case OotJPUS12:
            return 0x800f1980;
        case OotJapanGC:
            return 0x800f0850;
        case OotJapanMq:
            return 0x800f0830;
        case OotJapanGcZeldaCollection:
            return 0x800f0830;
        case OotUSAGC:
            return 0x800f0830;
        case OotUSAMq:
            return 0x800f0810;
        // Majora's Mask
        case MmJapan10:
            return 0x801B87A0;
        case MmJapan11:
            return 0x801B89E0;
        case MmUSADemo:
            return 0x801BD170;
        case MmUSA10:
            return 0x801BD910;
        case MmEurope10:
            return 0x801BE0A0;
        case MmEurope11Debug:
            return 0x80206820;
        case MmEurope11:
            return 0x801BE440;
        default:
            return -1;
        }
    }

    public long getEffectSS2OvlTableAddr() {
        switch (mVersion) {
        // Ocarina Of Time
        case OotEurope10:
            return 0x800e5b90;
        case OotEurope11:
            return 0x800e5bd0;
        case OotEuropeMqDbg:
            return 0x801159b0;
        case OotEuropeGC:
            return 0x800e4ab0;
        case OotEuropeMq:
            return 0x800e4a90;
        case OotJPUS10:
            return 0x800e7c40;
        case OotJPUS11:
            return 0x800e7e00;
        case OotJPUS12:
            return 0x800e8280;
        case OotJapanGC:
            return 0x800e7150;
        case OotJapanMq:
            return 0x800e7130;
        case OotJapanGcZeldaCollection:
            return 0x800e7130;
        case OotUSAGC:
            return 0x800e7130;
        case OotUSAMq:
            return 0x800e7110;
        // Majora's Mask
        case MmJapan10:
            return 0x801a9330;
        case MmJapan11:
            return 0x801a9570;
        case MmUSADemo:
            return 0x801add00;
        case MmUSA10:
            return 0x801ae4a0;
        case MmEurope10:
            return 0x801aefc0;
        case MmEurope11Debug:
            return 0x801f69e0;
        case MmEurope11:
            return 0x801af360;

        default:
            return -1;
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
