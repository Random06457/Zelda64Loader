package zelda64;

import zelda64.Zelda64Game.DmaDataEntry;

public class Zelda64File {
    public boolean Compressed;
    public int VRomStart;
    public int VRomEnd;
    public int RomStart;
    public int RomEnd;
    public byte[] Data;
    public boolean Deleted;
    DmaDataEntry DmaData;

    public Zelda64File() {

    }

    public Zelda64File(byte[] data, int vrom, int rom, boolean comp, int compSize) {
        Data = data;
        VRomStart = vrom;
        VRomEnd = vrom + (data != null ? data.length : compSize);
        RomStart = rom;
        RomEnd = rom + compSize;
        Compressed = comp;
        Deleted = false;
    }

    public static Zelda64File DeletedFile(int vrom, int rom, int size) {
        Zelda64File file = new Zelda64File();
        file.Data = new byte[size];
        file.Compressed = false;
        file.Deleted = true;
        file.VRomStart = vrom;
        file.VRomEnd = vrom + size;
        file.RomStart = rom;
        file.RomEnd = rom + size;

        return file;
    }

    public boolean Valid() {
        return Data != null;
    }
}
