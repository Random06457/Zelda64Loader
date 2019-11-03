package mm64;

import mm64.Mm64Game.DmaDataEntry;

public class Mm64File
{
	public boolean Compressed;
    public int VRomStart;
    public int VRomEnd;
    public int RomStart;
    public int RomEnd;
    public byte[] Data;
    public boolean Deleted;
    DmaDataEntry DmaData;

    public Mm64File()
    {
    	
    }
    public Mm64File(byte[] data, int vrom, int rom, boolean comp, int compSize)
    {
        Data = data;
        VRomStart = vrom;
    	VRomEnd = vrom+ (data != null ? data.length : compSize);
    	RomStart = rom;
    	RomEnd = rom+compSize;
        Compressed = comp;
        Deleted = false;
    }
    public static Mm64File DeletedFile(int vrom, int rom, int size)
    {
    	Mm64File file = new Mm64File();
    	file.Data = new byte[size];
    	file.Compressed = false;
    	file.Deleted = true;
    	file.VRomStart = vrom;
    	file.VRomEnd = vrom+size;
    	file.RomStart = rom;
    	file.RomEnd = rom+size;

		return file;
    }

    public boolean Valid()
    {
        return Data != null;
    }
}
