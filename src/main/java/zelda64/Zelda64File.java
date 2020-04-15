package zelda64;

import zelda64.Zelda64Game.DmaDataEntry;

public class Zelda64File {
    public boolean mCompressed;
    public int mVromStart;
    public int mVromEnd;
    public int mRomStart;
    public int mRomEnd;
    public byte[] mData;
    public boolean mDeleted;
    DmaDataEntry mDmaData;

    public Zelda64File() {

    }

    public Zelda64File(byte[] data, int vrom, int rom, boolean comp, int compSize) {
        mData = data;
        mVromStart = vrom;
        mVromEnd = vrom + (data != null ? data.length : compSize);
        mRomStart = rom;
        mRomEnd = rom + compSize;
        mCompressed = comp;
        mDeleted = false;
    }

    public static Zelda64File DeletedFile(int vrom, int rom, int size) {
        Zelda64File file = new Zelda64File();
        file.mData = new byte[size];
        file.mCompressed = false;
        file.mDeleted = true;
        file.mVromStart = vrom;
        file.mVromEnd = vrom + size;
        file.mRomStart = rom;
        file.mRomEnd = rom + size;

        return file;
    }

    public boolean Valid() {
        return mData != null;
    }
}
