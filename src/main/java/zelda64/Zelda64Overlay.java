package zelda64;

import java.nio.ByteBuffer;
import org.python.jline.internal.Log;
import ghidra.program.flatapi.FlatProgramAPI;

public class Zelda64Overlay {
    byte[] mRawData;
    long mRelaInfoOff;
    long mTextSize;
    long mDataSize;
    long mRodataSize;
    long mBssSize;
    long mRelocSize;
    long[] mEntries;
    boolean mRelocated;

    public Zelda64Overlay(byte[] data) {
        mRelocated = false;
        mRawData = data;
        ByteBuffer buff = ByteBuffer.wrap(mRawData);
        buff.position(mRawData.length - 4);
        int structLen = buff.getInt();
        mRelaInfoOff = (mRawData.length - structLen) & 0xFFFFFFFFl;
        buff.position((int) mRelaInfoOff);

        mTextSize = buff.getInt() & 0xFFFFFFFFl;
        mDataSize = buff.getInt() & 0xFFFFFFFFl;
        mRodataSize = buff.getInt() & 0xFFFFFFFFl;
        mBssSize = buff.getInt() & 0xFFFFFFFFl;
        mRelocSize = structLen & 0xFFFFFFFFl;// mRawData.length - mRelaInfoOff;
        int count = buff.getInt();
        mEntries = new long[count];
        for (int i = 0; i < count; i++)
            mEntries[i] = buff.getInt() & 0xFFFFFFFFl;
    }

    private void AddRelocEntry(FlatProgramAPI api, ByteBuffer buff, int type, long relocAddr, long ram, long fixed,
            long entry) {
        int off = (int) (relocAddr - ram);
        buff.position(off);
        byte origBytes[] = new byte[4];
        buff.get(origBytes);
        api.getCurrentProgram().getRelocationTable().add(api.toAddr(relocAddr), type, new long[] { entry }, origBytes,
                null);

        buff.position(off);
        buff.putInt((int) (fixed));
    }

    public void PerformRelocation(FlatProgramAPI api, long ram, long vram) {
        if (mRelocated)
            return;

        long[] baseOffs = new long[] { 0, ram, ram + mTextSize, ram + mTextSize + mDataSize, };
        Log.info(String.format("ram=0x%X; vram=0x%X", ram, vram));
        Log.info(String.format("base=0x%X", baseOffs[0]));
        Log.info(String.format(".text=0x%X", baseOffs[1]));
        Log.info(String.format(".data=0x%X", baseOffs[2]));
        Log.info(String.format(".rodata=0x%X", baseOffs[3]));

        long[] addrArray = new long[0x20];
        long[] insArray = new long[0x20];

        var buff = ByteBuffer.wrap(mRawData);

        for (int i = 0; i < mEntries.length; i++) {
            int type = (int) (mEntries[i] >> 24) & 0x3F;
            long relocAddr = baseOffs[(int) (mEntries[i] >> 30)] + (mEntries[i] & 0xFFFFFF);
            buff.position((int) (relocAddr - ram));
            long ins = buff.getInt() & 0xFFFFFFFFl;

            Log.info(String.format("entry=0x%X; type=%d; off=0x%X; data=0x%X", mEntries[i], type, relocAddr, ins));

            if (type == 2) // raw pointers
            {
                if ((ins & 0xf000000) == 0) {
                    AddRelocEntry(api, buff, type, relocAddr, ram, (ins - vram) + ram, mEntries[i]);
                }
            } else if (type == 4) // e.g. jal
            {
                var reloc = ins & 0xfc000000 | (ram + (((ins & 0x3ffffff) << 2 | 0x80000000) - vram) & 0xfffffff) >> 2;
                AddRelocEntry(api, buff, type, relocAddr, ram, reloc, mEntries[i]);

            } else if (type == 5) // e.g. lui at, 0x8080 | (0x3C01 8080)
            {
                int register = (int) ((ins >> 0x10) & 0x1F);
                addrArray[register] = relocAddr;
                insArray[register] = ins;
            } else if (type == 6) // e.g. lwc1 ft0, 0x08A0(a) | (0xC424 08A0)
            {
                int register = (int) ((ins >> 0x15) & 0x1F);
                var prevAddr = addrArray[register];
                var prevIns = insArray[register];

                long ptr = ((prevIns & 0xFFFF) << 16) + (short) (ins & 0xFFFF);
                if ((ptr & 0xF000000) == 0) {
                    var reloc = (ptr - vram) + ram;

                    AddRelocEntry(api, buff, 5, prevAddr, ram,
                            ((prevIns & 0xFFFF0000) | (reloc >> 0x10)) + (((reloc & 0x8000) != 0) ? 1 : 0),
                            mEntries[i]);
                    AddRelocEntry(api, buff, 6, relocAddr, ram, ins & 0xFFFF0000 | reloc & 0xFFFF, mEntries[i]);
                }
            }
        }
        mRelocated = true;

    }

    public byte[] GetText() {
        byte[] text = new byte[(int) mTextSize];
        ByteBuffer buff = ByteBuffer.wrap(mRawData);
        buff.get(text);
        return text;
    }

    public byte[] GetData() {
        byte[] data = new byte[(int) mDataSize];
        ByteBuffer buff = ByteBuffer.wrap(mRawData);
        buff.position((int) mTextSize);
        buff.get(data);
        return data;
    }

    public byte[] GetRodata() {
        byte[] rodata = new byte[(int) mRodataSize];
        ByteBuffer buff = ByteBuffer.wrap(mRawData);
        buff.position((int) (mTextSize + mDataSize));
        buff.get(rodata);
        return rodata;
    }

    public byte[] GetRelocData() {
        byte[] reloc = new byte[(int) mRelocSize];
        ByteBuffer buff = ByteBuffer.wrap(mRawData);
        buff.position((int) mRelaInfoOff);
        buff.get(reloc);
        return reloc;
    }

}
