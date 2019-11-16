package mm64;

import java.nio.ByteBuffer;

import org.python.jline.internal.Log;

public class Mm64Overlay {
    byte[] mRawData;
    long mRelaInfoOff;
    long mTextSize;
    long mDataSize;
    long mRodataSize;
    long mBssSize;
    long mRelocSize;
    long[] mEntries;
    boolean mRelocated;

    public Mm64Overlay(byte[] data) {
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

    public void PerformRelocation(long start, long virtStart) {
        if (mRelocated)
            return;

        long[] baseOffs = new long[] { 0, start, start + mTextSize, start + mTextSize + mDataSize, };
        Log.info(String.format("start=0x%X; virtStart=0x%X", start, virtStart));
        Log.info(String.format("base=0x%X", baseOffs[0]));
        Log.info(String.format(".text=0x%X", baseOffs[1]));
        Log.info(String.format(".data=0x%X", baseOffs[2]));
        Log.info(String.format(".rodata=0x%X", baseOffs[3]));

        long[] offArray = new long[0x20];
        long[] insArray = new long[0x20];

        var buff = ByteBuffer.wrap(mRawData);

        for (int i = 0; i < mEntries.length; i++) {
            int type = (int) (mEntries[i] >> 24) & 0x1F;
            long off = baseOffs[(int) (mEntries[i] >> 30)] + (mEntries[i] & 0xFFFFFF);
            buff.position((int) (off - start));
            long ins = buff.getInt() & 0xFFFFFFFFl;

            Log.info(String.format("entry=0x%X; type=%d; off=0x%X; data=0x%X", mEntries[i], type, off, ins));

            if (type == 2) // raw pointers
            {
                if ((ins & 0xf000000) == 0) {
                    buff.position((int) (off - start));
                    buff.putInt((int) ((ins - virtStart) + start));
                }
            } else if (type == 4) // e.g. jal
            {
                var reloc = ins & 0xfc000000
                        | (start + (((ins & 0x3ffffff) << 2 | 0x80000000) - virtStart) & 0xfffffff) >> 2;
                buff.position((int) (off - start));
                buff.putInt((int) (reloc));
            } else if (type == 5) // e.g. lui at, 0x8080 | (0x3C01 8080)
            {
                offArray[(int) ((ins >> 0x10) & 0x1F)] = off;
                insArray[(int) ((ins >> 0x10) & 0x1F)] = ins;
            } else if (type == 6) // e.g. lwc1 ft0, 0x08A0(a) | (0xC424 08A0)
            {
                var prevOff = offArray[(int) ((ins >> 0x15) & 0x1F)];
                var prevIns = insArray[(int) ((ins >> 0x15) & 0x1F)];

                var ptr = ((prevIns & 0xFFFF) << 16) | (ins & 0xFFFF);
                if ((ptr & 0xf000000) == 0) {
                    var reloc = (ptr - virtStart) + start;

                    buff.position((int) (prevOff - start));
                    buff.putInt((int) (((prevIns & 0xFFFF0000) | (reloc >> 0x10)) + (((reloc & 0x8000) != 0) ? 1 : 0)));
                    buff.position((int) (off - start));
                    buff.putInt((int) (ins & 0xFFFF0000 | reloc & 0xFFFF));
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
