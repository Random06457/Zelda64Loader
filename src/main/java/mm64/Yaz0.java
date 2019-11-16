package mm64;

import java.nio.ByteBuffer;

public class Yaz0 {
    public static byte[] DecodeBuffer(byte[] data) {

        var in = ByteBuffer.wrap(data);

        try {
            byte[] buff = new byte[4];
            in.get(buff);
            String magic = new String(buff);
            if (!magic.equals("Yaz0"))
                throw new Exception("Invalid Magic");

            int outSize = in.getInt();
            in.position(0x10);

            var out = ByteBuffer.allocate(outSize);

            int chunkHdr = in.get() & 0xFF;
            int chunkIdx = 0;

            while (out.position() < outSize) {
                // uncompressed byte
                if ((chunkHdr & 0x80) == 0x80) // if first bit is set
                {
                    out.put(in.get());
                }
                // compressed data
                else {
                    int raw = in.getShort() & 0xFFFF;
                    int nibble = raw >> 12;
                    int backOff = raw & 0xFFF;
                    int backSize = (nibble != 0) ? nibble + 2 // NR RR
                            : (in.get() & 0xFF) + 0x12; // 0R RR NN

                    int tmpPos = out.position();
                    int newPos = tmpPos - backOff - 1;
                    // Log.info( String.format("raw=0x%X; nibble=0x%X; backOff=0x%X; backSize=0x%X;
                    // tmpPos=0x%X, newPos=0x%X", raw, nibble, backOff, backSize, tmpPos, newPos));

                    for (int i = 0; i < backSize; i++) {
                        byte b = 0; // 0 if out of stream
                        if (newPos + i >= 0) {
                            out.position(newPos + i);
                            b = out.get();
                            out.position(tmpPos + i);
                        }
                        out.put(b);
                    }
                }

                chunkIdx++;
                chunkHdr <<= 1;

                // starts a new chunk
                if ((chunkIdx == 8) && out.position() < outSize) {
                    chunkHdr = in.get() & 0xFF;
                    chunkIdx = 0;
                }
            }

            return out.array();
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }

    }

}
