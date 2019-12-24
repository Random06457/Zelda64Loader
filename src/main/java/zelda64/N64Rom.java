package zelda64;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

public class N64Rom {

    public byte[] RawRom;

    public int getClockRate() {
        return ByteBuffer.wrap(RawRom).getInt(0x4) & 0xFFFFFFF0;
    }

    public int getEntryPoint() {
        return ByteBuffer.wrap(RawRom).getInt(8);
    }

    public int getReleaseOffset() {
        return ByteBuffer.wrap(RawRom).getInt(0xC);
    }

    public int getCRC1() {
        return ByteBuffer.wrap(RawRom).getInt(0x10);
    }

    public int getCRC2() {
        return ByteBuffer.wrap(RawRom).getInt(0x14);
    }

    public String getName() {
        byte[] name = new byte[0x14];
        ByteBuffer buff = ByteBuffer.wrap(RawRom);
        buff.position(0x20);
        buff.get(name, 0, name.length);
        try {
            return new String(name, "UTF8").replaceAll("\\s+$", "");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return "**ERROR**";
        }
    }

    public String getDeveloper() {
        return new String(new byte[] { RawRom[0x3B] });
    }

    public String getCartID() {
        return new String(new byte[] { RawRom[0x3C], RawRom[0x3D] });
    }

    public String getCountryCode() {
        return new String(new byte[] { RawRom[0x3E] });
    }

    public String getGameCode() {
        return getDeveloper() + getCartID() + getCountryCode();
    }

    public byte getVersion() {
        return RawRom[0x3F];
    }

    public N64Rom(byte[] data) throws Zelda64RomException {
        if (data.length < 0x1000 || data.length % 4 != 0)
            throw new Zelda64RomException("Invalid ROM Size");

        // check for endian swap
        if (data[0] != (byte) 0x80 && data[1] == (byte) 0x80) {
            RawRom = new byte[data.length];
            for (int i = 0; i < data.length; i += 2) {
                RawRom[i + 0] = data[i + 1];
                RawRom[i + 1] = data[i + 0];
            }
        } else
            RawRom = data;
    }
}