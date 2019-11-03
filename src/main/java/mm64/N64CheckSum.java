package mm64;

import java.nio.ByteBuffer;

public class N64CheckSum
{
    static final int CHECKSUM_START = 0x1000;
    static final int CHECKSUM_LENGTH = 0x100000;
    static final int CHECKSUM_END = CHECKSUM_START + CHECKSUM_LENGTH;
    
    private static long UIntToLong(int a)
    {
    	return a & 0xFFFFFFFFl;
    }
    private static int ROL(int a, int b)
    {
    	long al = UIntToLong(a);
    	return (int)((al << b) | (al >> (32 - b)));
    }
    
	private int CRC1;
	private int CRC2;
	
	public int getCRC1()
	{
		return CRC1;
	}
	public int getCRC2()
	{
		return CRC2;
	}
	
	public N64CheckSum(N64Rom rom, int cic)// throws N64CheckSumException
	{
		try
		{
			Compute(rom, cic);
		}
		catch (Exception e)
		{
			CRC1 = 0;
			CRC2 = 0;
		}
	}
	
	private void Compute(N64Rom rom, int cic) throws N64CheckSumException
	{
        if (rom.RawRom.length < CHECKSUM_START)
            throw new N64CheckSumException("Invalid File Lenght");
        
        int seed;
        int t1, t2, t3, t4, t5, t6;
        int pos;

        //init seeds
        switch (cic)
        {
            case 6101:
            case 6102:
                seed = 0xF8CA4DDC;
                break;
            case 6103:
                seed = 0xA3886759;
                break;
            case 6105:
                seed = 0xDF26F436;
                break;
            case 6106:
                seed = 0x1FEA617A;
                break;
            default:
                throw new N64CheckSumException("Invalid CIC");
        }

        t1 = t2 = t3 = t4 = t5 = t6 = seed;
        
        for (pos = CHECKSUM_START; pos < CHECKSUM_END; pos += 4)
        {
        	int d = ByteBuffer.wrap(rom.RawRom).getInt(pos);
            int r = ROL(d, d & 0x1F);

            // increment t4 if t6 overflows
            if (UIntToLong(t6 + d) < UIntToLong(t6))
                t4++;

            t6 += d;
            t3 ^= d;
            t5 += r;

            if (UIntToLong(t2) > UIntToLong(d))
                t2 ^= r;
            else
                t2 ^= t6 ^ d;

            if (cic == 6105)
            	t1 += ByteBuffer.wrap(rom.RawRom).getInt(0x0750 + (pos & 0xFF)) ^ d;
            else
                t1 += t5 ^ d;
        }

        if (cic == 6103)
        {
            CRC1 = (t6 ^ t4) + t3;
            CRC2 = (t5 ^ t2) + t1;
        }
        else if (cic == 6106)
        {
            CRC1 = (t6 * t4) + t3;
            CRC2 = (t5 * t2) + t1;
        }
        else
        {
            CRC1 = t6 ^ t4 ^ t3;
            CRC2 = t5 ^ t2 ^ t1;
        }
        
	}
	
	public static boolean Validate(N64Rom rom, int cic)
	{
		try
		{
			N64CheckSum c = new N64CheckSum(rom, cic);
			return c.CRC1 == rom.getCRC1() && c.CRC2 == rom.getCRC2();	
		}
		catch (Exception e)
		{
			return false;
		}
	}

}
