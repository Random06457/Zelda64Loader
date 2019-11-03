package mm64;

public enum Mm64Version
{
	Invalid(-1),
	Japan10(0),
	Japan11(1),
	USADebug(2),
	USADemo(3),
	USA10(4),
	Europe10(5),
	Europe11Debug(6),
	Europe11(7);
	
	static final String[] VERSIONS = new String[]
	{
		"zelda@srd44 00-03-31 02:22:11",
        "zelda@srd44 00-04-04 09:34:16",
        "zelda@srd44 00-07-06 16:46:35",
        "zelda@srd44 00-07-12 16:14:06",
        "zelda@srd44 00-07-31 17:04:16",
        "zelda@srd44 00-09-25 11:16:53",
        "zelda@srd44 00-09-29 09:29:05",
        "zelda@srd44 00-09-29 09:29:41",
	};

	
	public int ID;
	
	private Mm64Version(int id)
	{
		ID = id;
	}
	
	public String GetBuildName()
	{
		if (ID != Invalid.ID)
		{
			return VERSIONS[ID];
		}
		return "";
	}
	
	public static Mm64Version FromString(String s)
	{
		int id = -1;
		for (int i = 0; i < VERSIONS.length; i++)
		{
			if (s.equals(VERSIONS[i]))
			{
				id = i;
				break;
			}
		}

		for(Mm64Version v : Mm64Version.values())
		{
			if (v.ID == id)
				return v;
		}
		return Mm64Version.Invalid;
	}


}
