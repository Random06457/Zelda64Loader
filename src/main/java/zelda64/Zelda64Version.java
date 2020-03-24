package zelda64;

public enum Zelda64Version {
    Invalid(null),
    //Ocarina Of Time
    OotJPUS10("zelda@srd44 98-10-21 04:56:31"),
    OotJPUS11("zelda@srd44 98-10-26 10:58:45"),
    OotEurope10("zelda@srd44 98-11-10 14:34:22"),
    OotJPUS12("zelda@srd44 98-11-12 18:17:03"),
    OotEurope11("zelda@srd44 98-11-18 17:36:49"),
    OotJapanGC("zelda@srd022j   02-10-29 23:49:53"),
    OotJapanGCMq("zelda@srd022j   02-10-30 00:15:15"),
    OotUSAGC("zelda@srd022j   02-12-19 13:28:09"),
    OotUSAGCMq("zelda@srd022j   02-12-19 14:05:42"),
    OotEuropeGCMqDbg("zelda@srd022j   03-02-21 00:16:31"),
    OotEuropeGCDbg("zelda@srd022j   03-02-21 00:49:18"),
    OotEuropeGC("zelda@srd022j   03-02-21 20:12:23"),
    OotEuropeGCMq("zelda@srd022j   03-02-21 20:37:19"),
    OotJapanGcZeldaCollection("zelda@srd022j   03-10-08 21:53:00"),
    //Marjoa's Mask
    MmJapan10("zelda@srd44 00-03-31 02:22:11"),
    MmJapan11("zelda@srd44 00-04-04 09:34:16"),
    MmUSADebug("zelda@srd44 00-07-06 16:46:35"),
    MmUSADemo("zelda@srd44 00-07-12 16:14:06"),
    MmUSA10("zelda@srd44 00-07-31 17:04:16"),
    MmEurope10("zelda@srd44 00-09-25 11:16:53"),
    MmEurope11Debug("zelda@srd44 00-09-29 09:29:05"),
    MmEurope11("zelda@srd44 00-09-29 09:29:41");

    public String Name;

    private Zelda64Version(String name) {
        Name = name;
    }

    public String GetBuildName() {
        if (Name != null)
            return Name;
        return "Invalid";
    }

    public static Zelda64Version FromString(String s) {

    	var values = Zelda64Version.values();
    	for (int i = 0; i < values.length; i++)
    	{
    		if (s.equals(values[i].Name))
    			return values[i];
    	}
        return Zelda64Version.Invalid;
    }
}
