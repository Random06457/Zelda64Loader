package zelda64;

public enum Zelda64Version {
    Invalid(-1),
    //Ocarina Of Time
    OotJPUS10(0),
    OotJPUS11(1),
    OotEurope10(2),
    OotJPUS12(3),
    OotEurope11(4),
    OotJapanGC(5),
    OotJapanMq(6),
    OotUSAGC(7),
    OotUSAMq(8),
    OotEuropeMqDbg(9),
    OotEuropeGC(10),
    OotEuropeMq(11),
    OotJapanGcZeldaCollection(12),
    //Marjoa's Mask
    MmJapan10(13),
    MmJapan11(14),
    MmUSADebug(15),
    MmUSADemo(16),
    MmUSA10(17),
    MmEurope10(18),
    MmEurope11Debug(19),
    MmEurope11(20);

    static final String[] VERSIONS = new String[] {
        //Ocarina Of Time
        "zelda@srd44 98-10-21 04:56:31",
        "zelda@srd44 98-10-26 10:58:45",
        "zelda@srd44 98-11-10 14:34:22",
        "zelda@srd44 98-11-12 18:17:03",
        "zelda@srd44 98-11-18 17:36:49",
        "zelda@srd022j   02-10-29 23:49:53",
        "zelda@srd022j   02-10-30 00:15:15",
        "zelda@srd022j   02-12-19 13:28:09",
        "zelda@srd022j   02-12-19 14:05:42",
        "zelda@srd022j   03-02-21 00:16:31",
        "zelda@srd022j   03-02-21 20:12:23",
        "zelda@srd022j   03-02-21 20:37:19",
        "zelda@srd022j   03-10-08 21:53:00",
        //Majora's Mask
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

    private Zelda64Version(int id) {
        ID = id;
    }

    public String GetBuildName() {
        if (ID != Invalid.ID)
            return VERSIONS[ID];
        return "";
    }

    public static Zelda64Version FromString(String s) {
        int id = -1;
        for (int i = 0; i < VERSIONS.length; i++) {
            if (s.equals(VERSIONS[i])) {
                id = i;
                break;
            }
        }

        for (Zelda64Version v : Zelda64Version.values()) {
            if (v.ID == id)
                return v;
        }
        return Zelda64Version.Invalid;
    }
}
