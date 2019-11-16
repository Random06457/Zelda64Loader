package mm64;

import java.util.regex.Pattern;

public class MemPerm {
    public boolean R;
    public boolean W;
    public boolean X;

    public MemPerm(boolean r, boolean w, boolean x) {
        R = r;
        W = w;
        X = x;
    }

    public MemPerm(String s) {
        R = false;
        W = false;
        X = false;

        Pattern p = Pattern.compile("^(R|r|-)(W|w|-)(X|x|-)$");
        if (p.matcher(s).matches()) {
            R = s.charAt(0) != '-';
            W = s.charAt(1) != '-';
            X = s.charAt(2) != '-';
        }
    }

}
