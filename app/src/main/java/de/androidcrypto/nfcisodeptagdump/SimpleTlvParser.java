package de.androidcrypto.nfcisodeptagdump;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;

public class SimpleTlvParser {

    // https://jianmingli.com/wp/?p=1756

    static String TAG = "SimpleTlvParser";

    /**
     * Reads TLV values for a given hex string.
     */
    public static byte[][] readTLV(String tlvHexString, int tag) {
        return readTLV(hexStringToByteArray(tlvHexString), tag);
    }

    /**
     * Reads TLV values for a given byte array.
     */
    public static byte[][] readTLV(byte[] tlv, int tag) {
        if (tlv == null || tlv.length < 1) {
            throw new IllegalArgumentException("Invalid TLV");
        }

        int c = 0;
        ArrayList al = new ArrayList();

        ByteArrayInputStream is = null;
        try {
            is = new ByteArrayInputStream(tlv);

            while ((c = is.read()) != -1) {
                if (c == tag){
                    Log.d(TAG, "Got tag");
                    //log.debug("Got tag");
                    if ((c = is.read()) != -1){
                        byte[] value = new byte[c];
                        is.read(value,0,c);
                        al.add(value);
                    }
                }
            }
        } finally {
            if (is != null) {
                try{
                    is.close();
                }catch (IOException e){
                    Log.e(TAG, String.valueOf(e));
                    //log.error(e);
                }
            }
        }
        Log.d(TAG, "Got " + al.size() + " values for tag "
                + Integer.toHexString(tag));
        //log.debug("Got " + al.size() + " values for tag "            + Integer.toHexString(tag));
        byte[][] vals = new byte[al.size()][];
        al.toArray(vals);
        return vals;
    }

    /**
     * Converts a hex string to byte array.
     */
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
