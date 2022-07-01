# NFC IsoDep Tag Hex dump




Links:

List of EMV-tags: https://github.com/devnied/EMV-NFC-Paycard-Enrollment/blob/master/library/src/main/java/com/github/devnied/emvnfccard/iso7816emv/EmvTags.java


https://stackoverflow.com/questions/24631012/apdu-command-to-read-credit-card-data-from-visa-paywave-nfc-enabled-card-using-s

https://stackoverflow.com/questions/23107685/reading-public-data-of-emv-card/23113332#23113332

```plaintext
The EMV specifications for payment systems are publicly available at http://www.emvco.com/. These 
specifications contain details processes and flows how EMV compliant payment terminsal can read 
that data from a card, so you could simply implement the relevant parts of these specifications.

To summarize, what you would typically do to get the static data stored on the card:

Find the application (as you indicated).
Select the application by its AID.
Read the data files using READ RECORD commands (usually the first few records of the first few 
files contain the interesting data). On the cards I tried so far, there is no requirement to issue 
a GET PROCESSING OPTIONS command first, but you can only get a list of actual files/records 
relevant to transactions by issuing the GPO command and evaluationg the AFL sent by the card. 
But you can still use a brute-force approch to find the records relevant to you.
Read the data elements using GET DATA commands (of course you need to know what data elements 
you are looking for).
```

https://stackoverflow.com/questions/15059580/reading-emv-card-using-ppse-and-not-pse

```plaintext
2PAY.SYS.DDF01 is for contactless (e.g. NFC ) cards, while 1PAY.SYS.DDF01 is for contact cards.

After successfully (SW1 SW2 = 90 00) reading a PSE, you should only search for the SFI (tag 88) 
which is a mandatory field in the FCI template returned.

With the SFI as your start index, your would have to read the records starting from the start 
index until you get a 6A83 (RECORD_NOT_FOUND). E.g. if your SFI is 1, you would do a readRecord 
with record_number=1. That would probably be successful. Then you increment record_number to 2 
and do readRecord again. The increment to 3 .... Repeat it until you get 6A83 as your status.

The records read would be ADFs (at least 1). Then your would have to compare the read ADF Names 
with what your terminal support and also based on the ASI (Application Selection Indicator). At 
the end you would have a list of possible ADFs (Candidate list)

All the above steps (1-3) are documented in chapter 12.3.2 Book1 v4.3 of the EMV spec.

You would have to make a final selection (Chapter 12.4 Book1)

Read the spec book 1 chapter 12.3 - 12.4 for all the detailed steps.

Looking at the resulting TLV struct under BF0C:

tag=0xBF0C, length=0x1A
    tag=0x61, length=0x18
        tag=0x4F, length=0x07, value=0xA0000000031010 // looks like an AID to me
        tag=0x50, length=0x0A, value="VISA DEBIT"
        tag=0x87, length=0x01, value=0x01
I would guess that you need to first select A0000000031010 before getting the processing options.

```

https://stackoverflow.com/questions/38998065/how-to-read-response-from-a-credit-card-over-nfc
```plaintext
If your card actually is a MasterCard (or actually pretty much any EMV payment card), the card won't 
return its card number (actually: primary account number, PAN) in response to the application 
selection (SELECT) command. Instead, you would need to query the card for its data files and extract 
the number from those files.

Thus, you would first SELECT the MasterCard application by its AID:

result = isoDep.Transceive(HexStringToByteArray("00A404007A000000004101000"));
Next, you would typically issue a GET PROCESSING OPTIONS command (see Unable to identify AFL on a 
smart card) in order to discover the location of the data records. However, you could also skip 
this step and try to read records by a brute-force approach.

Reading records with a brute-force approach could look something like this:

for (int sfi = 1; sfi < 10; ++sfi ) {
    for (int record = 1; record < 10; ++record) {
        byte[] cmd = HexStringToByteArray("00B2000400");
        cmd[2] = (byte)(record & 0x0FF)
        cmd[3] |= (byte)((sfi << 3) & 0x0F8);
        result = isoDep.Transceive(cmd);
        if ((result != null) && (result.Length >=2)) {
            if ((result[result.Length - 2] == (byte)0x90) && (result[result.Length - 1] == (byte)0x00)) {
                // file exists and contains data
                byte[] data = Arrays.CopyOf(result, result.Length - 2);
                // TODO: parse data
            }
        }
    }
}
You would then need to search the data returned for each record in order to find the data object 
containing the PAN. See this answer on how to decode TLV encoded data objects. You can find an online 
TLV parser here. The PAN is typically encoded in a data object with the tag 0x5A (see here).

Note that the PAN that you can read over NFC may differ from the PAN printed on the card.

edited May 23, 2017 at 12:00
answered Aug 17, 2016 at 14:53
Michael Roland
38.3k1010 gold badges9090 silver badges187187 bronze badges
 
It should be pointed out that this is not secure (in terms of cryptography, so it's prone to fake cards). 
For a verified recognition of a card (and its PAN) you have to do a complete EMV transaction that 
involves either an online authorization or offline data authentication. You could perform this as a 
so called "0-value transaction" (a payment transaction with amount 0), but then you have to code the 
complete payment process! – 
Dominik
 Aug 18, 2016 at 12:11
 
@Dominik Correct. It definitely requires more than reading the PAN in order to authenticate a card. – 
Michael Roland
 Aug 18, 2016 at 16:15
 
Thanks for input, i can also add an interesting source that i used, this java project: 
com.github.devnied.emvnfccard!! – 
Kalkunen
 Aug 24, 2016 at 14:19 
 
@Kalkunen where you successful to use the mentioned project in xamarin? – 
Joe B
 Apr 11 at 15:28
```

https://saush.wordpress.com/2006/09/08/getting-information-from-an-emv-chip-card

A good article about all the processing commands to read an EMV card

https://stackoverflow.com/questions/50157927/chip-emv-getting-afl-for-every-smart-card

Regarding your 2nd question: GPO response may appears in 2 response template. Format 1 (Starting 
with Tag 80) or Format 2 (starting with Tag 77). choosing template is implementation dependent. 
For tag 77, response comes in TLV form (As you can see in your Hello Bank & Paypal. it will contains t
ag 94 which will indicate the AFL). When GPO comes with Tag 80 then it will not be in TLV form. 
First byte will be tag 80 second one will be length of data 3rd and 4th will be AIP and from 5th byte 
to end(before status word 9000) is AFL in this case. –
Gaurav Shukla
May 4, 2018 at 10:17



https://www.javacardos.com/javacardforum/viewtopic.php?t=150

```plaintext
//Select Applet, return File Control Information (FCI) Proprietary Template, it contains Dedicated File(DF), File Control Information and Application Tag.
00A4040006454D5600000100;
//Generates an 8 byte random number .
8084000000;

//READ RECORD Command: '00B2' + Record number + Reference control parameter. (See Book 3, Section 6.5.11)
//Get the record of SFI 1, Record 1,It contains  Primary account number, Bank identifier code, Cardholder Verification Method (CVM) List and other fields.
00B2010C;
//Get the Read record message template, record 2, It contains Certification Authority Public Key Index, Issuer Public Key Certificate, Issuer Public Key Remainder and Issuer Public Key Exponent.
00B2020C;
//Get the Read record message template, record 3, It contains ICC Public Key Certificate, ICC Public Key Exponent, ICC Public Key Remainder and Dynamic Data Authentication Data Object List (DDOL).
00B2030C;

//GET PROCESSING OPTIONS(GPO) Command: 80A80000 + Lc + PDOL related data + 00,(See Book 3, Section 6.5.8)
//In this applet, PDOL is not checked,The response message is a primitive data object with tag equal to '80'.the format is:
//80 + Length + AIP(Application Interchange Profile) + AFL(Application File Locator) 
80A80000;

//GET DATA command: in EMV Specification, the value of P1P2 will be '9F36', '9F13', '9F17', or '9F4F'(Log Format) (See Book 3, Section 6.5.7)
//Get the data of ATC(Application Transaction Counter, tag '9F36')), 
80CA9F36;
//Get the data of PIN Try Counter
80CA9F17;
//Get the data of Last Online ATC Register(tag '9F13')
80CA9F13;

//GENERATE AC command: It sends transaction-related data to the ICC, which computes and returns a cryptogram.in this applet of generateFirstAC only supporting request TC and ARQC.(See Book 3, Section 6.5.5)
//request TC
80AE4000;


//Compute the second AC response APDU using Format 1. 
//AAC
80AE2000;
```

```plaintext
The response on GET PROCESSING OPTIONS above is TLV encoded:

77 12 - response templait, containing response data
    82 02 3C00 - AUC
    94 0C 080202001001030018010201 - AFL
    9000 - SW (Status Word), response ofapplication, telling you, that no errors occured
Note, that response to GET PROCESSING OPTIONS may be returned as 80 template, in that case, you must parse it yourelf:

80 0E - response templait, containing response data
    3C00 - AUC (always 2 bytes long)
    080202001001030018010201 - AFL
    9000 - SW (Status Word), response ofapplication, telling you, that no errors
Y
```


This app read the complete content of a Tag of type NTAG21x (NTAG213, NTAG215 or NTAG216).

As the tag has 3 sections each will be read separately:

**a) Header section:**  stores the serial number of the tag, the static lock bytes and the 
Capability Container (CC) that is needed for NDEF-usage.

**b) User section:** this is the user memory of 144 bytes (NTAG213), 504 bytes (NTAG215) or 
888 bytes (NTAG216). Usually all data we write on the tag is saved in this section.

**c) Footer section:** here we find the dynamic lock bytes, the Configuration pages (0 and 1), 
the password and the PACK fields.

The app dumps the complete memory and tries to show the content in ASCII. As the password and 
PACK are not readable we just see 0x00 instead.

This app uses the low level protocol **NFCA** for the communication with the tag. There should be an 
automated font size adjusting on the dump data but I'm lazy at this point, just fit the value in the 
MainActivity-view to your needs:

```plaintext
<TextView
    android:id="@+id/tvMainReadResult"
    ...
    android:textSize="14sp"
    android:typeface="monospace"
    android:textStyle="normal" />
```

Add in AndroidManifest.xml:
```plaintext
    <uses-permission android:name="android.permission.NFC" />
    <uses-permission android:name="android.permission.VIBRATE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
        android:maxSdkVersion="28"/>
        
for Toolbar:
  android:theme="@style/Theme.AppCompat.Light.NoActionBar"        
```

Beginning with Android 11 you need to use queries for "intent.resolveActivity(getPackageManager()", 
so add im AndroidManifest.xml:
```plaintext
...
<queries>
    <intent>
        <action android:name="android.intent.action.SENDTO" />
        <data android:scheme="*" />
    </intent>
</queries>
```



    <androidx.appcompat.widget.Toolbar
        android:id="@+id/main_toolbar"
        android:layout_width="match_parent"
        android:layout_height="?attr/actionBarSize"
        android:background="@color/colorPrimary"
        android:elevation="@dimen/toolbar_elevation"
        android:theme="@style/ThemeOverlay.AppCompat.Dark.ActionBar"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        app:popupTheme="@style/ThemeOverlay.AppCompat.Light" />

The app icon is generated with help from **Launcher icon generator**  
(https://romannurik.github.io/AndroidAssetStudio/icons-launcher.html),  
(options trim image and resize to 110%, color #2196F3).
