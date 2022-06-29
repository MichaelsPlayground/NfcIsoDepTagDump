# NFC IsoDep Tag Hex dump




Links:

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