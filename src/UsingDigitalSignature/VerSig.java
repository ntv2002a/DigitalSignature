/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package UsingDigitalSignature;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;


/**
 *
 * @author trung
 */
public class VerSig {

    public static void main(String[] args) {
        File f = new File("src/UsingDigitalSignature/FileToSign.txt");
        File fsig = new File("src/UsingDigitalSignature/Signature.txt");
        File fkey = new File("src/UsingDigitalSignature/VuPublicKey.txt");
        try {
            //Input and Convert the encoded Public Key Bytes
            FileInputStream keyfis = new FileInputStream(fkey);
            byte[] enckey = new byte[keyfis.available()];
            keyfis.read(enckey);
            keyfis.close();

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(enckey);

            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

            PublicKey pubkey = keyFactory.generatePublic(pubKeySpec);

            //Input the Signature Bytes
            FileInputStream sigfis = new FileInputStream(fsig);
            byte[] sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify);
            sigfis.close();

            //Verify the Signature
            //Initialize the Signature Object for Verification
            Signature sig = Signature.getInstance("SHA1withDSA");
            sig.initVerify(pubkey);

            //Supply the Signature Object With the Data to be Verified
            FileInputStream datafis = new FileInputStream(f);
            BufferedInputStream bufin = new BufferedInputStream(datafis);

            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                sig.update(buffer, 0, len);
            };

            bufin.close();

            //Verify the Signature
            boolean verifies = sig.verify(sigToVerify);

            System.out.println("Signature verifies: " + verifies);

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}
