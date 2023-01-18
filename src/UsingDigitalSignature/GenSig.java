/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package UsingDigitalSignature;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;

/**
 *
 * @author trung
 */
public class GenSig {

    public static void main(String[] args) {
        /* Generate a DSA Signature */
        File f = new File("src/UsingDigitalSignature/FileNeeded/FileToSign.txt");
        File fsig = new File("src/UsingDigitalSignature/FileNeeded/Signature.txt");
        File fkey = new File("src/UsingDigitalSignature/FileNeeded/VuPublicKey.txt");

        try {

            //Creating KeyPair generator object
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", "SUN");

            //Initialize the Key Pair Generator
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            kpg.initialize(1024, random);

            //Generate the Pair of Keys
            KeyPair pair = kpg.generateKeyPair();
            PrivateKey pri = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            //Get a Signature object
            Signature sign = Signature.getInstance("SHA1withDSA", "SUN");

            //Initialize the Signature Object
            sign.initSign(pri);

            //Supply the Signature Object the Data to be Signed
            FileInputStream fis = new FileInputStream(f);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                sign.update(buffer, 0, len);
            }
            bufin.close();

            //Generate the Signature
            byte[] realSign = sign.sign();

            //Save the Signature in a file
            FileOutputStream sigfos = new FileOutputStream(fsig);
            sigfos.write(realSign);
            sigfos.close();

            //Save the Public Key in a file
            byte[] key = pub.getEncoded();
            FileOutputStream keyfos = new FileOutputStream(fkey);
            keyfos.write(key);
            keyfos.close();
            
            System.out.println("GenSig's run successfully");
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}
