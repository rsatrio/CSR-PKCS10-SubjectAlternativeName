package com.rizky.pubkeyinfra;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class RFC4683CsrExample {
    
    public static void main(String[] args) throws Exception  {
        
        //Generate KeyPair RSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        
        //Prepare data for CSR
        String subjectDN="C=ID, O=Rizky Inc., OU=Private, CN=Rizky Test2, EMAILADDRESS=rizkytest@gmail.com";
        String hashRandom="BC3AE7FBFFFD9C85A3FB234E51FFFD2190B1F8F161C0A2873B998EFAC067B03A";
        String pepsi="6A9E6264DDBD0FC997B9B40524247C8BC319D02A583F4B499DD3ECAF06C786DF";
        
        //Create CSR
        PKCS10CertificationRequest csr=CsrTools.createCsrRFC4683(subjectDN, hashRandom, pepsi, pair.getPrivate(), pair.getPublic());
        
        //Print CSR PEM
        OutputStreamWriter output = new OutputStreamWriter(System.out);
        PEMWriter pem = new PEMWriter(output);

        pem.writeObject(csr);
        pem.close();
        
    }

}
