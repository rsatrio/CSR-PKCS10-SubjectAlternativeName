package com.rizky.pubkeyinfra;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class SanEmailCsrExample {

    public static void main(String[] args) throws Exception  {
        //Generate KeyPair RSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        //Prepare data for CSR
        String subjectDN="C=ID, O=Rizky Inc., OU=Private, CN=Rizky Test San Email, EMAILADDRESS=rizkytest@gmail.com";
        String sanEmail="sanEmail@test.com";

        //Create CSR
        PKCS10CertificationRequest csr=CsrTools.createCsrSanEmail(subjectDN, sanEmail, pair.getPrivate(), pair.getPublic());

        //Print CSR PEM
        OutputStreamWriter output = new OutputStreamWriter(System.out);
        PEMWriter pem = new PEMWriter(output);

        pem.writeObject(csr);
        pem.close();


    }

}
