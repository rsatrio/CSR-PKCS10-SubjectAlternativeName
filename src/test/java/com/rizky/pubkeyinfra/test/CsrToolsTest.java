package com.rizky.pubkeyinfra.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.util.CertTools;
import org.cesecore.util.RFC4683Tools;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;

import com.rizky.pubkeyinfra.CsrTools;

public class CsrToolsTest {

    @Test
    public void TestCsrTools() throws Exception {

        //Generate KeyPair RSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        //Prepare data for CSR
        String subjectDN="C=ID, O=Rizky Inc., OU=Private, CN=Rizky Test3, EMAILADDRESS=rizkytest3@gmail.com";
        String hashRandom="BC3AE7FBFFFD9C85A3FB234E51FFFD2190B1F8F161C0A2873B998EFAC067B03D";
        String pepsi="6E9E6264DDBD0FC997B9B40524247C8BC319D02A583F4B499DD3ECAF06C786DF";

        //Create CSR
        PKCS10CertificationRequest csr=CsrTools.createCsrRFC4683(subjectDN, hashRandom, pepsi, pair.getPrivate(), pair.getPublic());

        Extension san=CertTools.getExtension(csr, Extension.subjectAlternativeName.getId());

        GeneralNames names = CertTools.getGeneralNamesFromExtension(san);
        Assert.assertThat(names.getNames()[0].getTagNo(), CoreMatchers.is(0));

        ASN1Primitive octet=ASN1Primitive.fromByteArray(names.getNames()[0].getName().toASN1Primitive().getEncoded());
        ASN1Sequence seq = ASN1Sequence.getInstance(octet);
        Assert.assertThat(seq.getObjectAt(0).toString(), CoreMatchers.is(RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD_OBJECTID));

    }

    @Test
    public void TestCsrToolsEmail() throws Exception {

        //Generate KeyPair RSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        //Prepare data for CSR
        String subjectDN="C=ID, O=Rizky Inc., OU=Private, CN=Rizky Test3, EMAILADDRESS=rizkytest3@gmail.com";
        String sanEmail="sanEmailTest@test.com";

        //Create CSR
        PKCS10CertificationRequest csr=CsrTools.createCsrSanEmail(subjectDN, sanEmail, pair.getPrivate(), pair.getPublic());

        Extension san=CertTools.getExtension(csr, Extension.subjectAlternativeName.getId());

        GeneralNames names = CertTools.getGeneralNamesFromExtension(san);
        Assert.assertThat(names.getNames()[0].getTagNo(), CoreMatchers.is(1));

        ASN1Primitive octet=ASN1Primitive.fromByteArray(names.getNames()[0].getName().toASN1Primitive().getEncoded());
        Assert.assertThat(octet.toString(), CoreMatchers.is(sanEmail));

    }

}
