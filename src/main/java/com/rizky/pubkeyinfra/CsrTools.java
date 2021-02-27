package com.rizky.pubkeyinfra;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.cesecore.util.RFC4683Tools;

public class CsrTools {

    public  static PKCS10CertificationRequest createCsrRFC4683(String subjectDN,String hashRandom,String pepsi,
            PrivateKey privKey,PublicKey pubKey)    {

        try {
            //Create SubjectDN here
            X500Principal subjectDnX500 = new X500Principal (subjectDN);

            //Create CSR Request Struct
            PKCS10CertificationRequestBuilder req=new JcaPKCS10CertificationRequestBuilder(subjectDnX500,pubKey);

            //Create Vector for RFC4683 Value (assumption using SHA-256 hash)
            ASN1EncodableVector v3 = new ASN1EncodableVector();
            v3.add(new AlgorithmIdentifier(TSPAlgorithms.SHA256));
            v3.add(new DEROctetString(hashRandom.getBytes()));
            v3.add(new DEROctetString(pepsi.getBytes()));
            DERTaggedObject rfc4683Val=new DERTaggedObject(0, new DERSequence(v3));

            //Create RFC4683 Extension Vector
            ASN1EncodableVector v2 = new ASN1EncodableVector();
            v2.add(new ASN1ObjectIdentifier(RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD_OBJECTID));
            v2.add(rfc4683Val);

            //Create OtherName Tag with RFC4683 Value
            GeneralName otherName=new GeneralName(GeneralName.otherName,
                    new DERSequence(v2));
            GeneralNames subjectAltName = new GeneralNames(otherName);

            //Create SAN Extension
            Vector oid2 = new Vector();
            Vector value2 = new Vector();

            oid2.add(Extension.subjectAlternativeName);
            value2.add(new X509Extension(false, new DEROctetString(subjectAltName)));
            X509Extensions extensions2=new X509Extensions(oid2, value2);
            
            //Create attribute set for CSR
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,new DERSet(extensions2)));
            DERSet attrSet=new DERSet(v);
            

            //Create CertRequestInfo
            CertificationRequestInfo info = new CertificationRequestInfo(
                    X500Name.getInstance(subjectDnX500.getEncoded()),                     
                    SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), attrSet);
            
            //Signed CertRequest
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privKey);
            privateSignature.update(info.getEncoded());
            
            byte[] signedRequest = privateSignature.sign();
            
            //Create Final CSR Request
            AlgorithmIdentifier algo1=AlgorithmIdentifier.getInstance(
                    new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")); 
            PKCS10CertificationRequest csr=new PKCS10CertificationRequest(
                    new CertificationRequest(info, algo1, new DERBitString(signedRequest)));
            
            return csr;

        }
        catch(Exception e)  {
            e.printStackTrace();
            return null;
            
        }
    }

    public  static PKCS10CertificationRequest createCsrSanEmail(String subjectDN,String email,
            PrivateKey privKey,PublicKey pubKey)    {

        try {
            //Create SubjectDN here
            X500Principal subjectDnX500 = new X500Principal (subjectDN);

            //Create CSR Request Struct
            PKCS10CertificationRequestBuilder req=new JcaPKCS10CertificationRequestBuilder(subjectDnX500,pubKey);
            
            //Create OtherName Tag with RFC4683 Value
            GeneralName otherName=new GeneralName(GeneralName.rfc822Name,
                    new DEROctetString(email.getBytes()));
            GeneralNames subjectAltName = new GeneralNames(otherName);
            
            //Create SAN Extension
            Vector oid2 = new Vector();
            Vector value2 = new Vector();

            oid2.add(Extension.subjectAlternativeName);
            value2.add(new X509Extension(false, new DEROctetString(subjectAltName)));
            X509Extensions extensions2=new X509Extensions(oid2, value2);
            
            //Create attribute set for CSR
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,new DERSet(extensions2)));
            
            DERSet attrSet=new DERSet(v);
            
            //Create CertRequestInfo
            CertificationRequestInfo info = new CertificationRequestInfo(
                    X500Name.getInstance(subjectDnX500.getEncoded()),                     
                    SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), attrSet);
            
            //Signed CertRequest
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privKey);
            privateSignature.update(info.getEncoded());
            
            byte[] signedRequest = privateSignature.sign();
            
            //Create Final CSR Request
            AlgorithmIdentifier algo1=AlgorithmIdentifier.getInstance(
                    new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")); 
            PKCS10CertificationRequest csr=new PKCS10CertificationRequest(
                    new CertificationRequest(info, algo1, new DERBitString(signedRequest)));
            
            return csr;

        }
        catch(Exception e)  {
            e.printStackTrace();
            return null;
            
        }
    }

}
