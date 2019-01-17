package com.tom_roush.pdfbox.sample.signing;

import com.tom_roush.pdfbox.pdmodel.PDDocument;
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.cms.SignerInfoGenerator;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DigestCalculatorProvider;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;

public class PDFSigner {

  private X509Certificate certificate;
  private PrivateKey privateKey;

  public PDFSigner(X509Certificate cert, PrivateKey pk) {
    certificate = cert;
    privateKey = pk;
  }

  public void signDocument(File pdfDoc) throws IOException {
    PDDocument document = PDDocument.load(pdfDoc);
    signDocument(document);
    FileOutputStream out = new FileOutputStream(pdfDoc);
    document.saveIncremental(out);
  }

  public void signDocument(PDDocument document) throws IOException {

    PDSignature signature = new PDSignature();
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);

    // subfilter for basic and PAdES Part 2 signatures
    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

    // TODO load this from the certificate or args
    signature.setName("Eduard Cuba");
    signature.setLocation("Zurich, ZH");
    signature.setReason("Testing");
    signature.setSignDate(Calendar.getInstance());

    document.addSignature(signature, new PDFContentSigner());
  }

  private class PDFContentSigner implements SignatureInterface {
    @Override
    public byte[] sign(InputStream content) throws IOException {
      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      try {
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().build();
        SignerInfoGenerator sig = new JcaSignerInfoGeneratorBuilder(dcp).build(sha1Signer, certificate);
        JcaCertStore certStore = new JcaCertStore(Collections.singletonList(certificate));

        gen.addSignerInfoGenerator(sig);
        gen.addCertificates(certStore);

        CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
        CMSSignedData signedData = gen.generate(msg, false);

        return signedData.getEncoded();

      } catch (OperatorCreationException | CertificateEncodingException | CMSException e) {
        e.printStackTrace();
        return null;
      }
    }
  }
}
