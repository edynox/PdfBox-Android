package com.tom_roush.pdfbox.sample;

import android.app.Activity;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Toast;

import com.github.barteksc.pdfviewer.PDFView;
import com.tom_roush.pdfbox.pdmodel.PDDocument;
import com.tom_roush.pdfbox.sample.signing.PDFSigner;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class MainActivity extends Activity {

  File root;
  PDDocument document;
  PDFView pdfView;
  Integer pageNumber = 0;
  AssetManager assetManager;


  @Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    root = android.os.Environment.getExternalStorageDirectory();
    pdfView = findViewById(R.id.pdfView);
    assetManager = getAssets();
    downloadPdf(null);
  }

  protected void makeToast(String message) {
    Toast.makeText(getApplicationContext(), message, Toast.LENGTH_SHORT).show();
  }

	// load a custom PDF
	protected void getRemotePdf() {
    try {
      URL url = new URL("https://vetri.global/wp-content/themes/vetri/documents/whitepaper.pdf");
      URLConnection conn = url.openConnection();

      int size = conn.getContentLength();
      DataInputStream stream = new DataInputStream(url.openStream());

      byte[] buffer = new byte[size];
      stream.readFully(buffer);
      stream.close();

      document = PDDocument.load(buffer);
    } catch (IOException e) {
      makeToast("Error: " + e.getMessage());
      e.printStackTrace();
    }
  }

  protected void renderPdf() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      document.save(out);
      pdfView.fromBytes(out.toByteArray())
          .defaultPage(pageNumber)
          .enableSwipe(true)
          .swipeHorizontal(false)
          .load();
    } catch (IOException e) {
      makeToast("Error: " + e.getMessage());
      e.printStackTrace();
    }
  }

  // FIXME: loading and signing a PDF twice damages the PDF
  protected void getLocalPdf() {
    try {
      document = PDDocument.load(new File(root.getAbsolutePath() + "/Download/test.pdf"));
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void downloadPdf(View v) {
    makeToast("Loading");
    Thread thread = new Thread(new Runnable() {
      @Override
      public void run() {
        getRemotePdf();
        // getLocalPdf();
        renderPdf();
      }
    });
    thread.start();
  }

  public void savePdf(View v) {
    String path = root.getAbsolutePath() + "/Download/test.pdf";
    try {
      FileOutputStream out = new FileOutputStream(path);
      document.saveIncremental(out);
      makeToast("Saved to: " + path);
    } catch (IOException e) {
      makeToast("Error: " + e.getMessage());
      e.printStackTrace();
    }
  }

  public void signPdf(View v) {

    PDFSigner signer = new PDFSigner(getCertificate(), getPrivateKey());

    try {
      signer.signDocument(document);
      makeToast("Success");
    } catch (IOException e) {
      makeToast("Error: " + e.getMessage());
      e.printStackTrace();
    }

  }

  protected PrivateKey getPrivateKey() {

    try {

      StringBuilder pkcs8Lines = new StringBuilder();
      InputStream key = assetManager.open("key.pem");

      BufferedReader in = new BufferedReader(new InputStreamReader(key, StandardCharsets.UTF_8));
      String str;

      while ((str=in.readLine()) != null) {
        pkcs8Lines.append(str);
      }

      in.close();

      // Remove the "BEGIN" and "END" lines, as well as any whitespace

      String pkcs8Pem = pkcs8Lines.toString();
      pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
      pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
      pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

      // Base64 decode the result

      byte [] pkcs8EncodedBytes = Base64.decode(pkcs8Pem, Base64.DEFAULT);

      // extract the private key

      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");

      return kf.generatePrivate(keySpec);
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      makeToast("Error: " + e.getMessage());
      e.printStackTrace();
    }
    return null;
  }

  protected X509Certificate getCertificate() {
    try {
      BufferedInputStream bis = new BufferedInputStream(assetManager.open("cert.pem"));
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(bis);
    } catch (IOException | CertificateException e) {
      makeToast("Error: " + e.getMessage());
      e.printStackTrace();
    }
    return null;
  }
}