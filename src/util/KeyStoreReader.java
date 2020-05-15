package util;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreReader {
	KeyStore ks;

	public KeyStoreReader() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
		ks = ks.getInstance("JKS", "SUN");
		ks.load(null);
	}
	
	public void load(InputStream is, String password) throws NoSuchAlgorithmException, CertificateException, IOException {
		ks.load(is, password.toCharArray());
	}
	
	public Certificate getCertificate(String alias) {
		try {
			
			return ks.getCertificate(alias);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}
	
	public PrivateKey getKey(String alias, String password) {
		try {
			return (PrivateKey)ks.getKey(alias, password.toCharArray());
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

}
