package app;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;
import util.KeyStoreReader;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";

	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException,
			NoSuchPaddingException, InvalidAlgorithmParameterException {
		// Build a new authorized API client service.
		Gmail service = getGmailService();
		ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();

		String user = "me";
		String query = "is:unread label:INBOX";

		List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
		for (int i = 0; i < messages.size(); i++) {
			Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());

			MimeMessage mimeMessage;
			try {

				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());

				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");

				mimeMessages.add(mimeMessage);

			} catch (MessagingException e) {
				e.printStackTrace();
			}
		}

		System.out.println("Select a message to decrypt:");
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

		String answerStr = reader.readLine();
		Integer answer = Integer.parseInt(answerStr);

		MimeMessage chosenMessage = mimeMessages.get(answer);

		MailBody mb = new MailBody(MailHelper.getText(chosenMessage));

		KeyStoreReader ksr;
		byte[] secretKeyBytes = null;
		try {
			ksr = new KeyStoreReader();
			// Sifra je jednostavna kako ne bih morao da je pamtim, shvatam da nije za
			// upotrebu u stvarnom svetu
			ksr.load(new FileInputStream("./data/userb.jks"), "sifra123");
			PrivateKey key = ksr.getKey("userb", "sifra123");
			Cipher rsaCipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipherDec.init(Cipher.DECRYPT_MODE, key);

			secretKeyBytes = rsaCipherDec.doFinal(mb.getEncKeyBytes());
			for (byte b : secretKeyBytes)
				System.out.print(b);
			System.out.println("\n");

		} catch (KeyStoreException | NoSuchProviderException | CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// TODO: Decrypt a message and decompress it. The private key is stored in a
		// file.
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");

		byte[] iv1 = mb.getIV1Bytes();
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);

		System.out.println(mb.getEncMessage());
		byte[] decyphMsg = null;
		try {
			decyphMsg = aesCipherDec.doFinal(mb.getEncMessageBytes());
			String receivedBodyTxt = new String(decyphMsg);
			System.out.println(receivedBodyTxt);
			String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
			System.out.println("Body text: " + decompressedBodyText);
		} catch (Exception e) {
			e.printStackTrace();
		}

		byte[] iv2 = mb.getIV2Bytes();
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);
		// inicijalizacija za dekriptovanje
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);

		// dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
		System.out.println("Subject text: " + new String(decompressedSubjectTxt));

	}
}
