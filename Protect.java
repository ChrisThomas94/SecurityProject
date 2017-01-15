package coursework;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Protect {

    //SET DIRECTORY
    final protected static String directory = "C:\\Users\\Chris\\Documents\\Uni\\Stage 3\\Security\\SUBMISSION - Copy\\Q1";

    //set these two values as true for first initialization
	static boolean startUp = false;
	static boolean startingUp = false;

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private static final Random RANDOM = new SecureRandom();
	final static ArrayList<String> originalFiles = new ArrayList<String>();
	final static ArrayList<String> originalAuxFiles = new ArrayList<String>();
	//used hash set as add items to object in 2 different places making array list difficult
	static HashSet<String> auxFiles = new HashSet<String>();

	static Scanner scanner;
	static byte[] ivBytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	public static void main(String[] args) throws Exception {

		if(startingUp){
			//init();
			
		} else {
		
			if (args.length == 0) {
				System.out.println("You must specify an operation!");
	
			} else if (args[0].equals("-e") || args[0].equals("-d")) {
				
				if(args.length == 1){
					System.out.println("You must specify a file!");
				} else {
					
					if(args.length == 2){
						System.out.println("A password is required!");
						
					} else {
					
						String operationDesc;
						String operation = args[0];
						String filename = args[1];
						String filepath = directory + "/" + args[1];
						char[] inputPass = args[2].toCharArray();
						byte[] hashedPass = hash(inputPass);
						byte[] fetchedPass;
						
						if(args[0].equals("-d")){
							operationDesc = "decrypting";
						} else {
							operationDesc = "encrypting";
						}
						
						System.out.println("User is " + operationDesc + " " + filename + " using the password: " + args[2]);
	
						
						if(!checkFileExists(filepath)){
							System.out.println("File does not exist!");
							
						} else {
							
							if(operation.equals("-d") && filename.contains(".enc")){
								filepath = filepath.substring(0, filepath.length() - 4);
							}

							fetchedPass = getHashedPass(operation, filepath);

				
							if (args[0].equals("-e") && isExpectedPassword(hashedPass, fetchedPass)) {
								
								// generate AES key using hashed write password
								SecretKeySpec writeKey = new SecretKeySpec(fetchedPass, "AES");
	
								// decrypt AES key using the key generated above
								byte[] decryptedAESW = decryptAESKey(operation, filepath, writeKey, ivBytes);
	
								// trim AES key to remove 16 unwanted bytes
								byte[] trimmed = Arrays.copyOfRange(decryptedAESW, 0, decryptedAESW.length - 16);
	
								// use trimmed decrypted key to encrypt file
								encryptFile(filepath, trimmed, ivBytes);
	
								// delete plaintext file
								File file = new File(filepath);
								file.delete();
				
							} else if (args[0].equals("-d") && isExpectedPassword(hashedPass, fetchedPass)) {
				
								// generate AES key using the hashed read password
								SecretKeySpec readKey = new SecretKeySpec(fetchedPass, "AES");
				
								// decrypt filename_AES key using the key generated above
								byte[] decryptedAESR = decryptAESKey(operation, filepath, readKey, ivBytes);
				
								// trim AES key to remove 16 unwanted bytes
								byte[] trimmed = Arrays.copyOfRange(decryptedAESR, 0, decryptedAESR.length - 16);
				
								// use trimmed decrypted key to decrypt file
								boolean verify = decryptFile(filepath, trimmed, ivBytes);
								
								if(verify){
									File file = new File(filepath + ".enc");
									file.delete();
								}
				
							} else if (!isExpectedPassword(hashedPass, fetchedPass)) {
								System.out.println("Error: incorrect password!");
				
							}
						}
					}
				}
			
			} else if (args[0].equals("-c")) {
				//delete all files from directory that are not encrypted
				check();
	
			} else if (!args[0].equals("-e") && !args[0].equals("-d") && !args[0].equals("-c")) {
				// invalid argument
				System.out.println("Invalid Argument!\n-e to Encrypt\n-d to Decrypt\n-c to Wipe");
	
			}
		}
	}

	//fetch the stored password hash
	public static byte[] getHashedPass(String arg, String filepath) throws FileNotFoundException {
		
		File passFile = new File(filepath + "_password_hash.enc");
		byte[] hashedPass = null;
		try {
			scanner = new Scanner(passFile);

			while (scanner.hasNext()) {
				scanner.nextLine();

				String fileName = scanner.next();

				if (arg.equals("-e")) {
					// fetch write password
					scanner.next();
					String hashedWP = scanner.next();
					// System.out.println("hashedWP: " + hashedWP);
					hashedPass = hexStringToByteArray(hashedWP);
					break;

				} else if (arg.equals("-d")) {
					// fetch read password
					String hashedRP = scanner.next();
					// System.out.println("stored hashedRP: " + hashedRP);
					hashedPass = hexStringToByteArray(hashedRP);
					break;

				}
			}
		} finally {

		}
		return hashedPass;
	}

	//check entered password hash matches stored password hash
	public static boolean isExpectedPassword(byte[] inputHash, byte[] expectedHash) throws InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {

		String pass = bytesToHex(inputHash);
		String check = bytesToHex(expectedHash);

		if(pass.equals(check)){
			return true;
		} else {
			return false;
		}
	}

	//encrypt AES key using hashed password as the key
	public static byte[] encryptAESKey(byte[] aesBytes, byte[] keyBytes, byte[] ivBytes) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {


		SecretKeySpec fileKey = new SecretKeySpec(keyBytes, "AES");

		SecretKeySpec AESKey = new SecretKeySpec(aesBytes, "AES");
		byte[] byteAESKey = AESKey.getEncoded();

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		aesCipher.init(Cipher.ENCRYPT_MODE, fileKey, ivSpec);
		byte[] encrypted = new byte[aesCipher.getOutputSize(byteAESKey.length)];
		int enc_len = aesCipher.update(byteAESKey, 0, byteAESKey.length, encrypted, 0);
		enc_len += aesCipher.doFinal(encrypted, enc_len);

		return encrypted;
	}

	//decrypt AES key using hashed password as the key
	public static byte[] decryptAESKey(String arg, String filename, SecretKeySpec key, byte[] ivBytes) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {

		// get write aes key
		byte[] AESKey = null;
		File passFile = new File(filename + "_AES.enc");

		try {
			scanner = new Scanner(passFile);

			while (scanner.hasNext()) {
				scanner.nextLine();

				String fileName = scanner.next();

				if (arg.equals("-e")) {

					// fetch write password
					scanner.next();
					String encryptedWAES = scanner.next();
					AESKey = hexStringToByteArray(encryptedWAES);
					break;

				} else if (arg.equals("-d")) {

					// fetch read password
					String encryptedRAES = scanner.next();
					AESKey = hexStringToByteArray(encryptedRAES);
					break;
				}
			}
		} finally {

		}

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

		Cipher desCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		desCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		byte[] decrypted = new byte[desCipher.getOutputSize(AESKey.length)];
		int dec_len = desCipher.update(AESKey, 0, AESKey.length, decrypted, 0);
		dec_len += desCipher.doFinal(decrypted, dec_len);

		return decrypted;
	}

	//encrypt content file using decrypted AES file key
	public static void encryptFile(String filepath, byte[] keyBytes, byte[] ivBytes) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, SignatureException {

		byte[] input = null;
		
		if(!startUp){
			input = Files.readAllBytes(Paths.get(filepath));
		} else {
			input = Files.readAllBytes(Paths.get(filepath));
		}
		
		SecretKeySpec fileKey = new SecretKeySpec(keyBytes, "AES");

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		aesCipher.init(Cipher.ENCRYPT_MODE, fileKey, ivSpec);
		byte[] encrypted = new byte[aesCipher.getOutputSize(input.length)];
		int enc_len = aesCipher.update(input, 0, input.length, encrypted, 0);
		enc_len += aesCipher.doFinal(encrypted, enc_len);

		FileOutputStream fos = new FileOutputStream(filepath + ".enc");
		fos.write(encrypted);
		fos.close();

		System.out.println("File Encrypted Successfully");

		// create signature for filename.enc
		generateSignature(filepath, encrypted);
	}

	//encrypt content file using decrypted AES file key
	public static boolean decryptFile(String filepath, byte[] keyBytes, byte[] ivBytes) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, SignatureException, InvalidKeySpecException {

		byte[] input = Files.readAllBytes(Paths.get(filepath + ".enc"));
		byte[] decrypted = null;
		boolean verifySig = verifyFileSignature(filepath, input);

		// create signature for filename.enc
		if(verifySig){

			SecretKeySpec fileKey = new SecretKeySpec(keyBytes, "AES");

			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
			Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			try {
				aesCipher.init(Cipher.DECRYPT_MODE, fileKey, ivSpec);
				decrypted = new byte[aesCipher.getOutputSize(input.length)];
				int enc_len = aesCipher.update(input, 0, input.length, decrypted, 0);
				enc_len += aesCipher.doFinal(decrypted, enc_len);

				//String filenameTrim = filepath.substring(0, filepath.length() - 4);

				FileOutputStream fos = new FileOutputStream(filepath);
				fos.write(decrypted);
				fos.close();

				System.out.println("File Decrypted Successfully");

			} catch (IllegalBlockSizeException e) {

				System.out.println("Incorrect signature, the file has been tampered with!");
			}
		} else {
			System.out.println("Incorrect Signature!");
		}

		return verifySig;

	}

	//generate signature of encrypted content file
	private static void generateSignature(String filepath, byte[] encrypted) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
				
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, random);
		
		KeyPair pair = keyGen.generateKeyPair();
		
		//System.out.println("key pair "+pair);
		
		Signature dsa = Signature.getInstance("SHA1withRSA");
		
		/* Initializing the object with a private key */
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		dsa.initSign(priv);

		/* Update and sign the data */
		dsa.update(encrypted);
		byte[] sig = dsa.sign();
		byte[] publicKey = pub.getEncoded();
		
		Path p = Paths.get(filepath);
		String signatureFile = p.getFileName().toString()+ "_signature.enc";
		
		FileOutputStream fos = new FileOutputStream(filepath + "_signature.enc");
		fos.write(sig);
		fos.close();
		
		//originalAuxFilesHashSet.add(signatureFile);
		auxFiles.add(signatureFile);
		
		p = Paths.get(filepath);
		String publicKeyFile = p.getFileName().toString()+ "_pk.enc";
				
		fos = new FileOutputStream(filepath + "_pk.enc");
		fos.write(publicKey);
		fos.close();
		
		//originalAuxFilesHashSet.add(publicKeyFile);
		auxFiles.add(publicKeyFile);
		
	}

	//verify signature of encrypted content file
	private static boolean verifyFileSignature(String filename, byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException, IOException, InvalidKeySpecException {

		if(filename.contains(".enc")) {
			filename = filename.substring(0, filename.length() - 4);
		}

		byte[] pk = Files.readAllBytes(Paths.get(filename + "_pk.enc"));
		byte[] sig = Files.readAllBytes(Paths.get(filename + "_signature.enc"));

		String publicK = bytesToHex(pk);
		String sign = bytesToHex(sig);
		
		//System.out.println("public key "+ publicK);
		//System.out.println("sig " + sign);

		Signature dsa = Signature.getInstance("SHA1withRSA");
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pk);
		PublicKey pub = keyFactory.generatePublic(pubKeySpec);

		//PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
		dsa.initVerify(pub);

		/* Update and verify the data */
		dsa.update(input);
		boolean verifies = dsa.verify(sig);
		//System.out.println("signature verifies: " + verifies);
		
		return verifies;
	}

	//check for invalid files
	public static void check() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException {

		boolean fileListExists = true;
		boolean auxFileListExists = true;

		if(originalFiles.size() == 0){
			fileListExists = updateFileList();
			//System.out.println("\n");

		}

		if(originalAuxFiles.size() == 0){
			auxFileListExists = updateAuxFileList();
			//System.out.println("\n");

		}

		if(fileListExists && auxFileListExists) {
			// enter directory here
			final File folder = new File(directory);

			File[] files = folder.listFiles();

			HashSet<String> allFiles = new HashSet<String>();

			ArrayList<String> currentFiles = new ArrayList<String>();
			currentFiles = originalFiles;

			ArrayList<String> currentAuxFiles = new ArrayList<String>();
			currentAuxFiles = originalAuxFiles;

			for (File file : files) {
				// if file DOES NOT end with .enc or if filename is less than 4
				// chars long
				if (file.getName().length() < 4 || !file.getName().substring(file.getName().length() - 4, file.getName().length()).equals(".enc")) {
					System.out.println("File Unencrypted, File Deleted: " + file);
					// delete file
					file.delete();
				} else {

					allFiles.add(file.getName());
				}

				for (int i = 0; i < originalFiles.size(); i++) {
					if (file.getName().equals(originalFiles.get(i) + ".enc")) {
                        allFiles.remove(file.getName());

						byte[] input = Files.readAllBytes(Paths.get(file.toURI()));
						boolean verifySig = verifyFileSignature(file.toString(), input);

						if (!verifySig) {
							System.out.println("Invalid Signature, File Deleted: " + file);
							file.delete();
						} else {
                            currentFiles.remove(i);
                            currentFiles.remove(file.getName());
                        }


					} else if (file.getName().equals("aux_file_list.enc") || file.getName().equals("file_list.enc") || file.getName().equals(originalFiles.get(i) + "_signature.enc") || file.getName().equals(originalFiles.get(i) + "_pk.enc")) {

						allFiles.remove(file.getName());
					}
				}

				for (int i = 0; i < originalAuxFiles.size(); i++) {
					if (file.getName().equals(originalAuxFiles.get(i))) {
						currentAuxFiles.remove(i);
						currentAuxFiles.remove(file.getName());
						allFiles.remove(file.getName());
					} else if (file.getName().equals("aux_file_list.enc") || file.getName().equals("file_list.enc")) {

						allFiles.remove(file.getName());
					}
				}
			}

			System.out.println("Additional Files: " + allFiles);
			System.out.println("Missing Original Files: " + currentFiles);
			System.out.println("Missing Original Aux Files: " + currentAuxFiles);

			for (File file : files) {
				if (allFiles.contains(file.getName())) {
					System.out.println("\nAdditional File, File Deleted: " + file);
					file.delete();
				}

			}
		} else {

			if (!fileListExists && !auxFileListExists) {
				System.out.println("The file_list and the aux_file_list cannot be found in the directory. Therefore this operation cannot be carried out accurately, please contact the system admin.");
			} else if (!fileListExists){
				System.out.println("The file_list cannot be found in the directory. Therefore this operation cannot be carried out accurately, please contact the system admin.");
			} else {
				System.out.println("The aux_file_list cannot be found in the directory. Therefore this operation cannot be carried out accurately, please contact the system admin.");
			}
		}

	}

	//fetch list of original files in directory
	public static boolean updateFileList() throws FileNotFoundException {

		String files = directory + "/file_list.enc";

		boolean fileListExists = checkFileExists(files);

		if(fileListExists){

			File fileList = new File(directory + "/file_list.enc");
			String file;
			int fileNo = 0;
			scanner = new Scanner(fileList);

			scanner.nextLine();

			while (scanner.hasNext()) {
				fileNo++;
				file = scanner.next();
				originalFiles.add(file);
				//System.out.println("File Number " + fileNo + ": " + file);
			}
			scanner.close();
		}

		return fileListExists;

	}

	//fetch list of original aux files in directory
	public static boolean updateAuxFileList() throws FileNotFoundException{

		String files = directory + "/aux_file_list.enc";

		boolean auxFileExists = checkFileExists(files);

		if(auxFileExists){

			File fileList = new File(files);
			String file;
			int fileNo = 0;
			scanner = new Scanner(fileList);

			while (scanner.hasNext()) {
				fileNo++;
				file = scanner.next();
				originalAuxFiles.add(file);
				//originalAuxFilesHashSet.add(file);
				//System.out.println("Aux File Number " + fileNo + ": " + file);
			}
			scanner.close();
		}

		return  auxFileExists;
	}

	//generate some random bytes
	public static byte[] randomBytes() {
		byte[] salt = new byte[16];
		RANDOM.nextBytes(salt);
		return salt;
	}

	//hash function
	public static byte[] hash(char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {

		byte[] keyBytes = (new String(password)).getBytes("UTF-8");
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		keyBytes = sha.digest(keyBytes);
		keyBytes = Arrays.copyOf(keyBytes, 16);
		return keyBytes;
	}

	//http://stackoverflow.com/questions/1816673/how-do-i-check-if-a-file-exists-in-java
	public static boolean checkFileExists(String filepath){
		
		File file = new File(filepath);
		
		if(file.exists() && !file.isDirectory()) { 
		    return true;
		}
		
		return false;
	}

	//http://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	//http://stackoverflow.com/questions/8890174/in-java-how-do-i-convert-a-hex-string-to-a-byte
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

}
