import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.*;
import java.util.Scanner;

/**
 * This class handles the logic as well as the layout of the NotePad.
 *
 * Created by rdnot on 10/4/2017.
 * https://www.sourcecodester.com/java/5834/how-create-notepad-project-java.html
 */
class NotePad extends JFrame {

    /**
     * FileToOpen and FileToSave are int values that determine what
     * JFileChooser Option was selected. It is used to determine
     * branches in the code.
     */
    private int fileToOpen, fileToSave;
    /**
     * fileOpen and fileSave are the JFileChoosers used to open and save the application
     * respectively.
     */
    private JFileChooser fileOpen, fileSave;
    /**
     * This string is used as the title of the encryption query popup.
     */
    private String queryTitle = "Encrypt?";
    /**
     * This string is the query presented to the user
     */
    private String query = "Would you like to encrypt this file?";
    /**
     * This string appears on the password JOptionPanes
     */
    private String passwordLabelText = "Password: ";
    /**
     * This string is the title of the password JOptionPanes
     */
    private String passwordPaneTitle = "Enter an Encryption/Decryption Key";
    /**
     * This is the iv used for encryption
     */
    private IvParameterSpec iv;
    /**
     * These bytes are used to hold the randomly generated Initialization Vector
     */
    private byte[] ivBytes = new byte[16];

    /**
     * The Default no argument constructor
     */
    NotePad() {
        // Create and layout the components
        MenuBar menuBar = new MenuBar();
        final JTextArea textArea = new JTextArea();
        setMenuBar(menuBar);
        Menu file = new Menu("File");
        menuBar.add(file);
        MenuItem newFile = new MenuItem("New");
        MenuItem open = new MenuItem("Open");
        MenuItem save = new MenuItem("Save");
        MenuItem exit = new MenuItem("Exit");
        file.add(newFile);
        file.add(open);
        file.add(save);
        file.add(exit);
        getContentPane().add(textArea);

        // Add the Listeners for the MenuItems
        newFile.addActionListener( e -> textArea.setText(""));
        open.addActionListener(e -> {
            openFile();

            // if the user chose to encrypt
            if (fileToOpen == JFileChooser.APPROVE_OPTION) {
                textArea.setText("");
                try {
                    // Open the file and read out the tag, iv, and message.
                    File f = fileOpen.getSelectedFile();
                    byte[] tag = new byte[5];
                    byte[] message = null;
                    byte[] ivMsg = new byte[16];
                    if (f.length() >= 21) { // Want to avoid negative array size
                        message = new byte[(int) f.length() - 21];
                        FileInputStream inputStream = new FileInputStream(f);
                        inputStream.read(tag);
                        inputStream.read(ivMsg);
                        inputStream.read(message);
                    }

                    // If tag is equal to this tag, then the message must be decrypted.
                    // If it isn't, then just use the scanner and read all the text in.
                    if(!new String(tag).equals("<ENC>")) {
                        // Using a scanner because it handles the case where the file is
                        // less than 5 bytes long
                        Scanner scan = new Scanner(new FileReader(f.getPath()));
                        while (scan.hasNext()) {
                            textArea.append(scan.nextLine());
                        }
                    } else {
                        // We found <ENC>, so the file must be decrypted.
                        String password = askForPassword();
                        if(!password.equals("")) {
                            byte[] key = buildKey(password); // the same password will hash to the same key
                            if (key != null && key.length > 0) {
                                byte[] plainText = decryptFile(key, message, ivMsg); // key and iv both needed for CBC
                                textArea.append(new String(plainText, "UTF-8"));
                            }
                        }
                    }
                } catch (IOException iEx) {
                    System.err.println("I AM ERROR: Error occurred while opening file.");
                    System.err.println(iEx.getMessage());
                }
            }
        });
        save.addActionListener(e -> {
            byte[] cipherText = null;
            byte[] key;

            // Determine if we need to encrypt the file on save.
            String password = handleEncryption();
            if (!password.equals("")) {
                // if there is a password, then it needs to be encrypted.
                key = buildKey(password);
                cipherText = encryptMessage(key, textArea.getText());
            }
            saveFile();
            if(fileToSave == JFileChooser.APPROVE_OPTION) {
                // We chose to encrypt, so write out the message, the iv, then the cipher text
                try {
                    FileOutputStream out = new FileOutputStream(fileSave.getSelectedFile().getPath());
                    if (!password.equals("")) {
                        out.write("<ENC>".getBytes());
                        out.write(ivBytes);
                        out.write(cipherText); // need to provide a tag to know if a file needs decryption
                    }
                    else {
                        // Just write out all of the bytes if we don't need to encrypt
                        out.write(textArea.getText().getBytes());
                    }
                    out.close();
                } catch(IOException iEx) {
                    System.err.println("I AM ERROR: There was an error saving the file.");
                    System.err.println(iEx.getMessage());
                }
            }
        });
        exit.addActionListener(e -> System.exit(0));
    }

    /**
     * Creates the Open JFileChooser and prepares it for use
     */
    private void openFile() {
        JFileChooser open = new JFileChooser();
        fileToOpen = open.showOpenDialog(this);
        fileOpen = open;
    }

    /**
     * Creates the Save JFileChooser and prepares it for use
     */
    private void saveFile() {
        JFileChooser save = new JFileChooser();
        fileToSave = save.showSaveDialog(this);
        fileSave = save;
    }

    /**
     * Determine whether or not we want to encrypt the file. If we do, return
     * the entered password.
     *
     * https://stackoverflow.com/questions/8881213/joptionpane-to-get-password
     * @return - the password entered by the user or the empty string if not entered.
     */
    private String handleEncryption() {
        // This value will be used to determine whether or not to encrypt the file
        int saveEncrypted = JOptionPane.showOptionDialog(this,
                query, queryTitle, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, null, JOptionPane.YES_OPTION);

        // if YES is selected, then collect a password
        if (saveEncrypted == JOptionPane.YES_OPTION) { // The YES_OPTION should equal 0. No is 1.
            // Take the steps needed to encrypt the file.
            JPanel passwordPanel = new JPanel();
            JLabel passwordLabel = new JLabel(passwordLabelText);
            JPasswordField passwordField = new JPasswordField(10);
            passwordPanel.add(passwordLabel);
            passwordPanel.add(passwordField);
            int selection = JOptionPane.showOptionDialog(this, passwordPanel, passwordPaneTitle,
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null,
                    JOptionPane.OK_OPTION);

            // if OK was selected, then a password was entered. Beware of sizing issues here.
            if (selection == JOptionPane.OK_OPTION) {
                try {
                    char[] password = passwordField.getPassword();
                    return new String(new String(password).getBytes("UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    System.err.println("I AM ERROR: String encoding for password is not supported.");
                }
            }
        }
        return "";
    }

    /**
     * Build the key with the given password. This uses SHA-256 to hash the password
     * into a usable key for AES/CBC encryption
     *
     * https://stackoverflow.com/questions/3103652/hash-string-via-sha-256-in-java
     * https://stackoverflow.com/questions/3451670/java-aes-and-using-my-own-key
     * @param password - the password entered in by the user
     * @return key - the key hashed from the password
     */
    private byte[] buildKey(String password) {
        MessageDigest digest = null;
        byte[] key;

        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("I AM ERROR: The provided algorithm doesn't exist.");
            System.err.println(e.getMessage());
        }
        try {
            if (digest != null) {
                key = digest.digest(password.getBytes("UTF-8"));
                return key;
            }
        } catch (UnsupportedEncodingException e) {
            System.err.println("I AM ERROR: The specified character set doesn't exist.");
            System.err.println(e.getMessage());
        }

        return null;
    }

    /**
     * This function encrypts a message using AES in CBC mode with some padding.
     * The padding fills out the 16 byte blocks so the block cipher is legal.
     *
     * https://stackoverflow.com/questions/20796042/aes-encryption-and-decryption-with-java
     * @param key - the key to use for encryption
     * @param text - the text to encrypt
     * @return cipherText - the encrypted message as an array of bytes
     */
    private byte[] encryptMessage(byte[] key, String text) {
        byte[] cipherText;
        byte[] plainText = null;
        try {
            plainText = text.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        // Generate the iv
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);

        try {
            // This is the same key needed for decryption.
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher AesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            AesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
            cipherText = AesCipher.doFinal(plainText);
            return cipherText;
        } catch (NoSuchAlgorithmException e) {
            System.err.println("I AM ERROR: The provided algorithm doesn't exist for encryption.");
            System.err.println(e.getMessage());
        } catch (NoSuchPaddingException e) {
            System.err.println("I AM ERROR: The provided padding method doesn't exist.");
            System.err.println(e.getMessage());
        } catch (InvalidKeyException e) {
            System.err.println("I AM ERROR: The provided key is invalid.");
            System.err.println(e.getMessage());
        } catch (BadPaddingException e) {
            System.err.println("I AM ERROR: The provided padding is bad.");
            System.err.println(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            System.err.println("I AM ERROR: The used block size is illegal.");
            System.err.println(e.getMessage());
        }  catch (InvalidAlgorithmParameterException e) { // This error occurs if I use this code
            System.err.println("I AM ERROR: This iv is considered an illegal parameter.");
            System.err.println(e.getMessage());
        }

        return null;
    }

    /**
     * Asks the user for a password if the file is encrypted.
     * @return password - the password as a string or the empty string if canceled.
     */
    private String askForPassword() {
        // Take the steps needed to encrypt the file.
        JPanel passwordPanel = new JPanel();
        JLabel passwordLabel = new JLabel(passwordLabelText);
        JPasswordField passwordField = new JPasswordField(10);
        passwordPanel.add(passwordLabel);
        passwordPanel.add(passwordField);
        int selection = JOptionPane.showOptionDialog(this, passwordPanel, passwordPaneTitle,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null,
                JOptionPane.OK_OPTION);

        // if OK was selected, then a password was entered. Beware of sizing issues here.
        if (selection == JOptionPane.OK_OPTION) {
            try {
                char[] password = passwordField.getPassword(); // Don't store these in the end product
                return new String(new String(password).getBytes("UTF-8"));
            } catch (UnsupportedEncodingException e) {
                System.err.println("I AM ERROR: String encoding for password is not supported.");
            }
        }
        return "";
    }

    /**
     * This method decrypts the file by doing the same operations as the encryption method
     * but opening the Cipher in the decryption mode
     *
     * TODO: Combine the encryption and decryption methods. Pass in a flag in order to determine the mode
     *
     * @param key - the key used for the decryption
     * @param cipherText - the ciphertext to decrypt
     * @param ivMsg - the initialization vector stored with the file
     * @return plaintext - the array of plaintext as bytes
     */
    private byte[] decryptFile(byte[] key, byte[] cipherText, byte[] ivMsg) {
        byte[] plainText;
        IvParameterSpec ivReadIn = new IvParameterSpec(ivMsg);

        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher AesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            AesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivReadIn);
            plainText = AesCipher.doFinal(cipherText);
            return plainText;
        } catch (NoSuchAlgorithmException e) {
            System.err.println("I AM ERROR: The provided algorithm doesn't exist for encryption.");
            System.err.println(e.getMessage());
        } catch (NoSuchPaddingException e) {
            System.err.println("I AM ERROR: The provided padding method doesn't exist.");
            System.err.println(e.getMessage());
        } catch (InvalidKeyException e) {
            System.err.println("I AM ERROR: The provided key is invalid.");
            System.err.println(e.getMessage());
            showDecryptionFailure(); // Display that the decryption did not succeed.
        } catch (BadPaddingException e) {
            System.err.println("I AM ERROR: The provided padding is bad.");
            System.err.println(e.getMessage());
            showDecryptionFailure(); // Display that the decryption did not succeed.
        } catch (IllegalBlockSizeException e) {
            System.err.println("I AM ERROR: The used block size is illegal.");
            System.err.println(e.getMessage());
        }  catch (InvalidAlgorithmParameterException e) {
            System.err.println("I AM ERROR: This iv is considered an illegal parameter.");
            System.err.println(e.getMessage());
        }
        return null;
    }

    private void showDecryptionFailure() {
        JOptionPane.showOptionDialog(this,
                "The decryption did not succeed.","Decryption Failure",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null,
                JOptionPane.OK_OPTION);
    }
}
