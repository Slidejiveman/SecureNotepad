import org.apache.commons.codec.binary.Base64;

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
 * Created by rdnot on 10/4/2017.
 * https://www.sourcecodester.com/java/5834/how-create-notepad-project-java.html
 */
class NotePad extends JFrame {

    private int fileToOpen, fileToSave;
    private JFileChooser fileOpen, fileSave;
    private String queryTitle = "Encrypt?";
    private String query = "Would you like to encrypt this file?";
    private String passwordLabelText = "Password: ";
    private String passwordPaneTitle = "Enter an Encryption/Decryption Key";
    private IvParameterSpec iv;
    private byte[] ivBytes = new byte[16];

    NotePad() {
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
        newFile.addActionListener( e -> textArea.setText(""));
        open.addActionListener(e -> {
            openFile();
            if (fileToOpen == JFileChooser.APPROVE_OPTION) {
                textArea.setText("");
                try {
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

                    if(!new String(tag).equals("<ENC>")) {
                        // Using a scanner because it handles the case where the file is
                        // less than 5 bytes long
                        Scanner scan = new Scanner(new FileReader(f.getPath()));
                        while (scan.hasNext()) {
                            textArea.append(scan.nextLine());
                        }
                    } else {
                        String password = askForPassword(); // Need to handle passwords (destroy after use)
                        if(!password.equals("")) {
                            byte[] key = buildKey(password);
                            if (key != null && key.length > 0) {
                                // For now, just decrypt it and don't worry about a password yet.
                                byte[] plainText = decryptFile(key, message, ivMsg);
                                textArea.append(new String(plainText, "UTF-8"));
                            }
                        } // else display that the password was invalid and set the text area to be empty
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

            String password = handleEncryption();
            if (!password.equals("")) {
                key = buildKey(password);
                cipherText = encryptMessage(key, textArea.getText());
            }
            saveFile();
            if(fileToSave == JFileChooser.APPROVE_OPTION) {
                try {
                    FileOutputStream out = new FileOutputStream(fileSave.getSelectedFile().getPath());
                    if (!password.equals("")) {
                        out.write("<ENC>".getBytes());
                        out.write(ivBytes);
                        out.write(cipherText); // need to provide a tag to know if a file needs decryption
                    }
                    else {
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

    // to this method, I'll need to modify the code so it can tell whether
    // the file is encrypted or not
    private void openFile() {
        JFileChooser open = new JFileChooser();
        fileToOpen = open.showOpenDialog(this);
        fileOpen = open;
    }

    private void saveFile() {
        JFileChooser save = new JFileChooser();
        fileToSave = save.showSaveDialog(this);
        fileSave = save;
    }

    /**
     * https://stackoverflow.com/questions/8881213/joptionpane-to-get-password
     * @return
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
                    System.out.println("The encryption password is: " + new String(password));
                    return new String(new String(password).getBytes("UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    System.err.println("I AM ERROR: String encoding for password is not supported.");
                }
            }
        }
        return "";
    }

    /**
     * https://stackoverflow.com/questions/3103652/hash-string-via-sha-256-in-java
     * https://stackoverflow.com/questions/3451670/java-aes-and-using-my-own-key
     * @param password - the password entered in by the user
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
                System.out.println("This is the hash of the password: " + new String(key, "UTF-8"));
                return key;
            }
        } catch (UnsupportedEncodingException e) {
            System.err.println("I AM ERROR: The specified character set doesn't exist.");
            System.err.println(e.getMessage());
        }

        return null;
    }

    /**
     * https://stackoverflow.com/questions/20796042/aes-encryption-and-decryption-with-java
     * @param key - the key to use for encryption
     * @param text - the text to encrypt
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
            // This is the same key needed for decryption
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES"); // When no longer needed, keys must go!
            System.out.println("This is the encrypt function keyspec: " +new String(secretKeySpec.getEncoded()));
            Cipher AesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            AesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
            cipherText = AesCipher.doFinal(plainText);
            System.out.println("This is the ciphertext after generation: " + new String(cipherText));
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
                System.out.println("The decryption password is: " + new String(password));
                return new String(new String(password).getBytes("UTF-8"));
            } catch (UnsupportedEncodingException e) {
                System.err.println("I AM ERROR: String encoding for password is not supported.");
            }
        }
        return "";
    }

    private byte[] decryptFile(byte[] key, byte[] cipherText, byte[] ivMsg) {
        byte[] plainText;
        IvParameterSpec ivReadIn = new IvParameterSpec(ivMsg);

        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            System.out.println("This is the decrypt function keyspec: " + new String(secretKeySpec.getEncoded()));
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
        } catch (BadPaddingException e) {
            System.err.println("I AM ERROR: The provided padding is bad.");
            System.err.println(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            System.err.println("I AM ERROR: The used block size is illegal.");
            System.err.println(e.getMessage());
        }  catch (InvalidAlgorithmParameterException e) {
            System.err.println("I AM ERROR: This iv is considered an illegal parameter.");
            System.err.println(e.getMessage());
        }
        return null;
    }
}
