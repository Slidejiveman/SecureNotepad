import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

/**
 * Created by rdnot on 10/4/2017.
 * @see https://www.sourcecodester.com/java/5834/how-create-notepad-project-java.html
 */
class NotePad extends JFrame {

    private int fileToOpen, fileToSave;
    private JFileChooser fileOpen, fileSave;
    private String queryTitle = "Encrypt?";
    private String[] options = {"Yes", "No"};
    private String query = "Would you like to encrypt this file?";
    String passwordLabelText = "Password: ";
    String passwordPaneTitle = "Enter an Encryption/Decryption Key";

    NotePad() {
        MenuBar menuBar = new MenuBar();
        MenuItem menuItem = new MenuItem();
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
                    Scanner scan = new Scanner(new FileReader(fileOpen.getSelectedFile().getPath()));
                    while (scan.hasNext()) {
                        textArea.append(scan.nextLine());
                    }
                } catch (IOException iEx) {
                    System.err.println("I AM ERROR: Error occurred while opening file.");
                }
            }
        });
        save.addActionListener(e -> {
            saveFile();
            if(fileToSave == JFileChooser.APPROVE_OPTION) {
                try {
                    BufferedWriter out = new BufferedWriter(new FileWriter(fileSave.getSelectedFile().getPath()));
                    out.write(textArea.getText());
                    out.close();
                } catch(IOException iEx) {
                    System.err.println("I AM ERROR: There was an error saving the file.");
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
        handleEncryption();
        JFileChooser save = new JFileChooser();
        fileToSave = save.showSaveDialog(this);
        fileSave = save;
    }

    private void handleEncryption() {
        // This value will be used to determine whether or not to encrypt the file
        int saveEncrypted = JOptionPane.showOptionDialog(this,
                query, queryTitle, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, null, JOptionPane.YES_OPTION);

        // if YES is selected, then collect a password
        // Reference: https://stackoverflow.com/questions/8881213/joptionpane-to-get-password
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
                char[] password = passwordField.getPassword();
                System.out.println("The entered password is: " + new String(password));

                // From here, I need to use the password to run an AES encryption in CBC mode
                // I also need to attach a tag to the file somewhere so I will know if it needs
                // to be decrypted. I need to choose the security library to use.
            }

        }
    }
}
