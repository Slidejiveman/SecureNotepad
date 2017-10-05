import javax.swing.*;

/**
 * Secure NotePad is a project I did for my Information System Security class.
 * It allows the user to enter information into the GUI and save the file. It also
 * allows the user to open files from the file system.
 *
 *
 * Created by rdnot on 10/4/2017.
 *
 * This project relies on this tutorial that I used to get a better understanding of
 * how Java can be used to make a text editor using Swing and AWT. Credit for the base NotePad
 * functionality belongs to this source.
 * @see https://www.sourcecodester.com/java/5834/how-create-notepad-project-java.html
 */
public class Main {

    private static String applicationTitle = "Secure Notepad";

    public static void main (String args[]) {
        JFrame frame = new NotePad();
        frame.setTitle(applicationTitle);
        frame.setVisible(true);
        frame.setSize(1280, 720);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setResizable(true);
        frame.setLocationRelativeTo(null);
    }
}
