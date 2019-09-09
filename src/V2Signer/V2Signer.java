/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package V2Signer;

/**
 * *************************************************************
 *
 * V 2 S I G N E R
 *
 * This class generates and tests signatures given an input VEO and a PFX file.
 *
 * Andrew Waugh (andrew.waugh@prov.vic.gov.au) Copyright 2006, 2019 PROV
 *
 *************************************************************
 */
import java.io.*;
import java.security.*;
import VEOGenerator.*;

/**
 * This class wraps the VEOGenerator class to create a tool that can produce a
 * signed VEO to compare with one from a vendor.
 * <p>
 * The program generates a VEO given a <signedObject> element (in a source file)
 * and a PFX file (used for both ordinary and lock signatures. A minimal example
 * of usage is<br>
 * <pre>
 *     veosigner -s signer.pfx contents.xml
 * </pre>
 */
public class V2Signer {

    VEOGenerator vg;// the representation of the VEO
    boolean verbose;// true if verbose output
    File pfxFile;	// PFX file containing infor about the signer
    String hashAlg; // hash algorithm to use
    PFXUser signer;	// signer information
    String passwd;	// password for the PFX file
    String signedObj; // signed object to construct VEO
    File outputDir;	// directory in which to place the VEOs

    /**
     * Default constructor. This constructor processes the command line
     * arguments, obtains the location of the templates and parses them, and
     * reads the PFX file to obtain the signers details. If any errors occur, an
     * error message will be printed and the program will terminate.
     *
     * @param args command line arguments
     */
    public V2Signer(String args[]) {
        StringBuffer sb;
        int c;
        char ch;

        verbose = false;
        signer = null;
        passwd = null;
        outputDir = null;
        signedObj = null;
        hashAlg = "SHA1";

        // process command line arguments
        configure(args);

        // if a password for the pfx file has not been supplied, ask for it...
        if (passwd == null) {
            sb = new StringBuffer();
            System.out.print("Password: ");
            try {
                while ((c = System.in.read()) != -1) {
                    System.out.print("\b*");
                    ch = (char) c;
                    if (ch == '\r' || ch == '\n') {
                        break;
                    }
                    sb.append(ch);
                }
            } catch (IOException e) {
                System.err.println(e);
            }
            passwd = sb.toString();
        }

        // open pfx file
        try {
            signer = new PFXUser(pfxFile.getPath(), passwd);
        } catch (VEOError e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * Configure
     *
     * This method configures the V2Signer from the arguments on the command
     * line. See the comment at the start of this file for the command line
     * arguments.
     *
     * @param args[] the command line arguments
     */
    private void configure(String args[]) {
        int i;
        String usage = "veoSigner [-h <hashAlg>] -s <pfxFile> [-p <password>] [-o <outputDir>] [-v] signedObject";

        // process command line arguments
        i = 0;
        try {
            while (i < args.length) {

            	// get password
		if (args[i].toLowerCase().equals("-h")) {
			i++;
			hashAlg = args[i];
			i++;
			continue;
		}
                
                // get pfx file
                if (args[i].toLowerCase().equals("-s")) {
                    i++;
                    pfxFile = openFile("PFX file", args[i], false);
                    i++;
                    continue;
                }

                // get output directory
                if (args[i].toLowerCase().equals("-o")) {
                    i++;
                    outputDir = openFile("output directory", args[i], true);
                    i++;
                    continue;
                }

                // get password
                if (args[i].toLowerCase().equals("-p")) {
                    i++;
                    passwd = args[i];
                    i++;
                    continue;
                }

                // if verbose...
                if (args[i].toLowerCase().equals("-v")) {
                    verbose = true;
                    i++;
                    System.err.println("Verbose output");
                    continue;
                }

                // if last argument, this is the signed object
                if (i == args.length - 1) {
                    signedObj = args[i];
                    i++;
                    System.err.println("Signed Object: '" + signedObj + "'");
                    continue;
                }

                // if unrecognised arguement, print help string and exit
                System.err.println("Unrecognised argument '" + args[i] + "'");
                System.err.println(usage);
                System.exit(-1);
            }
        } catch (ArrayIndexOutOfBoundsException ae) {
            System.err.println("Missing argument. Usage: ");
            System.err.println(usage);
            System.exit(-1);
        }

        // check to see that user specified a PFXfile and a signed object
        if (pfxFile == null) {
            System.err.println("No PFX file specified");
            System.err.println(usage);
            System.exit(-1);
        }
        if (signedObj == null) {
            System.err.println("No signed object file specified");
            System.err.println(usage);
            System.exit(-1);
        }
    }

    /**
     * Open file.
     *
     * This method opens a file, checking to see that it exists and is the
     * correct type. The program terminates if an error is encountered.
     *
     * @param type a String describing the file to be opened
     * @param name the file name to be opened
     * @param isDirectory true if the file is supposed to be a directory
     * @return the File opened
     */
    private File openFile(String type, String name, boolean isDirectory) {
        String s;
        File f;

        s = null;
        f = null;
        try {
            f = new File(name);
            s = f.getCanonicalPath();
        } catch (NullPointerException npe) {
            System.err.println(type + " argument is null");
            System.exit(-1);
        } catch (IOException ioe) {
            System.err.println("Error when accessing " + type + ": " + ioe.getMessage());
            System.exit(-1);
        }
        if (s == null) {
            System.err.println("PANIC! VEOSigner.openFile(" + type + ", " + name + ", " + isDirectory + "): File is null");
            System.exit(-1);
        }
        if (!f.exists()) {
            System.err.println(type + " '" + s + "' does not exist");
            System.exit(-1);
        }
        if (isDirectory && !f.isDirectory()) {
            System.err.println(type + " '" + s + "' is a file not a directory");
            System.exit(-1);
        }
        if (!isDirectory && f.isDirectory()) {
            System.err.println(type + " '" + s + "' is a directory not a file");
            System.exit(-1);
        }
        if (verbose) {
            System.err.println(type + ": '" + s + "'");
        }
        return f;
    }

    /**
     * Build the VEOs. This method processes the data file, building VEOs from
     * the data and the templates.
     */
    public void buildVEOs() {
        String name = "VEOSigner.buildVEOs(): ";
        File f;
        File veo;
        FileInputStream fis;
        BufferedInputStream bis;

        f = openFile("Signed object", signedObj, false);
        fis = null;
        try {
            fis = new FileInputStream(f);
        } catch (FileNotFoundException fnfe) {
            fnfe.printStackTrace();
            System.err.println(name + "Signed object file not found");
            System.exit(-1);
        }
        bis = new BufferedInputStream(fis);

        try {
            // VEO file name is in column 2...
            veo = new File(signedObj + ".veo");

            vg = new VEOGenerator();

            // start VEO
            vg.startVEO(veo, 1, 1);
            vg.addSignatureBlock(signer, hashAlg);
            vg.addLockSignatureBlock(1, signer, hashAlg);

            // include signed object
            vg.includeSignedObject(bis);

            // end VEO
            vg.endVEO();
        } catch (VEOError ve) {
            ve.printStackTrace();
            System.err.println(name + "Error in constructing VEO (" + ve.getMessage() + ")");
            System.exit(-1);
        }

        try {
            bis.close();
            fis.close();
        } catch (IOException ioe) {
            /* ignore */ }

        // calculate hash value
        MessageDigest md;
        byte bin[];
        byte[] h;
        int i;
        char[] charbuf = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

        fis = null;
        try {
            fis = new FileInputStream(f);
        } catch (FileNotFoundException fnfe) {
            fnfe.printStackTrace();
            System.err.println(name + "Signed object file not found");
            System.exit(-1);
        }
        bis = new BufferedInputStream(fis);
        try {
            md = MessageDigest.getInstance("SHA1");
            bin = new byte[1];
            while (bis.read(bin) != -1) {
                if (bin[0] == 0x20 || bin[0] == 0x0D || bin[0] == 0x0A || bin[0] == 0x09) {
                    continue;
                }
                md.update(bin);
            }
            System.out.print("Hash of signed object: ");
            h = md.digest();
            for (i = 0; i < h.length; i++) {
                System.out.print(charbuf[(h[i] >> 4) & 0x0f]);
                System.out.print(charbuf[h[i] & 0x0f]);
            }
            System.out.println("");

        } catch (NoSuchAlgorithmException nsae) {
            System.err.println(name + "Security package doesn't support SHA1");
            System.exit(-1);
        } catch (IOException ioe) {
            System.err.println(name + "Error reading input file: " + ioe.getMessage());
            System.exit(-1);
        }
        try {
            bis.close();
            fis.close();
        } catch (IOException ioe) {
            /* ignore */ }
    }

    /**
     * Main program. This program is given a set of command line arguments and
     * builds a collection of VEOs from the information in the arguments.
     *
     * @param args command line arguments
     */
    public static void main(String args[]) {
        V2Signer vs = new V2Signer(args);

        // process datafile
        vs.buildVEOs();
    }
}
