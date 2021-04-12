/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package V2Signer;

import VEOGenerator.VEOGenerator;
import VERSCommon.PFXUser;
import VERSCommon.VEOError;
import VERSCommon.VEOFatal;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

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
    boolean help;           // true if printing a cheat list of command line options

    private static final String USAGE = "veoSigner [-h <hashAlg>] -s <pfxFile> <password> [-o <outputDir>] [-v] signedObject";

    /**
     * Report on version...
     *
     * <pre>
     * 2006     1.0 Created
     * 20190909 1.1 Added support for hash algorithms other than SHA-1
     * 20210409 2.0 Added version, and standardised reporting in run. Integrated with VERSCommon (PFXUser, VEOFatal, VEOError)
     * </pre>
     */
    static String version() {
        return ("2.00");
    }

    /**
     * Default constructor. This constructor processes the command line
     * arguments, obtains the location of the templates and parses them, and
     * reads the PFX file to obtain the signers details. If any errors occur, an
     * error message will be printed and the program will terminate.
     *
     * @param args command line arguments
     * @throws VERSCommon.VEOFatal if the signer cannot be instantiated
     */
    public V2Signer(String args[]) throws VEOFatal {
        SimpleDateFormat sdf;
        TimeZone tz;
        StringBuffer sb;
        int c;
        char ch;

        verbose = false;
        signer = null;
        passwd = null;
        outputDir = null;
        signedObj = null;
        hashAlg = "SHA256";
        help = false;

        // process command line arguments
        configure(args);

        // tell what is happening
        System.out.println("******************************************************************************");
        System.out.println("*                                                                            *");
        System.out.println("*                V E O ( V 2 )   R E S I G N I N G   T O O L                 *");
        System.out.println("*                                                                            *");
        System.out.println("*                                Version " + version() + "                                *");
        System.out.println("*               Copyright 2006 Public Record Office Victoria                 *");
        System.out.println("*                                                                            *");
        System.out.println("******************************************************************************");
        System.out.println("");
        System.out.print("Run at ");
        tz = TimeZone.getTimeZone("GMT+10:00");
        sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss+10:00");
        sdf.setTimeZone(tz);
        System.out.println(sdf.format(new Date()));
        System.out.println("");
        if (help) {
            // veoSigner [-h <hashAlg>] -s <pfxFile> [-p <password>] [-o <outputDir>] [-v] signedObject
            System.out.println("Command line arguments:");
            System.out.println(" Mandatory:");
            System.out.println("  <signedObject>: text file containing the vers:SignedObject element");
            System.out.println("  -s <pfxFile> <password>: path to a PFX file and its password for signing a VEO (can be repeated)");
            System.out.println("");
            System.out.println(" Optional:");
            System.out.println("  -h <hashAlgorithm>: specifies the hash algorithm (default SHA-256)");
            System.out.println("  -o <directory>: the directory in which the VEOs are created (default is current working directory)");
            System.out.println("");
            System.out.println("  -v: verbose mode: give more details about processing");
            System.out.println("  -help: print this listing");
            System.out.println("");
        }

        // check to see that user specified a PFXfile and a signed object
        if (pfxFile == null) {
            throw new VEOFatal("V2Singer()", 1, "No PFX file specified. Usage: " + USAGE);
        }
        if (signedObj == null) {
            throw new VEOFatal("V2Singer()", 1, "No text (.txt) file specified containing the vers:SignedObject element. Usage: " + USAGE);
        }

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

        System.out.println("Configuration:");
        System.out.println(" PFX file: '" + pfxFile.toString() + "'");
        if (outputDir != null) {
            System.out.println(" Output directory: '" + outputDir.toString() + "'");
        }
        System.out.println(" Hash algorithm: " + hashAlg);
        if (verbose) {
            System.out.println(" Verbose output is selected");
        }

        // open pfx file
        try {
            signer = new PFXUser(pfxFile.getPath(), passwd);
        } catch (VEOError e) {
            throw new VEOFatal(e.getMessage());
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
    private void configure(String args[]) throws VEOFatal {
        int i;

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
                    passwd = args[i];
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

                // help requested
                if (args[i].toLowerCase().equals("-help")) {
                    help = true;
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
                throw new VEOFatal("V2Singer()", 1, "Unrecognised argument '" + args[i] + "' Usage: " + USAGE);
            }
        } catch (ArrayIndexOutOfBoundsException ae) {
            throw new VEOFatal("V2Singer()", 2, "Missing argument. Usage: " + USAGE);
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
    private File openFile(String type, String name, boolean isDirectory) throws VEOFatal {
        String s;
        File f;

        s = null;
        f = null;
        try {
            f = new File(name);
            s = f.getCanonicalPath();
        } catch (NullPointerException | IOException e) {
            throw new VEOFatal("Error when accessing " + type + ": " + e.getMessage());
        }
        if (s == null) {
            throw new VEOFatal("PANIC! VEOSigner.openFile(" + type + ", " + name + ", " + isDirectory + "): File is null");
        }
        if (!f.exists()) {
            throw new VEOFatal(type + " '" + s + "' does not exist");
        }
        if (isDirectory && !f.isDirectory()) {
            throw new VEOFatal(type + " '" + s + "' is a file not a directory");
        }
        if (!isDirectory && f.isDirectory()) {
            throw new VEOFatal(type + " '" + s + "' is a directory not a file");
        }
        if (verbose) {
            System.err.println(type + ": '" + s + "'");
        }
        return f;
    }

    /**
     * Build the VEOs. This method processes the data file, building VEOs from
     * the data and the templates.
     *
     * @throws VERSCommon.VEOFatal if an error occurred that meant no further
     * processing is possible
     */
    public void buildVEOs() throws VEOFatal {
        String name = "VEOSigner.buildVEOs()";
        File f;
        File veo;
        FileInputStream fis;
        BufferedInputStream bis;

        fis = null;
        try {
            f = openFile("Signed object", signedObj, false);
            fis = new FileInputStream(f);
        } catch (FileNotFoundException | VEOFatal e) {
            throw new VEOFatal(name, 1, "Signed object cannot be opened:" + e.getMessage());
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
            throw new VEOFatal(name, 2, "Error in constructing VEO (" + ve.getMessage() + ")");
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
        String s;

        fis = null;
        try {
            fis = new FileInputStream(f);
        } catch (FileNotFoundException fnfe) {
            throw new VEOFatal(name, 3, "Signed object file not found");
        }
        bis = new BufferedInputStream(fis);
        switch (hashAlg) {
            case "SHA1":
                s = "SHA-1";
                break;
            case "SHA256":
                s = "SHA-256";
                break;
            case "SHA384":
                s = "SHA-384";
                break;
            case "SHA512":
                s = "SHA-512";
                break;
            default:
                throw new VEOFatal(name, 4, "Unknown hash algorithm: '" + hashAlg + "'");
        }
        try {
            md = MessageDigest.getInstance(s);
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
            throw new VEOFatal(name, 3, "Hash algorithm '" + s + "' is not supported");
        } catch (IOException ioe) {
            throw new VEOFatal(name, 4, "Error reading input file: " + ioe.getMessage());
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
        V2Signer vs;

        // process datafile
        try {
            vs = new V2Signer(args);
            vs.buildVEOs();
        } catch (VEOFatal e) {
            System.err.println(e.toString());
        }
    }
}
