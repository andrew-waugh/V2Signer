# V2Signer

Copyright Public Records Office Victoria 2022

License CC BY 4.0

## What is VERS?

This package is part of the Victorian Electronic Records Strategy (VERS)
software release. For more information about VERS see
[here](https://prov.vic.gov.au/recordkeeping-government/vers).

## What is V2Signer?

V2Signer generates VERS Version 2 (VERS V2) VERS Encapsulated Objects (VEOs)
by taking a text file containing a VERSEncapsulatedObject element and signs it using a PFX file.

Typically, this program is used to manually create a VEO from an existing V2 VEO.

Version 2 VEOs are specified in PROS 99/007. This specification is now obsolete
and you should use VERS V3. The equivalent code can be found in the neoVEO
package.

## Using V2Generator

V2Signer is run from the command line. 'v2signer -help' will print a
precis of the command line options. The package contains a BAT file.

To use this package you also need to download the VERSCommon package, and this
must be placed in the same directory as the V2Generator package.

Structurally, the package is an Apache Netbeans project.
