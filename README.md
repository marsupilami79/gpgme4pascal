# gpgme4pascal

These are some files that help in using GPGME for encrypting files with Free Pascal and Lazarus.

The source code is licensed under the FPC modified LGPL. See:
http://wiki.lazarus.freepascal.org/FPC_modified_LGPL

Known problems:
 - I am sure thre is a better way to do the gpgme and c library initialization
 - GPGME will raise a general error if the encryption key is not trusted. This 
   is not checked properly by the gpgme object. It only raises the gerneral error.
 - This implementation is far from being complete.