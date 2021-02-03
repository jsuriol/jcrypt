  jcrypt 1.0

  Toy encryption program.

  Usage: 

    jcrypt.py <file>         -  Encrypt <file>.
    jcrypt.py <jcrypt_file>  -  Decrypt  <jcrypt_file>.
    jcrypt -d <argument>     -  Print debugging information in the operation specified.
    jcrypt -i <jcrypt_file   -  Print information about <jcrypt_file>.
    jcrypt -p                -  Generate a password of default length (10).
    jcrypt -p <length>       -  Generate a password of <length> length (range 10-1024).

  The <file> argument is deemed a stream of bytes, whether it's a text file or a binary file.

  jcrypt encrypts it and creates <file>.jcrypt.

  If <file> is a jcrypt file, regarless of file name extension, jcrypt decrypts it and
  creates <file>.jclear.

  If <file> name contains periods, jcrypt uses the name up to and excluding the
  first period. For example if the input file name is 'foobar.new.txt' the
  output file will be 'foobar.jclear' with the cleartext.

  The maximum input file size is MAXCLEARSIZE.
