/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- James Handlon
	   2- Ethan Himes
Submitted on: 
     Insert the date of Submission here
	 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}


unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText)
{
  int status;
  unsigned len=0, encryptedLen=0;

  EVP_CIPHER_CTX  *ctx = EVP_CIPHER_CTX_new();
  if( !ctx )
  {
    handleErrors("encrypt: failed to creat CTX");
  }

  status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv);
  if( status != 1 )
  {
    handleErrors("encrypt: failed to EncryptInit_ex");
  }


  status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
  if( status != 1 )
  {
    handleErrors("encrypt: failed to EncryptUpdate");
  }
  encryptedLen += len;

  pCipherText += len;

  status = EVP_EncryptFinal_ex( ctx, pCipherText, &len );
  if( status != 1 )
  {
    handleErrors("encrypt: failed to EncryptFinal_ex");
  }
  encryptedLen += len;

  EVP_CIPHER_CTX_free(ctx);

  return encryptedLen;
}

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
  int status;
  unsigned len=0, decryptedLen=0;

  EVP_CIPHER_CTX  *ctx = EVP_CIPHER_CTX_new();
  if( !ctx )
  {
    handleErrors("decrypt: failed to creat CTX");
  }

  status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv);
  if( status != 1 )
  {
    handleErrors("decrypt: failed to DecryptInit_ex");
  }

  status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
  if( status != 1 )
  {
    handleErrors("decrypt: failed to DecryptUpdate");
  }
  decryptedLen += len;

  pDecryptedText += len;

  status = EVP_DecryptFinal_ex( ctx, pDecryptedText, &len );
  if( status != 1 )
  {
    handleErrors("decrypt: failed to DecryptFinal_ex");
  }
  decryptedLen += len;

  EVP_CIPHER_CTX_free(ctx);

  return decryptedLen;
}

EVP_PKEY *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    EVP_PKEY *key = EVP_PKEY_new() ;
    if ( public )
        key = PEM_read_PUBKEY( fp, &key , NULL , NULL );
    else
        key = PEM_read_PrivateKey( fp , &key , NULL , NULL );
 
    fclose( fp );

    return key;
}


//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen' 
//
// Returns: 
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig || !privKey || !inData )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA private-key signing
    EVP_PKEY_CTX *ctx =  EVP_PKEY_CTX_new(privKey, NULL);
    if ( !ctx )
    {
      handleErrors("privKeySign: failed to creat CTX");
      EVP_PKEY_CTX_free( ctx );
      return 0;
    }

    if (EVP_PKEY_sign_init(ctx) != 1)
    {
      handleErrors("privKeySign: failed to EVP_PKEY_sign_init");
      EVP_PKEY_CTX_free( ctx );
      return 0;
    }

    // Determine how big the size of the signature could be
    size_t cipherLen ; 
    if (EVP_PKEY_sign(ctx, NULL, &cipherLen, inData, inLen) <= 0)
    {
      handleErrors("privKeySign: failed to get size of signature");
      EVP_PKEY_CTX_free( ctx );
      return 0;
    }

    // Next allocate memory for the ciphertext
    *sig = malloc(cipherLen);
    if (!(*sig))
    {
      handleErrors("privKeySign: failed to allocate memory");
      EVP_PKEY_CTX_free( ctx );
      return 0;
    }

    // Now, actually sign the inData using EVP_PKEY_sign( )
    if (EVP_PKEY_sign(ctx, *sig, sigLen, inData, inLen) <= 0)
    {
      handleErrors("privKeySign: failed to get size of signature");
      EVP_PKEY_CTX_free( ctx );
      return 0;
    }

    // All is good
    EVP_PKEY_CTX_free( ctx );     // remember to do this if any failure is encountered above

    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !pubKey  ||  !data  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA public-key signature verification
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if( !ctx )
    {
      handleErrors("pubKeyVerify: failed to creat CTX");
      EVP_PKEY_CTX_free( ctx );
      return 0;
    }
    
    if (EVP_PKEY_verify_init(ctx) != 1)
    {
      handleErrors("privKeySign: failed to EVP_PKEY_sign_init");
      EVP_PKEY_CTX_free( ctx );
      return 0;
    }

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify(ctx, sig, sigLen, data, dataLen) ;

    //  free any dynamically-allocated objects 
    EVP_PKEY_CTX_free( ctx );

    return decision ;

}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    EVP_MD_CTX *mdCtx ;
    size_t nBytes ;
    unsigned int  mdLen ;

	  // Use EVP_MD_CTX_create() to create new hashing context    
    mdCtx = EVP_MD_CTX_create();
    
    // Initialize the context using EVP_DigestInit() so that it deploys 
	  // the HASH_ALGORITHM() hashing function 
    if (EVP_DigestInit(mdCtx, HASH_ALGORITHM()) != 1)
    {
      EVP_MD_CTX_destroy(mdCtx);
      return 0;
    }

    uint8_t buffer[4096];

    while ( (nBytes = read(fd_in, buffer, 4096)) > 0 )   // Loop until end-of input file
    {
        // Read a chunk of input from fd_in. Exit the loop when End-of-File is reached
        if (EVP_DigestUpdate(mdCtx, buffer, nBytes) != 1)
        {
          EVP_MD_CTX_destroy(mdCtx);
          return 0;
        }

        // VP_DigestUpdate( )
        
        // if ( fd_out > 0 ) send the above chunk of data to fd_out
        if (fd_out > 0)
        {
          write(fd_out, buffer, nBytes);
        }
    }

    // EVP_DigestFinal( )
    if (EVP_DigestFinal(mdCtx, digest, &mdLen) != 1)
    {
      EVP_MD_CTX_destroy(mdCtx);
      return 0;
    }
    
    // EVP_MD_CTX_destroy( );
    EVP_MD_CTX_destroy(mdCtx);

    return mdLen ;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na
// All Len(*) fields are size_t integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

unsigned MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments

    if (log == NULL || msg1 == NULL || IDa == NULL || IDb == NULL || Na == NULL)
      exitError("One of new message parameters is null.");

    size_t    LenA    = strlen(IDa); //  number of bytes in IDa ;
    size_t    LenB    = strlen(IDb); //  number of bytes in IDb ;
    size_t    LenMsg1 = LenA + LenB + LENSIZE + LENSIZE + NONCELEN; //  number of bytes in the completed MSG1 ;;
    size_t   *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    printf("%s\n", IDa);
    *msg1 = (uint8_t*) malloc(LenMsg1);
    if (*msg1 == NULL)
    {
      exitError("Memory allocation for new message failed.");
    }


    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;
    
    // use the pointer p to traverse through msg1 and fill the successive parts of the msg
    
    memcpy(p, &LenA, LENSIZE);
    p += LENSIZE;

    memcpy(p, IDa, LenA);
    p += LenA;

    memcpy(p, &LenB, LENSIZE);
    p += LENSIZE;

    memcpy(p, IDb, LenB);
    p += LenB;

    memcpy(p, Na, NONCELEN);

    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    BIO_dump_indent_fp( log , msg1, LenMsg1, 4);
    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if (log == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
      exitError("One of the message received parameters is null.");
    }

    size_t LenMsg1 = 0, LenA , lenB ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na

    // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa):
    if (read(fd, &LenA, LENSIZE) == -1)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }

    LenMsg1 += LENSIZE;

    // 2) Allocate memory for ID_A ... But on failure to allocate memory:
    *IDa = (char*) malloc(LenA);

    if (*IDa == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    if (read(fd, IDa, LenA) == -1)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

    LenMsg1 += LenA;

    // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
    if (read(fd, &lenB, LENSIZE) == -1)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }

    LenMsg1 += LENSIZE;

    // 4) Allocate memory for ID_B    But on failure to allocate memory:
    *IDb = (char*) malloc(lenB);

    if (*IDb == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// Now, read IDb ... But on failure to read ID_B from the pipe
    if (read(fd, IDb, lenB) == -1)
    {
        fprintf( log , "Unable to receive all %lu bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }

    LenMsg1 += lenB;
    
    // 5) Read Na   But on failure to read Na from the pipe
    if (read(fd, Na, NONCELEN) == -1)
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }

    LenMsg1 += NONCELEN;
 
    fprintf( log , "MSG1 ( %lu bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}
