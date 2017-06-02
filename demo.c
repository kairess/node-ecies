#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ecc.h"
#include "hex.h"

static void encryption_decryption_demo(const char *text, const ECIES_pubkey_t *public, const ECIES_privkey_t *private)
{
  ECIES_size_t len = strlen(text) + 1;
  ECIES_byte_t *encrypted = malloc(len + ECIES_OVERHEAD);
  char *decrypted = malloc(len);

  printf("plain text: %s\n", text);
  ECIES_encrypt(encrypted, text, len, public);   /* encryption */

  {
    char *buf = malloc(2 * (len + ECIES_OVERHEAD) + 1);
    hex_dump(buf, encrypted, len + ECIES_OVERHEAD);
    
    printf("encrypted hex: %s\n", buf);
    
    free(buf);
  }
  
  if (ECIES_decrypt(decrypted, len, encrypted, private) < 0) /* decryption */
    printf("decryption failed!\n");
  else
    printf("after encryption/decryption: %s\n", decrypted);
  
  free(encrypted);
  free(decrypted);
}

int main()
{
  char buf[2 * ECIES_KEY_SIZE + 1];
  
  { /* Key generation demo */
    static ECIES_privkey_t priv;
    static ECIES_pubkey_t pub;
    
    ECIES_generate_keys(&priv, &pub);          /* generate a public/private key pair */
    
    printf("Key generation demo.\nHere is your new public/private key pair:\n");
    hex_dump(buf, pub.x, ECIES_KEY_SIZE); printf("Public key: %s:", buf);
    hex_dump(buf, pub.y, ECIES_KEY_SIZE); printf("%s\n", buf);
    hex_dump(buf, priv.k, ECIES_KEY_SIZE); printf("Private key: %s\n", buf);
  }
  
  { /* Encryption/decryption demo */
    static const ECIES_pubkey_t public = {
      { 0x01, 0xc5, 0x6d, 0x30, 0x2c, 0xf6, 0x42, 0xa8, 0xe1, 0xba, 0x4b, 0x48, 0xcc, 0x4f, 0xbe, 0x28, 0x45, 0xee, 0x32, 0xdc, 0xe7 },
      { 0x04, 0x5f, 0x46, 0xeb, 0x30, 0x3e, 0xdf, 0x2e, 0x62, 0xf7, 0x4b, 0xd6, 0x83, 0x68, 0xd9, 0x79, 0xe2, 0x65, 0xee, 0x3c, 0x03 },
    };
    
    static const ECIES_privkey_t private = {
      { 0x00, 0xe1, 0x0e, 0x78, 0x70, 0x36, 0x94, 0x1e, 0x6c, 0x78, 0xda, 0xf8, 0xa0, 0xe8, 0xe1, 0xdb, 0xfa, 0xc6, 0x8e, 0x26, 0xd2 },
    };
    
    printf("Encryption/descryption demo.\nHere is public/private key pair:\n");
    hex_dump(buf, public.x, ECIES_KEY_SIZE); printf("Public key: %s:", buf);
    hex_dump(buf, public.y, ECIES_KEY_SIZE); printf("%s\n", buf);
    hex_dump(buf, private.k, ECIES_KEY_SIZE); printf("Private key: %s\n", buf);
    
    encryption_decryption_demo("This secret demo message will be ECIES encrypted",
                               &public, &private);
  }
  
  return 0;
}
