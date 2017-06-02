#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ecc.h"
#include "hex.h"

#ifndef CHUNKED
#define CHUNKED 1
#endif

#ifndef CHUNK_SIZE
#define CHUNK_SIZE (8*1024)
#endif

static int keygen(const char *randomseed){
  char buf[2 * ECIES_KEY_SIZE + 1];
  ECIES_privkey_t priv;
  ECIES_pubkey_t pub;
  
  if(randomseed){
    srandom(atoi(randomseed));
  }
  
  ECIES_generate_keys(&priv, &pub);          /* generate a public/private key pair */
  
  hex_dump(buf, pub.x, ECIES_KEY_SIZE); printf("%s:", buf);
  hex_dump(buf, pub.y, ECIES_KEY_SIZE); printf("%s\n", buf);
  hex_dump(buf, priv.k, ECIES_KEY_SIZE); printf("%s\n", buf);
  
  return 0;
}

static const size_t chunk_size = CHUNK_SIZE;

#if CHUNKED

static int read_chunk(FILE *stm, char *raw, int len){
  if(feof(stm)){
    return 0;
  }
  
  len = fread(raw, 1, len, stm);
  
  if(len < 0){
    fprintf(stderr, "Read error\n");
    return -1;
  }
  
  return len;
}

#else/*CHUNKED*/

static int read_all(FILE *stm, char **raw){
  int rbs, end = 0, len = 0;
  
  *raw = NULL;
  
  for(; !feof(stm); ){
    if(end < 1){
      end += chunk_size;
      *raw = realloc(*raw, len + end);
    }
    rbs = fread(*raw + len, 1, end, stm);
    if(rbs < 0){
      fprintf(stderr, "Read error\n");
      return -1;
    }
    len += rbs;
    end -= rbs;
  }
  
  return len;
}

#endif/*CHUNKED*/

static void write_all(FILE *stm, const char *raw, int len){
  int wbs, pos = 0;
  
  for(; len > 0; ){
    wbs = fwrite(raw + pos, 1, len, stm);
    if(wbs < 0){
      fprintf(stderr, "Write error\n");
    }
    pos += wbs;
    len -= wbs;
  }
}

static int encrypt(const char *pubkey){
  ECIES_pubkey_t public = {
    { 0x01, 0xc5, 0x6d, 0x30, 0x2c, 0xf6, 0x42, 0xa8, 0xe1, 0xba, 0x4b, 0x48, 0xcc, 0x4f, 0xbe, 0x28, 0x45, 0xee, 0x32, 0xdc, 0xe7 },
    { 0x04, 0x5f, 0x46, 0xeb, 0x30, 0x3e, 0xdf, 0x2e, 0x62, 0xf7, 0x4b, 0xd6, 0x83, 0x68, 0xd9, 0x79, 0xe2, 0x65, 0xee, 0x3c, 0x03 },
  };
  
  if(pubkey){
    int r = hex_load(public.x, ECIES_KEY_SIZE, pubkey);
    if(0 > r){
      fprintf(stderr, "Invalid public key x\n");
      return 1;
    }
    if(0 > hex_load(public.y, ECIES_KEY_SIZE, pubkey + r + 1)){
      fprintf(stderr, "Invalid public key y\n");
      return 1;
    }
  }

#if CHUNKED
  {
    ECIES_stream_t stm;
    
    {
      ECIES_byte_t enc[ECIES_START_OVERHEAD];
      
      ECIES_encrypt_start(&stm, enc, &public);
      
      write_all(stdout, (const char*)enc, ECIES_START_OVERHEAD);
    }
    
    {
      ECIES_byte_t enc[CHUNK_SIZE + ECIES_CHUNK_OVERHEAD];
      int len;
      
      for(; ;){
        len = read_chunk(stdin, (char*)enc, CHUNK_SIZE);

        if(len == 0){
          break; /*eof*/
        }
        
        if(len < 0){
          return -1;
        }
        
        ECIES_encrypt_chunk(&stm, enc, len);
        
        write_all(stdout, (const char*)enc, len + ECIES_CHUNK_OVERHEAD);
      }
    }
  }
#else/*CHUNKED*/
  {
    int raw_len, enc_len;
    char *raw;
    ECIES_byte_t *enc;
    
    raw_len = read_all(stdin, &raw);

    if(raw_len < 0){
      return -1;
    }
    
    enc_len = raw_len + ECIES_OVERHEAD;
    enc = malloc(enc_len);
    
    ECIES_encrypt(enc, raw, raw_len, &public);
    
    free(raw);
    
    write_all(stdout, (const char*)enc, enc_len);
    
    free(enc);
  }
#endif/*CHUNKED*/
  
  return 0;
}

static int decrypt(const char *privkey){
  ECIES_privkey_t private = {
    { 0x00, 0xe1, 0x0e, 0x78, 0x70, 0x36, 0x94, 0x1e, 0x6c, 0x78, 0xda, 0xf8, 0xa0, 0xe8, 0xe1, 0xdb, 0xfa, 0xc6, 0x8e, 0x26, 0xd2 },
  };
  
  if(privkey){
    if(0 > hex_load(private.k, ECIES_KEY_SIZE, privkey)){
      fprintf(stderr, "Invalid private key\n");
      return 1;
    }
  }

#if CHUNKED
  {
    ECIES_stream_t stm;
    
    {
      ECIES_byte_t enc[ECIES_START_OVERHEAD];
      int len;
      
      len = read_chunk(stdin, (char*)enc, ECIES_START_OVERHEAD);
      
      if(len < ECIES_START_OVERHEAD){
        return -1;
      }
      
      len = ECIES_decrypt_start(&stm, enc, &private);
      
      if(len < 0){
        return len;
      }
    }
    
    {
      ECIES_byte_t enc[CHUNK_SIZE + ECIES_CHUNK_OVERHEAD];
      int len;
      
      for(; ;){
        len = read_chunk(stdin, (char*)enc, CHUNK_SIZE + ECIES_CHUNK_OVERHEAD);
        
        if(len == 0){
          break; /*eof*/
        }
        
        if(len < ECIES_CHUNK_OVERHEAD){
          return -1;
        }
        
        ECIES_decrypt_chunk(&stm, enc, len - ECIES_CHUNK_OVERHEAD);
        
        write_all(stdout, (const char*)enc, len - ECIES_CHUNK_OVERHEAD);
      }
    }
  }
#else/*CHUNKED*/
  {
    int raw_len, enc_len, res;
    char *raw;
    ECIES_byte_t *enc;
    
    enc_len = read_all(stdin, (char**)&enc);
    
    if(enc_len < 0){
      return -1;
    }
    
    raw_len = enc_len - ECIES_OVERHEAD;
    raw = malloc(raw_len);
    
    if((res = ECIES_decrypt(raw, raw_len, enc, &private)) < 0){
      fprintf(stderr, "Decryption failed %d\n", res);
      
      free(raw);
      free(enc);
      
      return 1;
    }
    
    free(enc);
    
    write_all(stdout, raw, raw_len);
    
    free(raw);
  }
#endif/*CHUNKED*/
  
  return 0;
}

int main(int argc, const char *argv[]){
  if(argc < 2) goto usage;
  
  switch(argv[1][0]){
  case 'k':
    return keygen(argc > 2 ? argv[2] : NULL);
  case 'e':
    return encrypt(argv[2]);
  case 'd':
    return decrypt(argv[2]);
  default:
    goto usage;
  }
  
 usage:
  fprintf(stderr, "Usage: %s <command> [parameters]\n"
          "  [k]eygen [random-seed] -- generate public/private key pair\n"
          "  [e]ncrypt [public-key-x:public-key-y] -- encrypt stdin to stdout using public key\n"
          "  [d]ecrypt [private-key] -- decript stdin to stdout using private key\n", argv[0]);
  
  return 0;
}
