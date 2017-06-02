#include "hex.h"

static inline hex_byte_t char2byte(char h){
  return h <= '9' ? h - '0' : h <= 'F' ? h - 'A' + 10 : h <= 'f' ? h - 'a' + 10 : -1;
}

int hex_load(hex_byte_t *s, hex_size_t len, const char *b){
  const char *c = b;
  
  for(; (*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f') || (*c >= 'A' && *c <= 'F'); c++);
  
  if((c - b + 1) / 2 != len){ /* not enough input */
    return -1;
  }

  if(len < 1){
    return 0;
  }

  len = c - b;
  
  if(len % 2){
    *s++ = char2byte(*b++);
  }
  
  for(; b < c; ){
    *s = char2byte(*b++) << 4;
    *s++ |= char2byte(*b++);
  }
  
  return len;
}

static inline char byte2char(hex_byte_t i){
  return i < 10 ? i + '0' : i - 10 + 'a';
}

void hex_dump(char *b, const hex_byte_t *s, hex_size_t len){
  const hex_byte_t *e = s + len;
  
  if(len < 1){
    return;
  }
  
  if(*s < 16){
    *b++ = byte2char(*s++);
  }else{
    *b++ = byte2char(*s >> 4);
    *b++ = byte2char(*s++ & 0xf);
  }

  for(; s < e; ){
    *b++ = byte2char(*s >> 4);
    *b++ = byte2char(*s++ & 0xf);
  }

  *b = '\0';
}
