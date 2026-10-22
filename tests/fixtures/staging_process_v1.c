/* Private signed fixture process. It is not CPython, uv or an offline proof. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Standalone fixture SHA256; product/Python hashlib is the independent oracle.
   Keep this small test process independent of crypto-framework initialization. */
static uint32_t rotate(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void sha256(const unsigned char *body,size_t size,unsigned char out[32]){
 static const uint32_t k[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 uint32_t state[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 size_t blocks=(size+9+63)/64;uint64_t bit_length=(uint64_t)size*8;
 for(size_t block=0;block<blocks;block++){
  unsigned char chunk[64];uint32_t w[64];
  for(size_t j=0;j<64;j++){size_t p=block*64+j;
   chunk[j]=p<size?body[p]:(p==size?0x80:(p>=blocks*64-8?(unsigned char)(bit_length>>((blocks*64-1-p)*8)):0));}
  for(unsigned j=0;j<16;j++)w[j]=((uint32_t)chunk[j*4]<<24)|((uint32_t)chunk[j*4+1]<<16)|((uint32_t)chunk[j*4+2]<<8)|chunk[j*4+3];
  for(unsigned j=16;j<64;j++){uint32_t s0=rotate(w[j-15],7)^rotate(w[j-15],18)^(w[j-15]>>3),s1=rotate(w[j-2],17)^rotate(w[j-2],19)^(w[j-2]>>10);w[j]=w[j-16]+s0+w[j-7]+s1;}
  uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
  for(unsigned j=0;j<64;j++){uint32_t s1=rotate(e,6)^rotate(e,11)^rotate(e,25),choice=(e&f)^(~e&g),t1=h+s1+choice+k[j]+w[j],s0=rotate(a,2)^rotate(a,13)^rotate(a,22),majority=(a&b)^(a&c)^(b&c),t2=s0+majority;
   h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
  state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
 }
 for(unsigned i=0;i<8;i++)for(unsigned j=0;j<4;j++)out[i*4+j]=(unsigned char)(state[i]>>(24-j*8));
}

typedef struct {char path[1024],record[1024];unsigned char *body;size_t size;unsigned mode,kind,owner;} Entry;
static Entry entries[64];
static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static void timing(const char *mode,const char *phase){
 if(!strcmp(mode,"install-timing")){struct timespec now;if(clock_gettime(CLOCK_MONOTONIC,&now))exit(14);
  fprintf(stderr,"{\"native_phase\":\"%s\",\"seconds\":%.9f}\n",phase,(double)now.tv_sec+(double)now.tv_nsec/1e9);fflush(stderr);}
}
static void hash(const unsigned char *body,size_t n,char *out){
 unsigned char raw[32];sha256(body,n,raw);size_t j=0;
 for(size_t i=0;i<32;i+=3){unsigned value=(unsigned)raw[i]<<16;if(i+1<32)value|=(unsigned)raw[i+1]<<8;if(i+2<32)value|=raw[i+2];
  out[j++]=alphabet[(value>>18)&63];out[j++]=alphabet[(value>>12)&63];if(i+1<32)out[j++]=alphabet[(value>>6)&63];if(i+2<32)out[j++]=alphabet[value&63];}
 out[j]=0;
}
static unsigned char *expand(const unsigned char *body,size_t size,const char *root,size_t *length){
 size_t cap=size+strlen(root)*64+8192;unsigned char *out=malloc(cap);if(!out)exit(11);size_t pos=0;
 for(size_t i=0;i<size;){const char *tail=NULL;size_t skip=0;
  if(size-i>=13&&!memcmp(body+i,"@interpreter@",13)){tail="/payload/interpreter/bin/python";skip=13;}
  else if(size-i>=6&&!memcmp(body+i,"@tool@",6)){tail="/payload/tool";skip=6;}
  if(tail){size_t n=strlen(root),m=strlen(tail);if(pos+n+m>=cap)exit(12);memcpy(out+pos,root,n);pos+=n;memcpy(out+pos,tail,m);pos+=m;i+=skip;}
  else {if(pos+1>=cap)exit(12);out[pos++]=body[i++];}
 }
 *length=pos;return out;
}
int main(int argc,char **argv){
 const char *mode=argc>1?argv[1]:"install";
 timing(mode,"entry");
 if(!strcmp(mode,"fail"))return 23;
 if(!strcmp(mode,"flood")){for(int i=0;i<4097;i++)fputc('X',stdout);fflush(stdout);return 0;}
 if(!strcmp(mode,"emit")||!strcmp(mode,"install-emit")){for(int i=0;i<2049;i++)fputc('Y',stdout);fflush(stdout);if(!strcmp(mode,"emit"))return 0;}
 if(!strcmp(mode,"hang")){signal(SIGTERM,SIG_IGN);fputs("W10E-READY\n",stderr);fflush(stderr);for(;;)pause();}
 if(!strcmp(mode,"delay")){struct timespec delay={3,0};nanosleep(&delay,NULL);return 0;}
 if(!strcmp(mode,"overdue")){kill(getppid(),SIGSTOP);return 0;}
 if(!strcmp(mode,"descendant")){if(fork()==0){signal(SIGTERM,SIG_IGN);for(;;)pause();}return 0;}
 char root[1024];if(!getcwd(root,sizeof(root)))return 2;
 FILE *f=fopen("payload/installer/install-map.bin","rb");if(!f)return 3;
 unsigned count;if(fscanf(f,"%u\n",&count)!=1||count>64)return 4;
 for(unsigned i=0;i<count;i++){
  Entry *e=&entries[i];unsigned pathlen,reclen,bodylen;
  if(fscanf(f,"%u %u %u %u %u %u\n",&e->mode,&e->kind,&e->owner,&pathlen,&reclen,&bodylen)!=6||pathlen>=1024||reclen>=1024||bodylen>1048576)return 5;
  if(fread(e->path,1,pathlen,f)!=pathlen||fread(e->record,1,reclen,f)!=reclen)return 6;e->path[pathlen]=0;e->record[reclen]=0;
  e->body=malloc(bodylen+1);if(!e->body||fread(e->body,1,bodylen,f)!=bodylen)return 6;e->size=bodylen;
  if(e->kind==1){unsigned char *raw=e->body;e->body=expand(raw,e->size,root,&e->size);free(raw);}
 }
 if(fgetc(f)!=EOF)return 7;fclose(f);
 timing(mode,"parsed");
 if(!strcmp(mode,"ordinary")){for(unsigned i=0;i<count;i++)if(entries[i].kind==0&&entries[i].size){entries[i].body[0]^=1;break;}}
 for(unsigned i=0;i<count;i++){
  /* The product already verifies/precreates the complete directory closure.
     Do not spend the fixed execution window repeating mkdir for every ancestor. */
  Entry *e=&entries[i];if(e->kind==2)continue;int fd=open(e->path,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 8;FILE *out=fdopen(fd,"wb");if(!out){close(fd);return 8;}
  if(fwrite(e->body,1,e->size,out)!=e->size||(e->mode!=0600&&fchmod(fd,e->mode))||fclose(out))return 9;
 }
 timing(mode,"written");
 for(unsigned i=0;i<count;i++){
  Entry *e=&entries[i];if(e->kind!=2)continue;int fd=open(e->path,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 8;FILE *out=fdopen(fd,"wb");if(!out){close(fd);return 8;}
  for(unsigned j=0;j<count;j++)if(entries[j].owner==e->owner){Entry *a=&entries[j];char digest[44];
   if(!strcmp(mode,"missing-record-covered")&&j==0)continue;
   if(a->kind==2){if(!strcmp(mode,"selfrow"))fprintf(out,"%s,sha256=bad,1\n",a->record);else fprintf(out,"%s,,\n",a->record);}
   else {hash(a->body,a->size,digest);fprintf(out,"%s,sha256=%s,%zu\n",a->record,digest,a->size);}
  }
  if((e->mode!=0600&&fchmod(fd,e->mode))||fclose(out))return 9;
 }
 if(!strcmp(mode,"extra")){FILE *out=fopen("payload/tool/extra","wb");if(!out)return 8;fputs("undeclared",out);fclose(out);}
 if(!strcmp(mode,"emptydir")&&mkdir("payload/tool/undeclared",0700))return 8;
 if(!strcmp(mode,"extra-metadata")){for(unsigned i=0;i<count;i++)if(entries[i].kind==2){char path[1024];strcpy(path,entries[i].path);char *slash=strrchr(path,'/');if(!slash)return 8;strcpy(slash+1,"UNDECLARED");FILE *out=fopen(path,"wb");if(!out)return 8;fputs("undeclared",out);fclose(out);break;}}
 if(!strcmp(mode,"missing-record-covered"))unlink(entries[0].path);
 if(!strcmp(mode,"missing"))unlink(entries[0].path);
 if(!strcmp(mode,"badrecord")){for(unsigned i=0;i<count;i++)if(entries[i].kind==2){FILE *out=fopen(entries[i].path,"ab");fputs("../escape,sha256=bad,1\n",out);fclose(out);break;}}
 timing(mode,"recorded");
 return 0;
}
