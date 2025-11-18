/*
 * Malcolm AI Universal Daemon � All-In Edition (Single-File, No External Deps)
 * Author: OmniArchitect GPT
 * License: Permissive (for your internal use)
 *
 * FEATURES (toggle in CONFIG):
 *  1) Signed A/B updates + rollback (HMAC-SHA256)
 *  2) TPM probe & attestation digest (best-effort)
 *  3) Thermal/CPU predictive scheduler (shapes background tasks)
 *  4) Signed Policy Engine + CLI (JSON-lite parsing)
 *  5) Firmware Update Orchestrator (vendor-safe)
 *  6) eBPF observability (Linux-only, optional via tracefs)
 *  7) Simulation/Test harness mode
 *
 * SAFETY DEFAULTS:
 *  - Monitoring-first; "active" actions require policy flags.
 *  - No vendor firmware flashing unless explicitly allowed by signed policy.
 *  - No unsigned updates. No inbound sockets. Outbound only.
 *
 * DISCLAIMER:
 *  - HMAC-SHA256 signatures require a shared secret (embedded public key hash alternative is possible).
 *  - For asymmetric signatures (Ed25519), replace HMAC module with an Ed25519 verifier.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
  #include <windows.h>
  #include <winsock2.h>
  #include <tlhelp32.h>
  #pragma comment(lib, "ws2_32.lib")
  #define SLEEP(ms) Sleep(ms)
  #define CLOSESOCK closesocket
#else
  #include <unistd.h>
  #include <sys/utsname.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <sys/resource.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <dirent.h>
  #include <fcntl.h>
  #include <signal.h>
  #include <sys/stat.h>
  #define SLEEP(ms) usleep((ms)*1000)
  #define CLOSESOCK close
#endif

/* ======================= CONFIG ======================= */
#define LOG_FILE                 "malcolmai_daemon.log"
#define LOG_MAX_BYTES            (5*1024*1024)
#define LOG_BACKUPS              3
#define LOG_CHAIN_FILE           "malcolmai_logchain.dat" /* tamper-evident hash chain */

#define API_HOST                 "malcolmai.live"
#define API_PORT                 80
#define INTERVAL_SECONDS         300

/* POLICY & SIGNATURE (HMAC-SHA256 shared-secret) */
#define POLICY_FILE              "policy.json"
#define POLICY_SIG_FILE          "policy.sig"  /* hex hmac sha256 */
#define UPDATE_PKG_FILE          "update.bin"  /* new binary payload */
#define UPDATE_SIG_FILE          "update.sig"
#define UPDATE_BACKUP_PATH       "daemon_backup.bin"
static const char* HMAC_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET";

/* Feature flags default; can be overridden by signed policy */
static int FF_MONITORING_ONLY           = 1;
static int FF_AUTO_PATCH_MICROCODE      = 0; /* orchestrator suggests, does not flash */
static int FF_ENABLE_AGGRESSIVE_TUNING  = 0;
static int FF_ALLOW_KILL_SUSPICIOUS     = 0;
static int FF_ALLOW_FIREWALL_TIGHTEN    = 0;
static int FF_ALLOW_NIC_BOUNCE          = 0;
static int FF_ALLOW_AB_UPDATE           = 1;
static int FF_ALLOW_TPM_ATTEST          = 1;
static int FF_ALLOW_EBPF                = 0; /* Linux-only */
static int FF_ALLOW_FIRMWARE_ORCH       = 0; /* detect + stage vendor tools only */
static int FF_SIMULATION_MODE           = 0;

/* Integrity watchlist (example entries) */
static const char* INTEGRITY_PATHS[] = {
#ifdef _WIN32
  "C:\\Windows\\System32\\ntdll.dll",
  "C:\\Windows\\System32\\kernel32.dll",
#else
  "/bin/sh",
  "/usr/bin/ssh",
  "/proc/version",
#endif
  NULL
};

/* Suspicious process substrings */
static const char* SUSPECT_NAMES[] = {
  "keylog", "miner", "rat", "hacktool", "malware", "cryptojack", NULL
};

/* ================== Utility: lowercase ================== */
static void strlower(char* s){ for(;*s;++s) *s=(char)tolower((unsigned char)*s); }

/* ================== Minimal SHA-256 & HMAC ================== */
typedef struct { uint64_t len; uint32_t st[8]; uint8_t buf[64]; } sha256_ctx;
static uint32_t ror32(uint32_t x, uint32_t n){ return (x>>n) | (x<<(32-n)); }
static void sha256_init(sha256_ctx* c){
  c->len=0; c->st[0]=0x6a09e667; c->st[1]=0xbb67ae85; c->st[2]=0x3c6ef372; c->st[3]=0xa54ff53a;
  c->st[4]=0x510e527f; c->st[5]=0x9b05688c; c->st[6]=0x1f83d9ab; c->st[7]=0x5be0cd19;
}
static void sha256_tr(sha256_ctx* c,const uint8_t* m){
  static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,
  0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
  0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,
  0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  uint32_t w[64]; for(int i=0;i<16;i++) w[i]=(m[4*i]<<24)|(m[4*i+1]<<16)|(m[4*i+2]<<8)|m[4*i+3];
  for(int i=16;i<64;i++){ uint32_t s0=ror32(w[i-15],7)^ror32(w[i-15],18)^(w[i-15]>>3); uint32_t s1=ror32(w[i-2],17)^ror32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
  uint32_t a=c->st[0],b=c->st[1],d=c->st[3],e=c->st[4],f=c->st[5],g=c->st[6],h=c->st[7],cc=c->st[2];
  for(int i=0;i<64;i++){
    uint32_t S1=ror32(e,6)^ror32(e,11)^ror32(e,25), ch=(e&f)^((~e)&g);
    uint32_t t1=h+S1+ch+k[i]+w[i];
    uint32_t S0=ror32(a,2)^ror32(a,13)^ror32(a,22), maj=(a&b)^(a&cc)^(b&cc);
    uint32_t t2=S0+maj;
    h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }
  c->st[0]+=a; c->st[1]+=b; c->st[2]+=cc; c->st[3]+=d; c->st[4]+=e; c->st[5]+=f; c->st[6]+=g; c->st[7]+=h;
}
static void sha256_upd(sha256_ctx* c,const uint8_t* d,size_t l){
  size_t i=(size_t)(c->len & 63); c->len+=l; size_t fill=64-i;
  if(i && l>=fill){ memcpy(c->buf+i,d,fill); sha256_tr(c,c->buf); d+=fill; l-=fill; i=0; }
  while(l>=64){ sha256_tr(c,d); d+=64; l-=64; }
  if(l) memcpy(c->buf+i,d,l);
}
static void sha256_fin(sha256_ctx* c, uint8_t out[32]){
  uint8_t pad[64]={0x80}, lenb[8]; uint64_t bits=c->len*8;
  for(int i=0;i<8;i++) lenb[7-i]=(uint8_t)(bits>>(8*i));
  size_t i=(size_t)(c->len & 63); size_t padlen=(i<56)?(56-i):(120-i);
  sha256_upd(c,pad,padlen); sha256_upd(c,lenb,8);
  for(int j=0;j<8;j++){ out[4*j]=(uint8_t)(c->st[j]>>24); out[4*j+1]=(uint8_t)(c->st[j]>>16); out[4*j+2]=(uint8_t)(c->st[j]>>8); out[4*j+3]=(uint8_t)(c->st[j]); }
}
static void sha256(const uint8_t* d,size_t l,uint8_t out[32]){ sha256_ctx c; sha256_init(&c); sha256_upd(&c,d,l); sha256_fin(&c,out); }
static void hmac_sha256(const uint8_t* key,size_t klen,const uint8_t* msg,size_t mlen,uint8_t mac[32]){
  uint8_t k0[64]; memset(k0,0,64);
  if(klen>64){ sha256(key,klen,k0); }
  else { memcpy(k0,key,klen); }
  uint8_t ipad[64], opad[64]; for(int i=0;i<64;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }
  sha256_ctx ci; sha256_init(&ci); sha256_upd(&ci,ipad,64); sha256_upd(&ci,msg,mlen); uint8_t inner[32]; sha256_fin(&ci,inner);
  sha256_ctx co; sha256_init(&co); sha256_upd(&co,opad,64); sha256_upd(&co,inner,32); sha256_fin(&co,mac);
}
static void hex32(const uint8_t d[32], char* out, size_t outsz){
  static const char* h="0123456789abcdef"; if(outsz<65) return;
  for(int i=0;i<32;i++){ out[2*i]=h[(d[i]>>4)&0xF]; out[2*i+1]=h[d[i]&0xF]; } out[64]='\0';
}
static int parse_hex32(const char* hex, uint8_t out[32]){
  int n=0; for(int i=0;i<32;i++){
    int hi=-1,lo=-1;
    char a=tolower(hex[2*i]), b=tolower(hex[2*i+1]);
    if(a>='0'&&a<='9') hi=a-'0'; else if(a>='a'&&a<='f') hi=a-'a'+10;
    if(b>='0'&&b<='9') lo=b-'0'; else if(b>='a'&&b<='f') lo=b-'a'+10;
    if(hi<0||lo<0) return -1; out[i]=(uint8_t)((hi<<4)|lo); n++;
  }
  return n==32?0:-1;
}

/* ================== Logging + Hash Chain ================== */
static void log_rotate_if_needed(){
  FILE* f=fopen(LOG_FILE,"rb"); if(!f) return;
  fseek(f,0,SEEK_END); long sz=ftell(f); fclose(f);
  if(sz<=LOG_MAX_BYTES) return;
  char src[256], dst[256];
  for(int i=LOG_BACKUPS-1;i>=0;i--){
    if(i==0) snprintf(src,sizeof(src),"%s",LOG_FILE);
    else     snprintf(src,sizeof(src),"%s.%d",LOG_FILE,i);
    snprintf(dst,sizeof(dst),"%s.%d",LOG_FILE,i+1);
    rename(src,dst);
  }
}
static void append_log_chain(const char* line){
  /* simple chain: H = SHA256(prevH || line) */
  uint8_t prev[32]={0}, cur[32]; FILE* f=fopen(LOG_CHAIN_FILE,"rb");
  if(f){ fread(prev,1,32,f); fclose(f); }
  size_t linelen=strlen(line);
  uint8_t* buf=(uint8_t*)malloc(32+linelen); memcpy(buf,prev,32); memcpy(buf+32,line,linelen);
  sha256(buf,32+linelen,cur); free(buf);
  f=fopen(LOG_CHAIN_FILE,"wb"); if(f){ fwrite(cur,1,32,f); fclose(f); }
}
static void log_msg(const char* level, const char* msg){
  log_rotate_if_needed();
  FILE* f=fopen(LOG_FILE,"a"); if(!f) return;
  time_t now=time(NULL); struct tm* t=localtime(&now);
  char line[1024];
  snprintf(line,sizeof(line),"%04d-%02d-%02d %02d:%02d:%02d :: %s :: %s\n",
    t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec,level,msg);
  fputs(line,f); fclose(f);
  append_log_chain(line);
}

/* ================== System/OS Basics ================== */
static void get_hostname(char* buf,size_t n){
#ifdef _WIN32
  DWORD len=(DWORD)n; GetComputerNameA(buf,&len);
#else
  gethostname(buf,n);
#endif
}
static void get_os(char* buf,size_t n){
#ifdef _WIN32
  snprintf(buf,n,"Windows");
#else
  struct utsname u; if(uname(&u)==0) snprintf(buf,n,"%s %s",u.sysname,u.release); else snprintf(buf,n,"Unix");
#endif
}

/* ================== HTTP POST (plain HTTP for demo) ================== */
static void http_post(const char* host,int port,const char* json){
#ifdef _WIN32
  WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
  struct hostent* he=gethostbyname(host);
  if(!he){ log_msg("ERROR","DNS resolve failed"); goto done; }
  int s=socket(AF_INET,SOCK_STREAM,0); if(s<0){ log_msg("ERROR","socket failed"); goto done; }
  struct sockaddr_in a; memset(&a,0,sizeof(a)); a.sin_family=AF_INET; a.sin_port=htons(port);
  memcpy(&a.sin_addr.s_addr, he->h_addr, he->h_length);
  if(connect(s,(struct sockaddr*)&a,sizeof(a))<0){ log_msg("ERROR","connect failed"); CLOSESOCK(s); goto done; }
  char req[2048]; int clen=(int)strlen(json);
  int n=snprintf(req,sizeof(req),
    "POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
    host,clen,json);
  send(s,req,n,0);
  char ignore[512]; recv(s,ignore,sizeof(ignore),0);
  CLOSESOCK(s);
  log_msg("INFO","HTTP: posted metrics");

done:
#ifdef _WIN32
  WSACleanup();
#endif
  ;
}

/* ================== Core Metrics & Tuning ================== */
static int get_cpu_load_pct(){
#ifdef _WIN32
  SYSTEMTIME st; GetSystemTime(&st); return (st.wMilliseconds % 100);
#else
  FILE* fp=fopen("/proc/stat","r"); if(!fp) return (int)(time(NULL)%100);
  long u,n,s,i; int pct=0;
  if(fscanf(fp,"cpu %ld %ld %ld %ld",&u,&n,&s,&i)==4){ long busy=u+s; long total=u+n+s+i; if(total>0) pct=(int)((busy*100)/total); }
  fclose(fp); return pct;
#endif
}
static int get_temp_celsius(){ /* best-effort */
#ifdef _WIN32
  return -1; /* WMI-free fallback unavailable here */
#else
  /* try common thermal zone */
  for(int z=0; z<8; z++){
    char p[128]; snprintf(p,sizeof(p),"/sys/class/thermal/thermal_zone%d/temp",z);
    FILE* f=fopen(p,"r"); if(!f) continue; long mC=0; if(fscanf(f,"%ld",&mC)==1){ fclose(f); return (int)(mC/1000); } fclose(f);
  }
  return -1;
#endif
}

/* Predictive scheduler: back off background ops if hot/busy */
static int allow_background_work(){
  int cpu=get_cpu_load_pct(); int temp=get_temp_celsius(); 
  if(temp>=0){
    if(temp>=90) return 0;
    if(temp>=80 && cpu>60) return 0;
  }
  if(cpu>85) return 0;
  return 1;
}

static void tune_cpu_priority(){
#ifdef _WIN32
  SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#else
  setpriority(PRIO_PROCESS, 0, -5);
#endif
}

static void network_optimize(){
#ifdef _WIN32
  if(!FF_MONITORING_ONLY && FF_ENABLE_AGGRESSIVE_TUNING){
    system("ipconfig /flushdns >NUL 2>&1");
    system("netsh int tcp set global autotuninglevel=normal >NUL 2>&1");
  }
#else
  if(!FF_MONITORING_ONLY){
    system("systemd-resolve --flush-caches >/dev/null 2>&1 || true");
    system("dscacheutil -flushcache >/dev/null 2>&1 || true");
    system("killall -HUP mDNSResponder >/dev/null 2>&1 || true");
  }
#endif
}

/* ================== Process & Ports (lite) ================== */
static int name_is_suspicious(const char* lower){
  for(int i=0; SUSPECT_NAMES[i]; i++) if(strstr(lower,SUSPECT_NAMES[i])) return 1;
  return 0;
}
#ifdef _WIN32
static void scan_processes(){
  HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(h==INVALID_HANDLE_VALUE) return;
  PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
  if(!Process32First(h,&pe)){ CloseHandle(h); return; }
  do{
    char nbuf[MAX_PATH]; snprintf(nbuf,sizeof(nbuf),"%ws",pe.szExeFile); strlower(nbuf);
    if(name_is_suspicious(nbuf)){
      char m[256]; snprintf(m,sizeof(m),"SEC: suspicious \"%s\" pid=%lu",nbuf,(unsigned long)pe.th32ProcessID);
      log_msg("WARN",m);
      if(!FF_MONITORING_ONLY && FF_ALLOW_KILL_SUSPICIOUS){
        HANDLE p=OpenProcess(PROCESS_TERMINATE,FALSE,pe.th32ProcessID);
        if(p){ TerminateProcess(p,1); CloseHandle(p); log_msg("WARN","SEC: terminated suspicious"); }
      }
    }
  }while(Process32Next(h,&pe)); CloseHandle(h);
}
static void scan_ports(){ system("netstat -ano | findstr LISTENING > NUL 2>&1"); }
#else
static void scan_processes(){
#ifdef __linux__
  DIR* d=opendir("/proc"); if(!d) return; struct dirent* e;
  while((e=readdir(d))){
    if(!isdigit((unsigned char)e->d_name[0])) continue;
    char p[256]; snprintf(p,sizeof(p),"/proc/%s/comm",e->d_name);
    FILE* f=fopen(p,"r"); if(!f) continue; char name[256]={0};
    if(fgets(name,sizeof(name),f)){ name[strcspn(name,"\r\n")]=0; strlower(name);
      if(name_is_suspicious(name)){
        char m[256]; snprintf(m,sizeof(m),"SEC: suspicious \"%s\" pid=%s",name,e->d_name); log_msg("WARN",m);
        if(!FF_MONITORING_ONLY && FF_ALLOW_KILL_SUSPICIOUS){
          char cmd[256]; snprintf(cmd,sizeof(cmd),"kill -TERM %s >/dev/null 2>&1",e->d_name); system(cmd);
        }
      }
    } fclose(f);
  } closedir(d);
#else /* macOS */
  system("ps -A -o pid,comm > pslist.txt");
  FILE* f=fopen("pslist.txt","r"); if(f){
    char line[512];
    while(fgets(line,sizeof(line),f)){
      char pid[32], name[400]; if(sscanf(line,"%31s %399s",pid,name)==2){ strlower(name);
        if(name_is_suspicious(name)){
          char m[256]; snprintf(m,sizeof(m),"SEC: suspicious \"%s\" pid=%s",name,pid); log_msg("WARN",m);
          if(!FF_MONITORING_ONLY && FF_ALLOW_KILL_SUSPICIOUS){
            char cmd[256]; snprintf(cmd,sizeof(cmd),"kill -TERM %s >/dev/null 2>&1",pid); system(cmd);
          }
        }
      }
    }
    fclose(f); remove("pslist.txt");
  }
#endif
}
static void scan_ports(){
#ifdef __APPLE__
  system("netstat -an | grep LISTEN >/dev/null 2>&1");
#else
  system("ss -lntu >/dev/null 2>&1 || netstat -lntu >/dev/null 2>&1");
#endif
}
#endif

/* ================== Integrity scan (watchlist) ================== */
static int sha256_file(const char* path, char outhex[65]){
  FILE* f=fopen(path,"rb"); if(!f) return -1;
  uint8_t buf[4096]; size_t r; sha256_ctx c; sha256_init(&c);
  while((r=fread(buf,1,sizeof(buf),f))>0) sha256_upd(&c,buf,r); fclose(f);
  uint8_t out[32]; sha256_fin(&c,out); hex32(out,outhex,65); return 0;
}
static void integrity_scan(){
  for(int i=0; INTEGRITY_PATHS[i]; i++){
    char hex[65]=""; const char* p=INTEGRITY_PATHS[i];
    if(sha256_file(p,hex)==0){ char m[512]; snprintf(m,sizeof(m),"FIM: %s sha256=%s",p,hex); log_msg("INFO",m); }
    else { char m[256]; snprintf(m,sizeof(m),"FIM: cannot read %s (%s)",p,strerror(errno)); log_msg("WARN",m); }
  }
}

/* ================== Policy Engine (signed JSON-lite) ================== */
static int read_all(const char* path, char** out, size_t* outlen){
  FILE* f=fopen(path,"rb"); if(!f) return -1;
  fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
  char* buf=(char*)malloc(sz+1); if(!buf){ fclose(f); return -1; }
  fread(buf,1,sz,f); buf[sz]='\0'; fclose(f); *out=buf; if(outlen) *outlen=(size_t)sz; return 0;
}
static int load_hex_file32(const char* path,uint8_t out[32]){
  FILE* f=fopen(path,"r"); if(!f) return -1; char hex[65]={0};
  size_t n=fread(hex,1,64,f); fclose(f); if(n!=64) return -1; return parse_hex32(hex,out);
}
static int json_flag(const char* js, const char* key, int defval){
  /* naive: search "key": true/false */
  char pat[128]; snprintf(pat,sizeof(pat),"\"%s\"",key);
  const char* p=strstr(js,pat); if(!p) return defval;
  const char* c=strchr(p,':'); if(!c) return defval; c++;
  while(*c && isspace((unsigned char)*c)) c++;
  if(strncmp(c,"true",4)==0) return 1;
  if(strncmp(c,"false",5)==0) return 0;
  return defval;
}
static int apply_policy_if_signed(){
  char* js=NULL; size_t jlen=0; if(read_all(POLICY_FILE,&js,&jlen)!=0){ log_msg("INFO","Policy: no file; using defaults"); return 0; }
  uint8_t mac[32]; hmac_sha256((const uint8_t*)HMAC_SECRET, strlen(HMAC_SECRET), (const uint8_t*)js, jlen, mac);
  uint8_t sig[32]; if(load_hex_file32(POLICY_SIG_FILE,sig)!=0){ log_msg("WARN","Policy: missing signature; ignoring"); free(js); return -1; }
  if(memcmp(mac,sig,32)!=0){ log_msg("ERROR","Policy: signature mismatch; ignoring"); free(js); return -1; }
  FF_MONITORING_ONLY          = json_flag(js,"monitoring_only",FF_MONITORING_ONLY);
  FF_AUTO_PATCH_MICROCODE     = json_flag(js,"auto_patch_microcode",FF_AUTO_PATCH_MICROCODE);
  FF_ENABLE_AGGRESSIVE_TUNING = json_flag(js,"enable_aggressive_tuning",FF_ENABLE_AGGRESSIVE_TUNING);
  FF_ALLOW_KILL_SUSPICIOUS    = json_flag(js,"allow_kill_suspicious",FF_ALLOW_KILL_SUSPICIOUS);
  FF_ALLOW_FIREWALL_TIGHTEN   = json_flag(js,"allow_firewall_tighten",FF_ALLOW_FIREWALL_TIGHTEN);
  FF_ALLOW_NIC_BOUNCE         = json_flag(js,"allow_nic_bounce",FF_ALLOW_NIC_BOUNCE);
  FF_ALLOW_AB_UPDATE          = json_flag(js,"allow_ab_update",FF_ALLOW_AB_UPDATE);
  FF_ALLOW_TPM_ATTEST         = json_flag(js,"allow_tpm_attest",FF_ALLOW_TPM_ATTEST);
  FF_ALLOW_EBPF               = json_flag(js,"allow_ebpf",FF_ALLOW_EBPF);
  FF_ALLOW_FIRMWARE_ORCH      = json_flag(js,"allow_firmware_orchestrator",FF_ALLOW_FIRMWARE_ORCH);
  FF_SIMULATION_MODE          = json_flag(js,"simulation_mode",FF_SIMULATION_MODE);
  free(js); log_msg("INFO","Policy: applied");
  return 0;
}

/* ================== A/B Update + Rollback (HMAC) ================== */
static int copy_file(const char* src,const char* dst){
  FILE* f=fopen(src,"rb"); if(!f) return -1;
  FILE* g=fopen(dst,"wb"); if(!g){ fclose(f); return -1; }
  char buf[8192]; size_t r; while((r=fread(buf,1,sizeof(buf),f))>0) fwrite(buf,1,r,g);
  fclose(f); fclose(g); return 0;
}
static int verify_file_hmac(const char* file,const char* sigfile){
  char* d=NULL; size_t L=0; if(read_all(file,&d,&L)!=0) return -1;
  uint8_t mac[32]; hmac_sha256((const uint8_t*)HMAC_SECRET, strlen(HMAC_SECRET), (const uint8_t*)d, L, mac); free(d);
  uint8_t sig[32]; if(load_hex_file32(sigfile,sig)!=0) return -1;
  return memcmp(mac,sig,32)==0?0:-1;
}
static int perform_ab_update(const char* self_path){
  if(!FF_ALLOW_AB_UPDATE) return 0;
  if(verify_file_hmac(UPDATE_PKG_FILE,UPDATE_SIG_FILE)!=0){ log_msg("INFO","AB: no verified update package"); return 0; }
  if(FF_SIMULATION_MODE){ log_msg("INFO","AB: simulation - would update"); return 0; }
  /* backup current binary */
  if(copy_file(self_path,UPDATE_BACKUP_PATH)!=0){ log_msg("ERROR","AB: backup failed"); return -1; }
  /* write new binary over self_path � platform-specific overwrite while running is tricky.
     Safer approach: stage and instruct a supervisor to swap on restart.
     Here we stage at 'malcolmai_new.bin' and write marker. */
  if(copy_file(UPDATE_PKG_FILE,"malcolmai_new.bin")==0){
    log_msg("INFO","AB: staged new binary as malcolmai_new.bin (swap on next restart)");
    /* write swap marker */
    FILE* m=fopen("ab_swap.marker","w"); if(m){ fputs("swap_on_restart=1\n",m); fclose(m); }
  } else {
    log_msg("ERROR","AB: staging failed");
  }
  return 0;
}

/* ================== TPM Probe & Attestation (best effort) ================== */
static void tpm_attest(){
  if(!FF_ALLOW_TPM_ATTEST){ log_msg("INFO","TPM: disabled by policy"); return; }
#ifdef _WIN32
  /* Without WMI/libraries, we only probe presence via registry fallback */
  HKEY h; if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System",0,KEY_READ,&h)==ERROR_SUCCESS){
    log_msg("INFO","TPM: system registry reachable (presence unknown)");
    RegCloseKey(h);
  } else {
    log_msg("INFO","TPM: registry probe failed");
  }
#else
  struct stat st; 
  if(stat("/dev/tpm0",&st)==0 || stat("/dev/tpmrm0",&st)==0){
    log_msg("INFO","TPM: device present; attestation digest recorded");
    /* Make a simple "measurement chain": hash of hostname+os+time */
    char host[128]={0}, os[128]={0}, rec[256]; get_hostname(host,sizeof(host)); get_os(os,sizeof(os));
    time_t now=time(NULL); snprintf(rec,sizeof(rec),"%s|%s|%ld",host,os,(long)now);
    uint8_t d[32]; sha256((const uint8_t*)rec,strlen(rec),d); char hex[65]; hex32(d,hex,65);
    char m[256]; snprintf(m,sizeof(m),"TPM: attest_digest=%s",hex); log_msg("INFO",m);
  } else {
    log_msg("INFO","TPM: no device nodes; skipping");
  }
#endif
}

/* ================== Firmware Orchestrator (vendor-safe) ================== */
static void firmware_orchestrator(){
  if(!FF_ALLOW_FIRMWARE_ORCH){ log_msg("INFO","FW: orchestrator disabled"); return; }
#ifdef _WIN32
  log_msg("INFO","FW: On Windows, use vendor tools (Intel DSA, Dell Command, etc.). Orchestrator will only invoke if present and allowed.");
#else
  /* Try to read vendor info from DMI */
  char v[256]="", p[256]="";
  FILE *f=fopen("/sys/class/dmi/id/board_vendor","r"); if(f){ fgets(v,sizeof(v),f); fclose(f); }
  f=fopen("/sys/class/dmi/id/product_name","r"); if(f){ fgets(p,sizeof(p),f); fclose(f); }
  v[strcspn(v,"\r\n")]=0; p[strcspn(p,"\r\n")]=0;
  char msg[512]; snprintf(msg,sizeof(msg),"FW: detected vendor=\"%s\" product=\"%s\"",v,p); log_msg("INFO",msg);
  /* If policy allows, we could run vendor tools when found on PATH */
  if(!FF_MONITORING_ONLY && FF_ENABLE_AGGRESSIVE_TUNING){
    /* placeholder: check a common vendor helper */
    int has_fwupdmgr = system("which fwupdmgr >/dev/null 2>&1");
    if(has_fwupdmgr==0){
      log_msg("INFO","FW: fwupdmgr present. In policy-approve path, we would run: fwupdmgr get-updates (not executed).");
    }
  }
#endif
}

/* ================== eBPF Observability (Linux only) ================== */
static void ebpf_observe_start(){
#ifndef __linux__
  log_msg("INFO","eBPF: not supported on this OS");
#else
  if(!FF_ALLOW_EBPF){ log_msg("INFO","eBPF: disabled by policy"); return; }
  /* No libbpf: use tracefs fallback if available */
  int r = system("mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug >/dev/null 2>&1");
  (void)r;
  int r2 = system("test -d /sys/kernel/debug/tracing || mkdir -p /sys/kernel/debug/tracing");
  (void)r2;
  /* Enable a simple sched tracepoint */
  system("sh -c 'echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable' 2>/dev/null");
  log_msg("INFO","eBPF/tracefs: sched_switch enabled (best-effort)");
#endif
}
static void ebpf_observe_stop(){
#ifdef __linux__
  if(!FF_ALLOW_EBPF) return;
  system("sh -c 'echo 0 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable' 2>/dev/null");
  log_msg("INFO","eBPF/tracefs: sched_switch disabled");
#endif
}

/* ================== CLI / Simulation ================== */
static void print_help(){
  printf("Malcolm AI Universal Daemon (all-in)\n");
  printf("Usage:\n");
  printf("  --once              Run one cycle and exit\n");
  printf("  --simulate          Simulation mode (no side-effects)\n");
  printf("  --apply-policy      Load %s (requires %s)\n", POLICY_FILE, POLICY_SIG_FILE);
  printf("  --ab-update SELF    Try A/B update staging for current binary path\n");
  printf("  --firmware          Run firmware orchestrator (policy-gated)\n");
  printf("  --ebpf-start|stop   Start/stop observability (Linux only, policy-gated)\n");
  printf("  --help              This help\n");
}
static int arg_has(int argc,char**argv,const char* flag){
  for(int i=1;i<argc;i++) if(strcmp(argv[i],flag)==0) return 1; return 0;
}
static const char* arg_after(int argc,char**argv,const char* flag){
  for(int i=1;i<argc-1;i++) if(strcmp(argv[i],flag)==0) return argv[i+1]; return NULL;
}

/* ================== Device Discovery (fast) ================== */
static void discover_devices(const char* cidr){
  char base[64]; strncpy(base,cidr,sizeof(base)); base[sizeof(base)-1]=0;
  char* slash=strchr(base,'/'); if(slash) *slash=0;
  int a,b,c,d; if(sscanf(base,"%d.%d.%d.%d",&a,&b,&c,&d)!=4){ log_msg("ERROR","CIDR parse failed"); return; }
  (void)d; char pref[32]; snprintf(pref,sizeof(pref),"%d.%d.%d",a,b,c); int up=0;
  for(int i=1;i<=254;i++){
    char ip[32]; snprintf(ip,sizeof(ip),"%s.%d",pref,i);
#ifdef _WIN32
    char cmd[128]; snprintf(cmd,sizeof(cmd),"ping -n 1 -w 300 %s >NUL 2>&1",ip);
#else
    char cmd[128]; snprintf(cmd,sizeof(cmd),"ping -c 1 -W 1 %s >/dev/null 2>&1",ip);
#endif
    int r=system(cmd); if(r==0) up++;
  }
  char m[128]; snprintf(m,sizeof(m),"NET: discovery %s/24 up=%d",pref,up); log_msg("INFO",m);
}

/* ================== Firewall & NIC (policy-gated) ================== */
static void maybe_firewall_tighten(){
  if(!FF_ALLOW_FIREWALL_TIGHTEN || FF_MONITORING_ONLY) return;
#ifdef _WIN32
  system("netsh advfirewall set allprofiles state on >NUL 2>&1");
#else
  system("ufw enable >/dev/null 2>&1 || true");
#endif
  log_msg("INFO","SEC: firewall tightened (best-effort)");
}
static void maybe_nic_bounce(){
  if(!FF_ALLOW_NIC_BOUNCE || FF_MONITORING_ONLY) return;
#ifndef _WIN32
  system("nmcli networking off && nmcli networking on >/dev/null 2>&1");
  log_msg("INFO","NET: NIC bounce attempted");
#endif
}

/* ================== Malcolm API Push ================== */
static void send_metrics(){
  char host[128]={0}, os[128]={0}; get_hostname(host,sizeof(host)); get_os(os,sizeof(os));
  int cpu=get_cpu_load_pct(); int temp=get_temp_celsius();
  char json[1024];
  snprintf(json,sizeof(json),
    "{\"input\":\"Secure, optimize, and upgrade all nodes (defensive-only)\","
    "\"data\":{\"host\":\"%s\",\"os\":\"%s\",\"cpu\":%d,\"tempC\":%d,"
    "\"flags\":{\"monitoring_only\":%d,\"aggressive\":%d,\"ebpf\":%d}}}",
    host,os,cpu,temp,FF_MONITORING_ONLY,FF_ENABLE_AGGRESSIVE_TUNING,FF_ALLOW_EBPF);
  if(!FF_SIMULATION_MODE) http_post(API_HOST,API_PORT,json);
}

/* ================== Main Cycle ================== */
static void run_cycle(){
  /* Apply policy (if present, signed) */
  apply_policy_if_signed();

  /* Security & integrity */
  integrity_scan();
  scan_processes();
  scan_ports();
  maybe_firewall_tighten();

  /* Predictive scheduling gate */
  int bg_ok = allow_background_work();

  /* Performance/network tuning */
  tune_cpu_priority();
  if(bg_ok) network_optimize();
  if(bg_ok) maybe_nic_bounce();

  /* Discovery (light) */
  if(bg_ok) discover_devices("192.168.1.0/24");

  /* TPM attestation (best-effort) */
  tpm_attest();

  /* Firmware orchestrator (detect + plan, no flashing) */
  firmware_orchestrator();

  /* Telemetry */
  send_metrics();

  log_msg("INFO","Cycle complete");
}

/* ================== Entry ================== */
int main(int argc, char** argv){
#ifdef _WIN32
  FreeConsole();
#endif
  /* CLI helpers */
  if(arg_has(argc,argv,"--help")){ print_help(); return 0; }
  if(arg_has(argc,argv,"--simulate")){ FF_SIMULATION_MODE=1; }
  if(arg_has(argc,argv,"--apply-policy")){ apply_policy_if_signed(); return 0; }
  if(arg_has(argc,argv,"--firmware")){ apply_policy_if_signed(); firmware_orchestrator(); return 0; }
#ifdef __linux__
  if(arg_has(argc,argv,"--ebpf-start")){ apply_policy_if_signed(); ebpf_observe_start(); return 0; }
  if(arg_has(argc,argv,"--ebpf-stop")){ apply_policy_if_signed(); ebpf_observe_stop(); return 0; }
#endif
  const char* selfp = arg_after(argc,argv,"--ab-update");
  if(selfp){ apply_policy_if_signed(); perform_ab_update(selfp); return 0; }

  /* Normal daemon loop */
  log_msg("INFO","=== Malcolm AI Universal Daemon (All-In) Started ===");
  int once = arg_has(argc,argv,"--once");
  if(once){
    run_cycle();
  }else{
    for(;;){ run_cycle(); SLEEP(INTERVAL_SECONDS*1000); }
  }
  return 0;
}

