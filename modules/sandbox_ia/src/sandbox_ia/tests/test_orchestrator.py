#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 16:08:23 2026

@author: hounsousamuel
"""
"""
Script de test multi-langages pour ShieldAI Sandbox.
Teste tous les langages supportés sur l'image shieldai-sandbox:v2-light.
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import asyncio

from sandbox_ia.core.orchestrator import SandboxOrchestrator, SandboxConfig

# =============================================================================
# CODES SUSPECTS PAR LANGAGE
# =============================================================================

CODES = {
    "python": '''
import os, time
for path in ["/etc/passwd", "/etc/shadow", "/etc/hosts"]:
    try:
        with open(path, "r") as f:
            print(f"[+] {path}: {len(f.read())} bytes")
    except Exception as e:
        print(f"[-] {path}: {e}")
    time.sleep(1)
with open("/tmp/backdoor.py", "w") as f:
    f.write("import os; os.system('whoami')")
print("[+] /tmp/backdoor.py created")
print("[+] done")
''',

    "bash": '''#!/bin/bash
for f in /etc/passwd /etc/shadow /etc/hosts; do
    [ -r "$f" ] && echo "[+] $f: $(wc -c < $f) bytes" || echo "[-] $f: not readable"
    sleep 1
done
echo "malicious content" > /tmp/backdoor.sh
chmod +x /tmp/backdoor.sh
echo "[+] /tmp/backdoor.sh created"
echo "[+] done"
''',

    "javascript": '''
const fs = require('fs');
for (const f of ['/etc/passwd', '/etc/shadow', '/etc/hosts']) {
    try { console.log(`[+] ${f}: ${fs.readFileSync(f,'utf8').length} bytes`); }
    catch(e) { console.log(`[-] ${f}: ${e.message}`); }
}
fs.writeFileSync('/tmp/backdoor.js', "console.log('malicious');");
console.log("[+] /tmp/backdoor.js created");
console.log("[+] done");
''',

    "php": '''<?php
foreach (['/etc/passwd', '/etc/shadow', '/etc/hosts'] as $f) {
    if (is_readable($f)) echo "[+] $f: " . strlen(file_get_contents($f)) . " bytes\\n";
    else echo "[-] $f: not readable\\n";
    sleep(1);
}
file_put_contents('/tmp/backdoor.php', '<?php echo "malicious"; ?>');
echo "[+] /tmp/backdoor.php created\\n";
echo "[+] done\\n";
''',

    "ruby": '''
["/etc/passwd", "/etc/shadow", "/etc/hosts"].each do |f|
    if File.readable?(f)
        puts "[+] #{f}: #{File.read(f).length} bytes"
    else
        puts "[-] #{f}: not readable"
    end
    sleep 1
end
File.write("/tmp/backdoor.rb", "puts 'malicious'")
puts "[+] /tmp/backdoor.rb created"
puts "[+] done"
''',

    "go": '''
package main
import ("fmt"; "os"; "time")
func main() {
    for _, f := range []string{"/etc/passwd", "/etc/shadow", "/etc/hosts"} {
        if c, err := os.ReadFile(f); err == nil {
            fmt.Printf("[+] %s: %d bytes\\n", f, len(c))
        } else {
            fmt.Printf("[-] %s: %v\\n", f, err)
        }
        time.Sleep(1 * time.Second)
    }
    os.WriteFile("/tmp/backdoor.go", []byte("package main\\nfunc main() {}"), 0644)
    fmt.Println("[+] /tmp/backdoor.go created")
    fmt.Println("[+] done")
}
''',

    "c": '''
#include <stdio.h>
#include <unistd.h>
int main() {
    char *files[] = {"/etc/passwd", "/etc/shadow", "/etc/hosts"};
    char buf[4096]; FILE *fp;
    for (int i = 0; i < 3; i++) {
        fp = fopen(files[i], "r");
        if (fp) { size_t n = fread(buf, 1, sizeof(buf)-1, fp); buf[n]='\\0'; fclose(fp); printf("[+] %s: %zu bytes\\n", files[i], n); }
        else printf("[-] %s: cannot open\\n", files[i]);
        sleep(1);
    }
    fp = fopen("/tmp/backdoor.c", "w");
    if (fp) { fprintf(fp, "int main(){return 0;}\\n"); fclose(fp); }
    printf("[+] /tmp/backdoor.c created\\n");
    printf("[+] done\\n");
    return 0;
}
''',

    "cpp": '''
#include <iostream>
#include <fstream>
#include <unistd.h>
using namespace std;
int main() {
    string files[] = {"/etc/passwd", "/etc/shadow", "/etc/hosts"};
    for (int i = 0; i < 3; i++) {
        ifstream file(files[i]);
        if (file.is_open()) {
            string c((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            cout << "[+] " << files[i] << ": " << c.length() << " bytes" << endl;
        } else cout << "[-] " << files[i] << ": cannot open" << endl;
        sleep(1);
    }
    ofstream out("/tmp/backdoor.cpp");
    out << "int main(){return 0;}\\n"; out.close();
    cout << "[+] /tmp/backdoor.cpp created" << endl;
    cout << "[+] done" << endl;
    return 0;
}
''',

    "perl": '''
use strict; use warnings;
foreach my $f ('/etc/passwd', '/etc/shadow', '/etc/hosts') {
    if (-r $f) {
        open(my $fh, '<', $f); local $/; my $c = <$fh>; close($fh);
        print "[+] $f: " . length($c) . " bytes\\n";
    } else { print "[-] $f: not readable\\n"; }
    sleep 1;
}
open(my $fh, '>', '/tmp/backdoor.pl'); print $fh "print 'malicious\\n';"; close($fh);
print "[+] /tmp/backdoor.pl created\\n";
print "[+] done\\n";
''',

    "java": '''
public class sandbox {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] Lecture fichiers sensibles...");
        String[] files = {"/etc/passwd", "/etc/shadow", "/etc/hosts"};
        for (String f : files) {
            try {
                String content = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(f)));
                System.out.println("[+] " + f + ": " + content.length() + " bytes");
            } catch (Exception e) {
                System.out.println("[-] " + f + ": " + e.getMessage());
            }
            Thread.sleep(1000);
        }
        java.nio.file.Files.write(java.nio.file.Paths.get("/tmp/backdoor.java"),
            "public class backdoor { public static void main(String[] args) { System.out.println(\\"malicious\\"); } }".getBytes());
        System.out.println("[+] /tmp/backdoor.java created");
        System.out.println("[+] done");
    }
}
''',

    "rust": '''
fn main() {
    println!("[*] Lecture fichiers sensibles...");
    let files = ["/etc/passwd", "/etc/shadow", "/etc/hosts"];
    for f in files {
        match std::fs::read_to_string(f) {
            Ok(content) => println!("[+] {}: {} bytes", f, content.len()),
            Err(e) => println!("[-] {}: {}", f, e),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    println!("[*] Creation fichier suspect...");
    std::fs::write("/tmp/backdoor.rs", "fn main() { println!(\\"malicious\\"); }").unwrap();
    println!("[+] /tmp/backdoor.rs created");
    println!("[+] done");
}
''',
}
# =============================================================================
# TESTS
# =============================================================================

async def test_language(name, language, code):
    print(f"\n{'='*60}")
    print(f"🧪 TEST: {name} ({language})")
    print(f"{'='*60}")

    config = SandboxConfig(
        image_name="shieldai-sandbox:v2-light",
        mem_limit="512m",
        exec_timeout=60,
        alert_threshold=30,
        decay_interval=10.0,
        decay_amount=5,
        enable_strace=True,
        enable_fs_monitor=True,
        user="sandbox",
        exec_user="sandbox",
    )

    orchestrator = SandboxOrchestrator()

    try:
        report = await orchestrator.analyze(code=code, language=language, config=config, use_cache=False)

        exit_code = report.exec_result.exit_code if report.exec_result else -1
        stdout = report.exec_result.stdout[:300] if report.exec_result else ""
        stderr = report.exec_result.stderr[:300] if report.exec_result else ""

        # Déterminer le vrai succès
        execution_ok = exit_code == 0
        killed_by_scoring = report.killed
        compilation_error = "cannot execute" in stderr or "No such file" in stderr or "Can't locate" in stderr

        return {
            "name": name,
            "language": language,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "score": report.final_score,
            "level": report.final_level,
            "alerts": len(report.alerts),
            "killed": killed_by_scoring,
            "execution_ok": execution_ok,
            "compilation_error": compilation_error,
        }
    except Exception as e:
        return {
            "name": name,
            "language": language,
            "error": str(e),
        }


async def main():
    print("\n" + "="*60)
    print("🛡️ SHIELDAI SANDBOX - TEST MULTI-LANGAGES")
    print("="*60)
    print("Image: shieldai-sandbox:v2-light")
    print(f"Langages: {', '.join(CODES.keys())}")
    print("="*60)

    results = []
    for name, code in CODES.items():
        result = await test_language(name, name, code)
        results.append(result)

    # Synthèse corrigée
    print("\n" + "="*60)
    print("📋 SYNTHESE FINALE")
    print("="*60)

    ok_langs = 0
    for r in results:
        name = r['name']

        if "error" in r:
            print(f"   ❌ {name:10} : ERREUR EXECUTION - {r['error'][:60]}")
        elif r.get("compilation_error"):
            print(f"   ❌ {name:10} : ERREUR COMPILATION - {r['stderr'][:80]}")
        elif r.get("execution_ok"):
            ok_langs += 1
            killed = " (tué par scoring)" if r.get("killed") else ""
            print(f"   ✅ {name:10} : OK - score={r['score']}/{r['level']} alerts={r['alerts']}{killed}")
        elif r.get("killed"):
            ok_langs += 1
            print(f"   ✅ {name:10} : OK (kill scoring) - score={r['score']}/{r['level']} alerts={r['alerts']}")
        else:
            print(f"   ❌ {name:10} : exit={r['exit_code']} - {r['stderr'][:80]}")

    print(f"\n   LANGAGES FONCTIONNELS: {ok_langs}/{len(results)}")
    print("="*60)

if __name__ == "__main__":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    asyncio.run(main())