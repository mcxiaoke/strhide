import sys
import os
import time
import subprocess
import psutil

def run_and_measure(cmd, desc=""):
    print(f"=== Running: {desc} ===")
    print(f"Command: {' '.join(cmd)}")
    start_time = time.perf_counter()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc = psutil.Process(p.pid)
    peak_rss = 0
    try:
        while p.poll() is None:
            try:
                mem = proc.memory_info().rss
                if mem > peak_rss:
                    peak_rss = mem
                # also check children if any
                for child in proc.children(recursive=True):
                    try:
                        cmem = child.memory_info().rss
                        if cmem > peak_rss:
                            peak_rss = cmem
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            time.sleep(0.05)
    except Exception as e:
        print(f"Monitor exception: {e}")
    
    stdout, stderr = p.communicate()
    elapsed = time.perf_counter() - start_time
    peak_mib = peak_rss / (1024 * 1024)
    peak_gib = peak_rss / (1024 * 1024 * 1024)
    print(f"Exit code: {p.returncode}")
    print(f"Elapsed: {elapsed:.2f} s")
    print(f"Peak RSS: {peak_mib:.2f} MiB ({peak_gib:.2f} GiB)")
    if p.returncode != 0:
        print(f"STDERR:\n{stderr.decode('utf-8', errors='replace')}")
    return {
        "desc": desc,
        "cmd": cmd,
        "returncode": p.returncode,
        "elapsed": elapsed,
        "peak_mib": peak_mib,
        "peak_gib": peak_gib,
        "stdout": stdout.decode('utf-8', errors='replace'),
        "stderr": stderr.decode('utf-8', errors='replace')
    }

def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else "rust/target/release/strhide.exe"
    exe = os.path.abspath(exe)
    print(f"Benchmarking binary: {exe}")
    
    carrier = os.path.abspath("temp/bighevc/anime-b.mp4")
    payload = os.path.abspath("temp/payload-1m.bin")
    out_stego = os.path.abspath("temp/bench_out.mp4")
    out_extracted = os.path.abspath("temp/bench_extracted.bin")
    
    results = []
    
    # 1. embed --capacity (sampled)
    r1 = run_and_measure([exe, "embed", "--capacity", carrier], "embed --capacity (sampled 1000 slices)")
    results.append(r1)
    
    # 2. embed --capacity --exact
    r2 = run_and_measure([exe, "embed", "--capacity", carrier, "--exact"], "embed --capacity --exact (all 34,454 slices)")
    results.append(r2)
    
    # 3. embed 1 MiB
    if os.path.exists(out_stego):
        os.remove(out_stego)
    r3 = run_and_measure([exe, "embed", "-d", payload, "-p", "pwd1234", carrier, "-o", out_stego], "embed 1 MiB payload")
    results.append(r3)
    
    # 4. extract 1 MiB
    if os.path.exists(out_extracted):
        os.remove(out_extracted)
    r4 = run_and_measure([exe, "extract", "-p", "pwd1234", out_stego, "-o", out_extracted], "extract 1 MiB payload")
    results.append(r4)
    
    # Verify extraction
    if os.path.exists(out_extracted) and os.path.exists(payload):
        with open(payload, 'rb') as f1, open(out_extracted, 'rb') as f2:
            d1 = f1.read()
            d2 = f2.read()
            if d1 == d2:
                print(">>> VERIFICATION: Payload extracted 100% BIT-PERFECT! <<<")
            else:
                print(f">>> VERIFICATION FAILED: Payload mismatch! len1={len(d1)}, len2={len(d2)} <<<")
    
    print("\n" + "="*50)
    print(f"SUMMARY FOR: {os.path.basename(exe)}")
    print("="*50)
    for r in results:
        print(f"{r['desc']:<45} | Time: {r['elapsed']:>7.2f} s | Peak RSS: {r['peak_mib']:>8.2f} MiB ({r['peak_gib']:>4.2f} GiB)")
    print("="*50)

if __name__ == "__main__":
    main()
