#!/usr/bin/env python3
"""Compare local disk and local Kubo IPFS using identical payload bytes."""
from __future__ import annotations
import argparse, csv, hashlib, os, statistics, sys, tempfile, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.ipfs_manager import upload_data, retrieve_file_bytes

def pct(v,p):
    s=sorted(v); x=(len(s)-1)*p/100; a=int(x); b=min(a+1,len(s)-1)
    return s[a]+(s[b]-s[a])*(x-a)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repeats",type=int,default=5)
    ap.add_argument("--sizes",default="1,5,10,25",help="MiB")
    args=ap.parse_args()
    if args.repeats<2: ap.error("--repeats must be >= 2")
    out=ROOT/"benchmarks"/"results"/"storage.csv"; out.parent.mkdir(parents=True,exist_ok=True)
    rows=[]
    for mib in map(int,args.sizes.split(",")):
        # IPFS helper accepts UTF-8 text, so use base64 to create a lossless text
        # representation; local disk stores those exact same bytes for fairness.
        import base64
        payload=base64.b64encode(os.urandom(mib*1024*1024))
        digest=hashlib.sha256(payload).hexdigest()
        local_w=[]; local_r=[]; ipfs_w=[]; ipfs_r=[]
        with tempfile.TemporaryDirectory(prefix="capstone-storage-bench-") as td:
            p=Path(td)/"payload.b64"
            for _ in range(args.repeats):
                t=time.perf_counter(); p.write_bytes(payload); local_w.append((time.perf_counter()-t)*1000)
                t=time.perf_counter(); local_data=p.read_bytes(); local_r.append((time.perf_counter()-t)*1000)
                if hashlib.sha256(local_data).hexdigest()!=digest: raise RuntimeError("Local disk hash mismatch")
                t=time.perf_counter(); cid=upload_data(payload.decode("ascii")); ipfs_w.append((time.perf_counter()-t)*1000)
                t=time.perf_counter(); remote=retrieve_file_bytes(cid); ipfs_r.append((time.perf_counter()-t)*1000)
                if hashlib.sha256(remote).hexdigest()!=digest: raise RuntimeError(f"IPFS hash mismatch for {cid}")
        rows.append({
            "file_size_mib":mib,"stored_payload_bytes":len(payload),"repeats":args.repeats,
            "local_write_mean_ms":statistics.mean(local_w),"local_read_mean_ms":statistics.mean(local_r),
            "ipfs_upload_mean_ms":statistics.mean(ipfs_w),"ipfs_retrieve_mean_ms":statistics.mean(ipfs_r),
            "ipfs_upload_p95_ms":pct(ipfs_w,95),"ipfs_retrieve_p95_ms":pct(ipfs_r,95),
            "local_hash_check":"PASS","ipfs_hash_check":"PASS"
        })
        print(f"{mib} MiB | local W/R {statistics.mean(local_w):.2f}/{statistics.mean(local_r):.2f} ms | IPFS U/R {statistics.mean(ipfs_w):.2f}/{statistics.mean(ipfs_r):.2f} ms | hashes PASS")
    with out.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print(f"\nSaved: {out}")

if __name__=="__main__": main()
