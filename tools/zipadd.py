"""Assemble the final APK: base apk + classes.dex + lib/<abi>/*.so (stored names kept)."""
import os, shutil, sys, zipfile

base, dex, libdir, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
if os.path.exists(out):
    os.remove(out)

with zipfile.ZipFile(base, "r") as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
    for item in src.infolist():
        data = src.read(item.filename)
        dst.writestr(item, data)
    dst.write(dex, "classes.dex", compress_type=zipfile.ZIP_DEFLATED)
    if libdir and os.path.isdir(libdir):
        for abi in sorted(os.listdir(libdir)):
            adir = os.path.join(libdir, abi)
            if not os.path.isdir(adir):
                continue
            for f in sorted(os.listdir(adir)):
                p = os.path.join(adir, f)
                if os.path.isfile(p):
                    dst.write(p, "lib/%s/%s" % (abi, f), compress_type=zipfile.ZIP_DEFLATED)
                    print("  + lib/%s/%s (%d)" % (abi, f, os.path.getsize(p)))

names = zipfile.ZipFile(out).namelist()
print("entries:", len(names))
for n in names:
    if n.startswith("lib/") or n in ("classes.dex", "AndroidManifest.xml", "resources.arsc"):
        print("   ", n)
