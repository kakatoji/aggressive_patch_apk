#!/usr/bin/env bash
# aggressive-frida-patcher.sh
# Aggressive APK autopatcher + optional Frida Gadget injection
# WARNING: Use only on apps you own/have permission to test.
#
# Requirements: apktool, python3, (apksigner optional), keytool (optional)
#
# Flags:
#   --inject-all       : Aggressive - patch SSL, root, debug, emulator, login, inject loader to Application & Activities
#   --no-google-login  : If present, skip login patching for Google Sign-In / gms
#   --minimal          : Only SSL pinning + root checks
#   --frida /path/to/libfrida-gadget.so : include frida .so and auto-load it
#   --dry-run          : show what would be patched; do not write changes
#
set -euo pipefail

# ---------- parse args ----------
if [ $# -lt 1 ]; then
  echo "Usage: $0 <app.apk> [--inject-all] [--no-google-login] [--minimal] [--frida /path/to/libfrida-gadget.so] [--dry-run]"
  exit 1
fi

APK_PATH="$1"; shift || true
INJECT_ALL="false"
NO_GOOGLE_LOGIN="false"
MINIMAL="false"
FRIDA_SO=""
DRYRUN="false"

while [ $# -gt 0 ]; do
  case "$1" in
    --inject-all) INJECT_ALL="true"; shift ;;
    --no-google-login) NO_GOOGLE_LOGIN="true"; shift ;;
    --minimal) MINIMAL="true"; shift ;;
    --frida) shift; FRIDA_SO="$1"; shift ;;
    --dry-run) DRYRUN="true"; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [ ! -f "$APK_PATH" ]; then
  echo "APK not found: $APK_PATH"; exit 1
fi

command -v apktool >/dev/null 2>&1 || { echo "Install apktool first (pkg install apktool)"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Install python3 (pkg install python)"; exit 1; }

APKSIGNER="$(command -v apksigner || true)"
KEYTOOL="$(command -v keytool || true)"

APK_NAME=$(basename "$APK_PATH" .apk)
WORK_DIR="${APK_NAME}_src"
PATCHED_APK="${APK_NAME}_aggressive_patched.apk"
LOGFILE="${APK_NAME}_aggressive_log.txt"
BACKUP_DIR="${WORK_DIR}_backup_smali"

# default behavior: if neither inject-all nor minimal passed, do inject-all
if [ "$INJECT_ALL" = "false" ] && [ "$MINIMAL" = "false" ]; then
  INJECT_ALL="true"
fi

echo "[*] Options: INJECT_ALL=$INJECT_ALL NO_GOOGLE_LOGIN=$NO_GOOGLE_LOGIN MINIMAL=$MINIMAL FRIDA_SO=$FRIDA_SO DRYRUN=$DRYRUN"
echo "[*] APK: $APK_PATH"
echo "" > "$LOGFILE"

# cleanup
rm -rf "$WORK_DIR" "$PATCHED_APK" "$LOGFILE" "$BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# 1) decompile
echo "[*] Decompiling APK..." | tee -a "$LOGFILE"
apktool d -f "$APK_PATH" -o "$WORK_DIR" 2>&1 | tee -a "$LOGFILE"

# 2) find smali dirs
mapfile -t SMALI_DIRS < <(find "$WORK_DIR" -maxdepth 3 -type d -name "smali*" 2>/dev/null || true)
if [ "${#SMALI_DIRS[@]}" -eq 0 ]; then
  echo "[!] No smali directories found. Exiting." | tee -a "$LOGFILE"; exit 1
fi
echo "[*] Found smali directories: ${SMALI_DIRS[*]}" | tee -a "$LOGFILE"

# 3) create python patcher (aggressive heuristics)
PYPATCHER="$(mktemp -u)/aggressive_frida_patcher.py"
cat > "$PYPATCHER" <<'PY'
#!/usr/bin/env python3
# aggressive_frida_patcher.py
# Usage: aggressive_frida_patcher.py <smali_file> <mode> <no_google_login> <dryrun>
import sys, re, os
path = sys.argv[1]
mode = sys.argv[2]  # "all" or "minimal"
no_google = sys.argv[3].lower() == "true"
dryrun = sys.argv[4].lower() == "true"

txt = open(path,'r',encoding='utf-8',errors='ignore').read()
orig = txt
method_re = re.compile(r'(^\s*\.method[^\r\n]*\r?\n.*?^\s*\.end method)', re.S|re.M)
patched = []

def get_ret(header):
    m = re.search(r'\)[^\s]*', header)
    if m:
        return m.group(0)[-1]
    return 'V'

def make_stub(header,ret,mode):
    decl = header
    if ret == 'V':
        return f"{decl}\n    .locals 0\n    return-void\n.end method\n"
    if ret == 'Z':
        # default choices:
        # - login -> return true
        # - others -> return false
        if mode == 'login':
            return f"{decl}\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method\n"
        else:
            return f"{decl}\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method\n"
    # fallback
    return f"{decl}\n    .locals 0\n    return-void\n.end method\n"

for m in list(method_re.finditer(txt)):
    block = m.group(1)
    header = block.splitlines()[0].strip()
    low = block.lower()
    choose = None

    # always target SSL pinning patterns
    if ('x509certificate' in low and 'java/lang/string' in low) or 'javax/net/ssl/sslsession' in low \
       or 'certificatepinner' in low or 'okhttp' in low or 'checkservertrusted' in low or 'hostnameverifier' in header.lower():
        choose = 'ssl'

    # root detection patterns
    if any(x in low for x in ['isrooted','isdevicerooted','checkroot','/system/bin/su','/system/xbin/su','test-keys','getprop ro.secure','ro.debuggable','superuser']):
        choose = 'root' if choose is None else choose

    # debug detection
    if any(x in low for x in ['isdebuggerconnected','isdebuggable','android:debuggable','getprop ro.debuggable']):
        choose = 'debug' if choose is None else choose

    # login/session heuristics (skipped if no_google flag true, but still patch non-google logins)
    login_keys = ['isloggedin','isauthenticated','hassession','getauthtoken','getidtoken','getaccesstoken','checksession','setloggedin','is_user_logged','is_signed_in']
    google_keys = ['com/google/android/gms','google.signin','google_signin','googlesignin','accounts.google']
    if any(k in low for k in login_keys):
        choose = 'login'
    # if google-specific and user requested skip-google, then skip choosing login for google patterns
    if any(k in low for k in google_keys):
        if no_google:
            # do not set choose to login for google-specific patterns
            pass
        else:
            choose = 'login'

    # additional aggressive heuristics when mode == 'all'
    if mode == 'all':
        if 'okhttpclient' in low or 'certificatepinner.check' in low:
            choose = 'ssl' if choose is None else choose
        # methods that check hostname/referer
        if 'verify(' in header.lower() and 'sslsession' in low:
            choose = 'ssl' if choose is None else choose

    if choose:
        ret = get_ret(header)
        # decide stub mode: for login->login, for others -> root/debug/ssl -> non-login stub
        stubmode = 'login' if choose == 'login' else 'other'
        new = make_stub(header, ret, stubmode)
        txt = txt.replace(block, new, 1)
        patched.append(f"{header}::{choose}")

if patched:
    if not dryrun:
        open(path,'w',encoding='utf-8').write(txt)
    print("PATCHED:" + ";".join(patched))
else:
    print("NOPATCH")
PY
chmod +x "$PYPATCHER"

echo "[*] Scanning and patching smali files..." | tee -a "$LOGFILE"
PATCHED_TOTAL=0
for sd in "${SMALI_DIRS[@]}"; do
  while IFS= read -r -d '' smfile; do
    rel="${smfile#$WORK_DIR/}"
    bak="${BACKUP_DIR}/${rel//\//_}.bak"
    mkdir -p "$(dirname "$bak")" || true
    cp "$smfile" "$bak"
    # run patcher
    MODE="minimal"
    if [ "$INJECT_ALL" = "true" ] && [ "$MINIMAL" = "false" ]; then MODE="all"; fi
    out="$(python3 "$PYPATCHER" "$smfile" "$MODE" "$NO_GOOGLE_LOGIN" "$DRYRUN" 2>/dev/null || true)"
    if [[ "$out" == PATCHED:* ]]; then
      echo "[PATCHED] $smfile -> ${out#PATCHED:}" | tee -a "$LOGFILE"
      PATCHED_TOTAL=$((PATCHED_TOTAL+1))
    fi
    if [[ "$out" == NOPATCH* ]]; then
      # no-op
      :
    fi
  done < <(find "$sd" -type f -name "*.smali" -print0)
done

echo "[*] Total patched files: $PATCHED_TOTAL" | tee -a "$LOGFILE"
if [ "$DRYRUN" = "true" ]; then
  echo "[*] Dry-run enabled: No files were modified (backups still made)." | tee -a "$LOGFILE"
  echo "[*] Exiting (dry-run)" | tee -a "$LOGFILE"
  exit 0
fi

# 4) Copy frida .so if requested; decide lib target
if [ -n "$FRIDA_SO" ]; then
  if [ ! -f "$FRIDA_SO" ]; then
    echo "[!] FRIDA .so not found at $FRIDA_SO" | tee -a "$LOGFILE"
  else
    LIB_TARGET=""
    for d in "lib/arm64-v8a" "lib/armeabi-v7a" "lib/x86" "lib/x86_64"; do
      if [ -d "$WORK_DIR/$d" ]; then LIB_TARGET="$d"; break; fi
    done
    if [ -z "$LIB_TARGET" ]; then
      LIB_TARGET="lib/arm64-v8a"
      mkdir -p "$WORK_DIR/$LIB_TARGET"
    fi
    cp "$FRIDA_SO" "$WORK_DIR/$LIB_TARGET/libfrida-gadget.so"
    echo "[*] Copied frida .so to $WORK_DIR/$LIB_TARGET/libfrida-gadget.so" | tee -a "$LOGFILE"
  fi
fi

# 5) Aggressive injection: Application.onCreate & all Activity.onCreate
PYINJ="$(mktemp -u)/aggressive_full_inject.py"
cat > "$PYINJ" <<'PYINJ'
#!/usr/bin/env python3
# aggressive_full_inject.py
# Inject System.loadLibrary("frida-gadget") into Application.onCreate and all Activity onCreate
import sys, os, re, xml.etree.ElementTree as ET
work = sys.argv[1]
frida_name = sys.argv[2] if len(sys.argv)>2 and sys.argv[2] else "frida-gadget"

# parse manifest for application name
man = os.path.join(work, "AndroidManifest.xml")
pkg = None
app_name = None
if os.path.exists(man):
    try:
        tree = ET.parse(man); root = tree.getroot()
        pkg = root.attrib.get('package')
        app = root.find('application')
        if app is not None:
            app_name = app.attrib.get('{http://schemas.android.com/apk/res/android}name') or app.attrib.get('android:name')
    except Exception:
        pass

# collect smali dirs & files
smali_dirs=[]
for r,d,f in os.walk(work):
    for dd in d:
        if dd.startswith("smali"):
            smali_dirs.append(os.path.join(r,dd))
candidates=[]
for sd in smali_dirs:
    for root,dirs,files in os.walk(sd):
        for file in files:
            if not file.endswith(".smali"): continue
            path = os.path.join(root,file)
            txt = open(path,'r',encoding='utf-8',errors='ignore').read()
            if " Landroid/app/Application;" in txt or " Landroid/app/Application" in txt:
                candidates.append(("app",path))
            if any(x in txt for x in [" Landroid/app/Activity;"," Landroidx/appcompat/app/AppCompatActivity;"," Landroid/support/v4/app/FragmentActivity;"]):
                candidates.append(("act",path))
# dedupe
seen=set(); filtered=[]
for t,p in candidates:
    if p not in seen:
        filtered.append((t,p)); seen.add(p)
# prefer manifest-specified Application
target_app=None
if app_name:
    an = app_name
    if an.startswith("."): an = (pkg or "") + an
    # simple match by simple file name
    for t,p in filtered:
        if an.split('.')[-1]+".smali" in p and t=="app":
            target_app=p; break
if not target_app:
    for t,p in filtered:
        if t=="app":
            target_app=p; break

injected=[]
# helper to ensure .locals >=1 and insert loadLibrary
def inject_into(path, frida_name):
    txt=open(path,'r',encoding='utf-8',errors='ignore').read()
    # find onCreate method
    m = re.search(r'(^\s*\.method[^\r\n]*onCreate\(\)V[^\r\n]*\r?\n.*?^\s*\.end method)', txt, re.S|re.M)
    if m:
        block = m.group(1)
        # ensure .locals at least 1
        loc = re.search(r'^\s*\.locals\s+(\d+)', block, re.M)
        if loc:
            if int(loc.group(1)) < 1:
                block = re.sub(r'^(\s*\.locals\s+)(\d+)', lambda mo: mo.group(1)+"1", block, count=1, flags=re.M)
        else:
            block = block.replace("\n", "\n    .locals 1\n", 1)
        inject_code = f'    const-string v0, "{frida_name}"\n    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
        # place after .locals
        block = re.sub(r'(^\s*\.method[^\r\n]*\r?\n\s*\.locals[^\r\n]*\r?\n)', lambda mo: mo.group(0)+inject_code, block, count=1, flags=re.M)
        newtxt = txt.replace(m.group(1), block, 1)
        open(path,'w',encoding='utf-8').write(newtxt)
        return True
    else:
        # add method before .end class (use Application.super as generic invoke-super to Application)
        endcls = re.search(r'(^\s*\.end class\s*$)', txt, re.M)
        if endcls:
            method_stub = f'\n    .method public onCreate()V\n    .locals 1\n    const-string v0, "{frida_name}"\n    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n    invoke-super {{p0}}, Landroid/app/Application;->onCreate()V\n    return-void\n    .end method\n'
            newtxt = txt[:endcls.start()] + method_stub + txt[endcls.start():]
            open(path,'w',encoding='utf-8').write(newtxt)
            return True
    return False

# inject into Application first
if target_app:
    ok = inject_into(target_app, frida_name)
    if ok: injected.append(target_app)

# inject into all activities too
for t,p in filtered:
    if t == "act":
        ok = inject_into(p, frida_name)
        if ok: injected.append(p)

# report
if injected:
    print("INJECTED:" + ",".join(injected))
else:
    print("NONE")
PYINJ
chmod +x "$PYINJ"

# decide frida-name (without lib and .so)
FRIDA_NAME="frida-gadget"
if [ -n "$FRIDA_SO" ]; then
  bn=$(basename "$FRIDA_SO")
  bn=${bn#lib}
  FRIDA_NAME="${bn%.so}"
fi

echo "[*] Injecting loader into Application & Activities (aggressive)..." | tee -a "$LOGFILE"
python3 "$PYINJ" "$WORK_DIR" "$FRIDA_NAME" 2>&1 | tee -a "$LOGFILE" || true

# 6) rebuild
echo "[*] Rebuilding APK (apktool b)..." | tee -a "$LOGFILE"
apktool b "$WORK_DIR" -o "$PATCHED_APK" 2>&1 | tee -a "$LOGFILE" || {
  echo "[!] Rebuild failed. Consider moving $WORK_DIR to x64 PC and run: apktool b $WORK_DIR -o $PATCHED_APK" | tee -a "$LOGFILE"
  exit 1
}

# 7) sign (generate keystore if absent)
KEYSTORE="aggressive_frida_key.jks"
KS_PASS="123456"
KS_ALIAS="aggressivefrida"
if [ ! -f "$KEYSTORE" ] && [ -n "$KEYTOOL" ]; then
  echo "[*] Generating keystore $KEYSTORE..." | tee -a "$LOGFILE"
  "$KEYTOOL" -genkey -v -keystore "$KEYSTORE" -storepass "$KS_PASS" -alias "$KS_ALIAS" -keypass "$KS_PASS" -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=AggressiveFrida, OU=Dev, O=Me, L=City, S=State, C=ID" 2>&1 | tee -a "$LOGFILE"
fi

if [ -n "$APKSIGNER" ]; then
  echo "[*] Signing patched APK..." | tee -a "$LOGFILE"
  "$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass "pass:$KS_PASS" "$PATCHED_APK" 2>&1 | tee -a "$LOGFILE" || true
  echo "[✓] Output APK: $PATCHED_APK" | tee -a "$LOGFILE"
else
  echo "[!] apksigner not found. APK built but unsigned: $PATCHED_APK" | tee -a "$LOGFILE"
fi

echo "[*] Backup of original smali in: $BACKUP_DIR" | tee -a "$LOGFILE"
echo "[*] Done. See log: $LOGFILE" | tee -a "$LOGFILE"
