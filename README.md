
## zipalign & apksigner (Android build tools)
<pre>
# Termux
pkg install apksigner zipalign -y
# Linux
sudo apt install apksigner zipalign -y

</pre>

## apktool
<pre>
# Termux
pkg install apktool -y
# Linux
sudo apt install apktool -y

</pre>

## Java (JDK)
<pre>
# termux
  pkg install openjdk-17 -y
# linux
sudo apt install openjdk-17-jdk -y 

</pre>

## aggressive_patch_apk
example:
<pre>
  chmod +x aggressive-frida-patcher.sh

# Full aggressive (patch semua, termasuk login)
./aggressive-frida-patcher.sh target.apk --inject-all

# Full aggressive but jangan ubah Google login
./aggressive-frida-patcher.sh target.apk --inject-all --no-google-login

# Minimal (SSL + root)
./aggressive-frida-patcher.sh target.apk --minimal

# Inject frida gadget (copy .so and auto-load)
./aggressive-frida-patcher.sh target.apk --inject-all --frida /sdcard/libfrida-gadget.so

# Dry run (lihat apa yang akan diubah)
./aggressive-frida-patcher.sh target.apk --inject-all --dry-run

</pre>
