android-shmem
=============

System V shared memory emulation on Android, using ashmem.
That includes shmget, shmat, shmdt and shmctl functions.
It does not use Binder service, and does not link to Java libraries -
it uses Linux sendmsg/recvmsg API to transfer file handlers.

Before compiling it, run
git submodule update --init libancillary

Also, you will need to add to your CFLAGS:
-D_LINUX_IPC_H -Dipc_perm=debian_ipc_perm
if you link to this library from Android code.

The most obvious reasons to use this lib is to speed up Linux GUI applications,
connected to XServer on Android - it will work for both
Xtightvnc Xserver inside Linux chroot, and for standalone Xserver,
which can be downloaded here:
https://sourceforge.net/projects/libsdl-android/files/apk/XServer-XSDL/

To use it inside Linux chroot installed on Android, do
env LD_PRELOAD="/path/to/libandroid-shmem-gnueabihf.so" linux_command

The shared memory segments it creates will be automatically destoryed
when an owner process destroys them or dies,
however Xserver and it's clients do not depend on that functionality.
