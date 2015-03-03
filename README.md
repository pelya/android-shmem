android-shmem
=============

System V shared memory emulation on Android, using ashmem.
That includes shmget, shmat, shmdt and shmctl functions.
It does not use Binder service, and does not link to Java libraries.
It uses Linux sendmsg/recvmsg API instead to transfer file handlers.

Before compiling it, run

    git submodule update --init libancillary

To use in Android add the android-shmem folder to your jni/ directory and add

    LOCAL_SHARED_LIBRARIES += android-shmem

to any Android.mk module file using the android-shmem library.
Add `include $(call all-subdir-makefiles)` to the jni/Android.mk
so that it builds the android-shmem module unless you already specify that
explicitly in some other way.

Also, you will need to add the following to your CFLAGS:

    -D_LINUX_IPC_H -Dipc_perm=debian_ipc_perm

if you link to this library from Android code.

The most obvious reasons to use this lib is to speed up Linux GUI applications,
connected to XServer on Android - it will work for both
Xtightvnc Xserver inside Linux chroot, and for standalone Xserver,
which can be downloaded here:
https://sourceforge.net/projects/libsdl-android/files/apk/XServer-XSDL/

To use it inside Linux chroot installed on Android, do

    env LD_PRELOAD="/path/to/libandroid-shmem-gnueabihf.so" linux_command

The shared memory segments it creates will be automatically destroyed
when an owner process destroys them or dies,
however Xserver and it's clients do not depend on that functionality.
