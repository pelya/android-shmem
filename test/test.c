#include <stdio.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#ifndef __ANDROID__
#define offsetof(type, member)  __builtin_offsetof (type, member)
#define debian_ipc_perm ipc_perm
#endif

int main()
{
	struct shmid_ds ds;
	printf("sizeof(struct shmid_ds)            %d\n", sizeof(ds));
	printf("sizeof(struct debian_ipc_shm_perm) %d\n", sizeof(ds.shm_perm));
	printf("offsetof(ds, shm_perm)             %d\n", offsetof(struct shmid_ds, shm_perm));
	printf("offsetof(ds, shm_segsz)            %d\n", offsetof(struct shmid_ds, shm_segsz));
	printf("offsetof(ds, shm_nattch)           %d\n", offsetof(struct shmid_ds, shm_nattch));
	printf("offsetof(ds.shm_perm, __key)       %d\n", offsetof(struct debian_ipc_perm, __key));
	printf("sizeof(ds.shm_perm.__key)          %d\n", sizeof(ds.shm_perm.__key));
	printf("offsetof(ds.shm_perm, mode)        %d\n", offsetof(struct debian_ipc_perm, mode));
	printf("offsetof(ds.shm_perm, __seq)       %d\n", offsetof(struct debian_ipc_perm, __seq));

	return 0;
}
