#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>

#ifdef __ANDROID__
#include <android/log.h>
#include "sys/shm.h"

#define DBG(...) __android_log_print(ANDROID_LOG_INFO, "shmem", __VA_ARGS__)
#else
#include <sys/shm.h>

#define DBG(format, ...) fprintf(stderr, format "\n", __VA_ARGS__)
#endif

#include "libancillary/ancillary.h"
#include "cutils/ashmem.h"

static pthread_t listening_thread_id = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct
{
	int remote;
	void *addr;
	int descriptor;
	size_t size;
} shmem_t;
static shmem_t *shmem = NULL;
static size_t shmem_amount = 0;
static int sock = 0;
static int sockid = 0;
#define SOCKNAME "/dev/shm/%08x"
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

static int get_shmid(unsigned int index)
{
	return sockid * 0x10000 + index;
}

static int get_sockid(int shmid)
{
	return shmid / 0x10000;
}

static unsigned int get_index(int shmid)
{
	return shmid % 0x10000;
}

static void *listening_thread(void * arg)
{
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int sendsock;
	DBG ("%s: thread started", __PRETTY_FUNCTION__);
	while ((sendsock = accept (sock, (struct sockaddr *)&addr, &len)) != -1)
	{
		unsigned int index;
		if (recv (sendsock, &index, sizeof(index), 0) != sizeof(index))
		{
			DBG ("%s: ERROR: recv() returned not %d bytes", __PRETTY_FUNCTION__, sizeof(index));
			close (sendsock);
			continue;
		}
		pthread_mutex_lock (&mutex);
		if (index < shmem_amount)
		{
			if (ancil_send_fd (sendsock, shmem[index].descriptor) != 0)
				DBG ("%s: ERROR: ancil_send_fd() failed: %s", __PRETTY_FUNCTION__, strerror(errno));
		}
		else
		{
			DBG ("%s: ERROR: index %d >= shmem_amount %d", __PRETTY_FUNCTION__, index, shmem_amount);
		}
		pthread_mutex_unlock (&mutex);
		close (sendsock);
		len = sizeof(addr);
	}
	DBG ("%s: ERROR: listen() failed, thread stopped", __PRETTY_FUNCTION__);
}

/* Get shared memory segment.  */
int shmget (key_t key, size_t size, int flags)
{
	char buf[256];
	int idx;
	int status;

	DBG ("%s: key %d size %zu flags 0%o (flags are ignored)", __PRETTY_FUNCTION__, key, size, flags);
	if (key != IPC_PRIVATE)
	{
		DBG ("%s: key %d != IPC_PRIVATE,  this is not supported", __PRETTY_FUNCTION__, key, flags);
		errno = EINVAL;
		return -1;
	}
	if (!listening_thread_id)
	{
		int i;
		sock = socket (AF_UNIX, SOCK_STREAM, 0);
		if (!sock)
		{
			DBG ("%s: cannot create UNIX socket: %s", __PRETTY_FUNCTION__, strerror(errno));
			errno = EINVAL;
			return -1;
		}
		for (i = 1; i < 1024; i++)
		{
			struct sockaddr_un addr;
			int len;
			memset (&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			sprintf (&addr.sun_path[1], SOCKNAME, i);
			len = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;
			if (bind (sock, (struct sockaddr *)&addr, len) != 0)
			{
				DBG ("%s: cannot bind UNIX socket %s: %s, trying next one, len %d", __PRETTY_FUNCTION__, &addr.sun_path[1], strerror(errno), len);
				continue;
			}
			DBG ("%s: bound UNIX socket %s", __PRETTY_FUNCTION__, addr.sun_path + 1);
			sockid = i;
			break;
		}
		if (i == 65536)
		{
			DBG ("%s: cannot bind UNIX socket, bailing out", __PRETTY_FUNCTION__);
			errno = ENOMEM;
			return -1;
		}
		if (listen (sock, 4) != 0)
		{
			DBG ("%s: listen failed", __PRETTY_FUNCTION__);
			errno = ENOMEM;
			return -1;
		}
		pthread_create (&listening_thread_id, NULL, &listening_thread, NULL);
	}
	pthread_mutex_lock (&mutex);
	idx = shmem_amount;
	sprintf (buf, SOCKNAME "-%d", sockid, idx);
	shmem_amount ++;
	shmem = realloc (shmem, shmem_amount * sizeof(shmem_t));
	size = ROUND_UP(size, getpagesize ());
	shmem[idx].size = size;
	shmem[idx].descriptor = ashmem_create_region (buf, size);
	shmem[idx].addr = NULL;
	shmem[idx].remote = 0;
	if (shmem[idx].descriptor < 0)
	{
		DBG ("%s: ashmem_create_region() failed for size %zu: %s", __PRETTY_FUNCTION__, size, strerror(errno));
		shmem_amount --;
		shmem = realloc (shmem, shmem_amount * sizeof(shmem_t));
		pthread_mutex_unlock (&mutex);
		return -1;
	}
	DBG ("%s: ID %d shmid %x FD %d size %zu", __PRETTY_FUNCTION__, idx, get_shmid(idx), shmem[idx].descriptor, shmem[idx].size);
	/*
	status = ashmem_set_prot_region (shmem[idx].descriptor, 0666);
	if (status < 0)
	{
		DBG ("%s: ashmem_set_prot_region() failed for size %zu: %s %d", __PRETTY_FUNCTION__, size, strerror(status), status);
		shmem_amount --;
		shmem = realloc (shmem, shmem_amount * sizeof(shmem_t));
		pthread_mutex_unlock (&mutex);
		return -1;
	}
	*/
	/*
	status = ashmem_pin_region (shmem[idx].descriptor, 0, shmem[idx].size);
	if (status < 0)
	{
		DBG ("%s: ashmem_pin_region() failed for size %zu: %s %d", __PRETTY_FUNCTION__, size, strerror(status), status);
		shmem_amount --;
		shmem = realloc (shmem, shmem_amount * sizeof(shmem_t));
		pthread_mutex_unlock (&mutex);
		return -1;
	}
	*/
	DBG ("%s: return ID %d shmid %x FD %d size %zu", __PRETTY_FUNCTION__, idx, get_shmid(idx), shmem[idx].descriptor, shmem[idx].size);
	pthread_mutex_unlock (&mutex);

	return get_shmid(idx);
}

static int shm_find_id(int shmid)
{
	unsigned int idx = get_index (shmid);
	int sid = get_sockid (shmid);
	if (sid != sockid)
	{
		int i;
		for (i = 0; i < shmem_amount; i++)
		{
			if (shmem[i].remote == shmid)
			{
				idx = i;
				sid = sockid;
				return idx;
			}
		}
		DBG ("%s: cannot find remote shmid %x", __PRETTY_FUNCTION__, shmid);
		return -1;
	}
	if (idx >= shmem_amount)
	{
		DBG ("%s: local ID %d > total amount %zu", __PRETTY_FUNCTION__, idx, shmem_amount);
		pthread_mutex_unlock (&mutex);
		return -1;
	}
	return idx;
}

/* Attach shared memory segment.  */
void *shmat (int shmid, const void *shmaddr, int shmflg)
{
	int idx;
	int sid = get_sockid (shmid);
	void *addr;
	DBG ("%s: shmid %x shmaddr %p shmflg %d", __PRETTY_FUNCTION__, shmid, shmaddr, shmflg);

	if (shmaddr != NULL)
	{
		DBG ("%s: shmaddr != NULL not supported", __PRETTY_FUNCTION__);
		errno = EINVAL;
		return (void *)-1;
	}

	pthread_mutex_lock (&mutex);
	idx = shm_find_id (shmid);

	if (idx == -1 && sid != sockid)
	{
		struct sockaddr_un addr;
		int addrlen;
		int recvsock;
		int descriptor;
		int size;

		pthread_mutex_unlock (&mutex);

		DBG ("%s:%d: sockid %d", __PRETTY_FUNCTION__, __LINE__, sid);

		idx = get_index (shmid);
		memset (&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		sprintf (&addr.sun_path[1], SOCKNAME, sid);
		addrlen = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;

		DBG ("%s:%d: addr %s", __PRETTY_FUNCTION__, __LINE__, &addr.sun_path[1]);

		recvsock = socket (AF_UNIX, SOCK_STREAM, 0);
		if (!recvsock)
		{
			DBG ("%s: cannot create UNIX socket: %s", __PRETTY_FUNCTION__, strerror(errno));
			errno = EINVAL;
			return (void *)-1;
		}
		if (connect (recvsock, (struct sockaddr *)&addr, addrlen) != 0)
		{
			DBG ("%s: cannot connect to UNIX socket %s: %s, len %d", __PRETTY_FUNCTION__, addr.sun_path + 1, strerror(errno), addrlen);
			close (recvsock);
			errno = EINVAL;
			return (void *)-1;
		}

		DBG ("%s:%d: connected to socket %s", __PRETTY_FUNCTION__, __LINE__, &addr.sun_path[1]);

		if (send (recvsock, &idx, sizeof(idx), 0) != sizeof(idx))
		{
			DBG ("%s: send() failed on socket %s: %s", __PRETTY_FUNCTION__, addr.sun_path + 1, strerror(errno));
			close (recvsock);
			errno = EINVAL;
			return (void *)-1;
		}

		if (ancil_recv_fd (recvsock, &descriptor) != 0)
		{
			DBG ("%s: ERROR: ancil_recv_fd() failed on socket %s: %s", __PRETTY_FUNCTION__, addr.sun_path + 1, strerror(errno));
			close (recvsock);
			errno = EINVAL;
			return (void *)-1;
		}
		close (recvsock);

		DBG ("%s:%d: got FD %d", __PRETTY_FUNCTION__, __LINE__, descriptor);

		size = ashmem_get_size_region(descriptor);
		if (size == 0 || size == -1)
		{
			DBG ("%s: ERROR: ashmem_get_size_region() returned %d on socket %s: %s", __PRETTY_FUNCTION__, size, addr.sun_path + 1, strerror(errno));
			errno = EINVAL;
			return (void *)-1;
		}

		DBG ("%s:%d: got size %d", __PRETTY_FUNCTION__, __LINE__, size);

		pthread_mutex_lock (&mutex);
		idx = shmem_amount;
		shmem_amount ++;
		shmem = realloc (shmem, shmem_amount * sizeof(shmem_t));
		shmem[idx].remote = shmid;
		shmem[idx].descriptor = descriptor;
		shmem[idx].size = size;
		shmem[idx].addr = NULL;
		DBG ("%s: created new remote shmem ID %d shmid %x FD %d size %zu", __PRETTY_FUNCTION__, idx, shmid, shmem[idx].descriptor, shmem[idx].size);
	}

	if (idx == -1)
	{
		DBG ("%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
		pthread_mutex_unlock (&mutex);
		errno = EINVAL;
		return (void *)-1;
	}
	if (shmem[idx].addr == NULL)
	{
		shmem[idx].addr = mmap(NULL, shmem[idx].size, PROT_READ | (shmflg == 0 ? PROT_WRITE : 0), MAP_SHARED, shmem[idx].descriptor, 0);
		if (shmem[idx].addr == MAP_FAILED)
		{
			DBG ("%s: mmap() failed for ID %x FD %d: %s", __PRETTY_FUNCTION__, idx, shmem[idx].descriptor, strerror(errno));
			shmem[idx].addr = NULL;
		}
	}
	addr = shmem[idx].addr;
	DBG ("%s: mapped addr %p for FD %d ID %d", __PRETTY_FUNCTION__, addr, shmem[idx].descriptor, idx);
	pthread_mutex_unlock (&mutex);

	return addr ? addr : (void *)-1;
}

/* Detach shared memory segment.  */
int shmdt (const void *shmaddr)
{
	pthread_mutex_lock (&mutex);
	int i;
	for (i = 0; i < shmem_amount; i++)
	{
		if (shmem[i].addr == shmaddr)
		{
			if (munmap (shmem[i].addr, shmem[i].size) != 0)
				DBG ("%s: munmap %p failed", __PRETTY_FUNCTION__, shmaddr);
			shmem[i].addr = NULL;
			DBG ("%s: unmapped addr %p for FD %d ID %d", __PRETTY_FUNCTION__, shmaddr, shmem[i].descriptor, i);
			pthread_mutex_unlock (&mutex);
			return 0;
		}
	}
	pthread_mutex_unlock (&mutex);

	DBG ("%s: invalid address %p", __PRETTY_FUNCTION__, shmaddr);
	errno = EINVAL;
	return -1;
}

static int shm_remove (int shmid)
{
	int idx;
	DBG ("%s: shmid %x", __PRETTY_FUNCTION__, shmid);

	pthread_mutex_lock (&mutex);
	idx = shm_find_id (shmid);
	if (idx == -1)
	{
		DBG ("%s: ERROR: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
		pthread_mutex_unlock (&mutex);
		errno = EINVAL;
		return -1;
	}

	if (shmem[idx].addr)
	{
		DBG ("%s: ERROR: shmid %x is still mapped to addr %p, call shmdt() first", __PRETTY_FUNCTION__, shmid, shmem[idx].addr);
		pthread_mutex_unlock (&mutex);
		errno = EINVAL;
		return -1;
	}
	close (shmem[idx].descriptor);
	shmem_amount --;
	memmove (&shmem[idx], &shmem[idx+1], (shmem_amount - idx) * sizeof(shmem_t));
	pthread_mutex_unlock (&mutex);
	return 0;
}

static int shm_stat (int shmid, struct shmid_ds *buf)
{
	int idx;
	DBG ("%s: shmid %x", __PRETTY_FUNCTION__, shmid);

	pthread_mutex_lock (&mutex);
	idx = shm_find_id (shmid);
	if (idx == -1)
	{
		DBG ("%s: ERROR: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
		pthread_mutex_unlock (&mutex);
		errno = EINVAL;
		return -1;
	}
	if (!buf)
	{
		DBG ("%s: ERROR: buf == NULL for shmid %x", __PRETTY_FUNCTION__, shmid);
		pthread_mutex_unlock (&mutex);
		errno = EINVAL;
		return -1;
	}

	/* Report max permissive mode */
	memset (buf, 0, sizeof(struct shmid_ds));
	buf->shm_segsz = shmem[idx].size;
	buf->shm_nattch = 1;
	buf->shm_perm.__key = IPC_PRIVATE;
	buf->shm_perm.uid = geteuid();
	buf->shm_perm.gid = getegid();
	buf->shm_perm.cuid = geteuid();
	buf->shm_perm.cgid = getegid();
	buf->shm_perm.mode = 0666;
	buf->shm_perm.__seq = 1;
	pthread_mutex_unlock (&mutex);
	return 0;
}

/* Shared memory control operation.  */
int shmctl (int shmid, int cmd, struct shmid_ds *buf)
{
	DBG ("%s: shmid %x cmd %d buf %p", __PRETTY_FUNCTION__, shmid, cmd, buf);
	if (cmd == IPC_RMID)
	{
		return shm_remove (shmid);
	}
	if (cmd == IPC_STAT)
	{
		return shm_stat (shmid, buf);
	}

	DBG ("%s: cmd %d not implemented yet!", __PRETTY_FUNCTION__, cmd);
	errno = EINVAL;
	return -1;
}
