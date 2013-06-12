#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <time.h>

#include <drm.h>

#include "libdrm_lists.h"
#include "armada_bufmgr.h"
#include "armada_ioctl.h"

#ifndef container_of
#define container_of(ptr, type, member) ({ \
    const typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

/* The interval in seconds between cache cleans */
#define BO_CACHE_CLEAN_INTERVAL	1
/* The maximum age in seconds of a BO in the cache */
#define BO_CACHE_MAX_AGE	2
/* Number of buckets in the BO cache */
#define NUM_BUCKETS		(3*9)

/*
 * These sizes come from the i915 DRM backend - which uses roughly
 * for n = 2..
 *   (4096 << n) + (4096 << n) * 1 / 4
 *   (4096 << n) + (4096 << n) * 2 / 4
 *   (4096 << n) + (4096 << n) * 3 / 4
 * The reasoning being that powers of two are too wasteful in X.
 */
static size_t bucket_size[NUM_BUCKETS] = {
	   4096,	   8192,	  12288,
	  20480,	  24576,	  28672,
	  40960,	  49152,	  57344,
	  81920,	  98304,	 114688,
	 163840,	 196608,	 229376,
	 327680,	 393216,	 458752,
	 655360,	 786432,	 917504,
	1310720,	1572864,	1835008,
	2621440,	3145728,	3670016,
};

struct armada_bucket {
	drmMMListHead head;	/* LRU list of bos in this size */
	size_t size;
};

struct armada_bo_cache {
	struct armada_bucket buckets[NUM_BUCKETS];
	drmMMListHead head;	/* LRU list of all freed bos */
	time_t last_cleaned;
};

struct drm_armada_bufmgr {
	struct armada_bo_cache cache;
	int fd;
};

struct armada_bo {
	struct drm_armada_bo bo;
	struct drm_armada_bufmgr *mgr; /* manager associated with this bo */
	drmMMListHead bucket;        /* Cache bucket list */
	drmMMListHead free;          /* Free list */
	time_t free_time;            /* Time this bo was freed */
	size_t alloc_size;           /* Allocated size */
	uint32_t ref;                /* Reference count */
	uint32_t name;               /* Global name */
};

#define to_armada_bo(_bo) container_of(_bo, struct armada_bo, bo)

#ifndef DRM_IOCTL_MODE_CREATE_DUMB
/* create a dumb scanout buffer */
struct drm_mode_create_dumb {
        uint32_t height;
        uint32_t width;
        uint32_t bpp;
        uint32_t flags;
        /* handle, pitch, size will be returned */
        uint32_t handle;
        uint32_t pitch;
        uint64_t size;
};
#define DRM_IOCTL_MODE_CREATE_DUMB DRM_IOWR(0xB2, struct drm_mode_create_dumb)
#endif

#ifndef DRM_IOCTL_MODE_DESTROY_DUMB
struct drm_mode_destroy_dumb {
        uint32_t handle;
};
#define DRM_IOCTL_MODE_DESTROY_DUMB    DRM_IOWR(0xB4, struct drm_mode_destroy_dumb)
#endif

#ifndef DRM_IOCTL_MODE_MAP_DUMB
struct drm_mode_map_dumb {
	uint32_t handle;
	uint32_t pad;
	uint64_t offset;
};
#define DRM_IOCTL_MODE_MAP_DUMB    DRM_IOWR(0xB3, struct drm_mode_map_dumb)
#endif

/* Given a width and bpp, return the pitch of a bo */
static unsigned armada_bo_pitch(unsigned width, unsigned bpp)
{
    unsigned pitch = bpp != 4 ? width * ((bpp + 7) / 8) : width / 2;

    /* 88AP510 spec recommends pitch be a multiple of 128 */
    return (pitch + 127) & ~127;
}

/* Given the pitch and height, return the allocated size in bytes of a bo */
static size_t armada_bo_size(unsigned pitch, unsigned height)
{
    return pitch * height;
}

static size_t armada_bo_round_size(size_t size)
{
    if (size > 1048576)
        size = (size + 1048575) & ~1048575;
    else if (size > 65536)
        size = (size + 65535) & ~65535;
    else
        size = (size + 4095) & ~4095;
    return size;
}

static void armada_bo_free(struct armada_bo *bo)
{
    int ret, fd = bo->mgr->fd;

    if (bo->bo.ptr) {
        munmap(bo->bo.ptr, bo->alloc_size);
        bo->bo.ptr = NULL;
    }

    if (bo->bo.type == DRM_ARMADA_BO_DUMB) {
        struct drm_mode_destroy_dumb arg;

        memset(&arg, 0, sizeof(arg));
        arg.handle = bo->bo.handle;
        ret = drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &arg);
    } else {
        struct drm_gem_close close;

        memset(&close, 0, sizeof(close));
        close.handle = bo->bo.handle;
        ret = ioctl(fd, DRM_IOCTL_GEM_CLOSE, &close);
    }

    if (ret == 0)
        free(bo);
}

static void armada_bo_cache_init(struct armada_bo_cache *cache)
{
    struct timespec time;
    unsigned i;

    clock_gettime(CLOCK_MONOTONIC, &time);

    cache->last_cleaned = time.tv_sec;
    DRMINITLISTHEAD(&cache->head);

    for (i = 0; i < NUM_BUCKETS; i++) {
        DRMINITLISTHEAD(&cache->buckets[i].head);
        cache->buckets[i].size = bucket_size[i];
    }
}

static void armada_bo_cache_fini(struct armada_bo_cache *cache)
{
    while (!DRMLISTEMPTY(&cache->head)) {
        struct armada_bo *bo;

        bo = DRMLISTENTRY(struct armada_bo, cache->head.next, free);

        DRMLISTDEL(&bo->bucket);
        DRMLISTDEL(&bo->free);

        armada_bo_free(bo);
    }
}

static struct armada_bucket *armada_find_bucket(struct armada_bo_cache *cache, size_t size)
{
    unsigned i;

    for (i = 0; i < NUM_BUCKETS; i++) {
        struct armada_bucket *bucket = &cache->buckets[i];

        if (bucket->size >= size)
            return bucket;
    }

    return NULL;
}

static void armada_bo_cache_clean(struct armada_bo_cache *cache, time_t time)
{
    if (time - cache->last_cleaned < BO_CACHE_CLEAN_INTERVAL)
        return;

    cache->last_cleaned = time;

    while (!DRMLISTEMPTY(&cache->head)) {
        struct armada_bo *bo;

        bo = DRMLISTENTRY(struct armada_bo, cache->head.next, free);
        if (time - bo->free_time < BO_CACHE_MAX_AGE)
            break;

        DRMLISTDEL(&bo->bucket);
        DRMLISTDEL(&bo->free);

        armada_bo_free(bo);
    }
}

static struct armada_bo *armada_bo_bucket_get(struct armada_bucket *bucket, size_t size)
{
    struct armada_bo *bo = NULL;

    if (!DRMLISTEMPTY(&bucket->head)) {
        drmMMListHead *entry = bucket->head.next;

        bo = DRMLISTENTRY(struct armada_bo, entry, bucket);
        DRMLISTDEL(&bo->bucket);
        DRMLISTDEL(&bo->free);
    }
    return bo;
}

static void armada_bo_cache_put(struct armada_bo *bo)
{
    struct armada_bo_cache *cache = &bo->mgr->cache;
    struct armada_bucket *bucket = armada_find_bucket(cache, bo->alloc_size);

    if (bucket) {
        struct timespec time;

        clock_gettime(CLOCK_MONOTONIC, &time);

        bo->free_time = time.tv_sec;
        DRMLISTADDTAIL(&bo->bucket, &bucket->head);
        DRMLISTADDTAIL(&bo->free, &cache->head);

        armada_bo_cache_clean(cache, time.tv_sec);

        return;
    }
    armada_bo_free(bo);
}

struct drm_armada_bo *drm_armada_bo_create_phys(struct drm_armada_bufmgr *mgr,
    uint32_t phys, size_t size)
{
    struct armada_bo *bo;
    int fd = mgr->fd;

    bo = calloc(1, sizeof *bo);
    if (bo) {
        struct drm_armada_gem_create_phys arg;
        int ret;

        memset(&arg, 0, sizeof(arg));
        arg.phys = phys;
        arg.size = size;

        ret = drmIoctl(fd, DRM_IOCTL_ARMADA_GEM_CREATE_PHYS, &arg);
        if (ret) {
            free(bo);
            return NULL;
        }
        bo->bo.ref = 1;
        bo->bo.handle = arg.handle;
        bo->bo.size = size;
        bo->bo.phys = phys;
        bo->bo.type = DRM_ARMADA_BO_LINEAR;
        bo->alloc_size = size;
        bo->ref = 1;
        bo->mgr = mgr;
    }
    return &bo->bo;
}

struct drm_armada_bo *drm_armada_bo_create(struct drm_armada_bufmgr *mgr,
    unsigned w, unsigned h, unsigned bpp)
{
    struct drm_armada_gem_create arg;
    struct armada_bucket *bucket;
    struct armada_bo *bo;
    unsigned pitch;
    size_t alloc_size;
    int fd = mgr->fd;
    int ret;

    pitch = armada_bo_pitch(w, bpp);
    alloc_size = armada_bo_size(pitch, h);

    /* Try to find a bucket for this allocation */
    bucket = armada_find_bucket(&mgr->cache, alloc_size);
    if (bucket) {
        /* Can we allocate from our cache? */
        bo = armada_bo_bucket_get(bucket, alloc_size);
        if (bo) {
            bo->bo.size = pitch * h;
            bo->bo.pitch = pitch;
            bo->ref = 1;
            return &bo->bo;
        }

        /* Otherwise, allocate a bo of the bucket size */
        alloc_size = bucket->size;
    } else {
        /* No bucket, so round the size up according to our old rules */
        alloc_size = armada_bo_round_size(alloc_size);
    }

    /* No, create a new bo */
    bo = calloc(1, sizeof *bo);
    if (!bo)
        return NULL;

    memset(&arg, 0, sizeof(arg));
    arg.size = alloc_size;

    ret = drmIoctl(fd, DRM_IOCTL_ARMADA_GEM_CREATE, &arg);
    if (ret) {
        free(bo);
        return NULL;
    }

    bo->bo.ref = 1;
    bo->bo.handle = arg.handle;
    bo->bo.size = pitch * h;
    bo->bo.pitch = pitch;
    bo->bo.type = DRM_ARMADA_BO_SHMEM;
    bo->alloc_size = alloc_size;
    bo->ref = 1;
    bo->mgr = mgr;

    return &bo->bo;
}

struct drm_armada_bo *drm_armada_bo_create_from_name(struct drm_armada_bufmgr *mgr,
    uint32_t name)
{
    struct armada_bo *bo;
    int fd = mgr->fd;

    bo = calloc(1, sizeof *bo);
    if (bo) {
        struct drm_gem_open arg;
        int ret;

        memset(&arg, 0, sizeof(arg));
        arg.name = name;
        ret = drmIoctl(fd, DRM_IOCTL_GEM_OPEN, &arg);
        if (ret == -1) {
            free(bo);
            return NULL;
        }
        bo->bo.ref = 1;
        bo->bo.handle = arg.handle;
        bo->bo.size = arg.size;
        bo->bo.type = DRM_ARMADA_BO_LINEAR; /* assumed */
        bo->alloc_size = arg.size;
        bo->ref = 1;
        bo->name = name;
        bo->mgr = mgr;
    }
    return &bo->bo;
}

struct drm_armada_bo *drm_armada_bo_dumb_create(struct drm_armada_bufmgr *mgr,
    unsigned w, unsigned h, unsigned bpp)
{
    struct armada_bo *bo;
    int fd = mgr->fd;

    bo = calloc(1, sizeof *bo);
    if (bo) {
        struct drm_mode_create_dumb arg;
        int ret;

        memset(&arg, 0, sizeof(arg));
        arg.width = w;
        arg.height = h;
        arg.bpp = bpp;

        ret = drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &arg);
        if (ret) {
            free(bo);
            return NULL;
        }
        bo->bo.ref = 1;
        bo->bo.handle = arg.handle;
        bo->bo.size = arg.size;
        bo->bo.pitch = arg.pitch;
        bo->bo.type = DRM_ARMADA_BO_DUMB;
        bo->alloc_size = arg.size;
        bo->ref = 1;
        bo->mgr = mgr;
    }
    return &bo->bo;
}

void drm_armada_bo_get(struct drm_armada_bo *dbo)
{
    struct armada_bo *bo = to_armada_bo(dbo);
    bo->ref++;
}

void drm_armada_bo_put(struct drm_armada_bo *dbo)
{
    struct armada_bo *bo = to_armada_bo(dbo);

    if (bo->ref-- == 1) {
        int ret;

        if (bo->bo.type == DRM_ARMADA_BO_SHMEM)
            armada_bo_cache_put(bo);
        else
            armada_bo_free(bo);
    }
}

int drm_armada_bo_flink(struct drm_armada_bo *dbo, uint32_t *name)
{
    struct armada_bo *bo = to_armada_bo(dbo);
    int fd = bo->mgr->fd;

    if (!bo->name) {
        struct drm_gem_flink flink;
        int ret;

        memset(&flink, 0, sizeof(flink));
        flink.handle = bo->bo.handle;
        ret = ioctl(fd, DRM_IOCTL_GEM_FLINK, &flink);
        if (ret)
            return ret;
        bo->name = flink.name;
    }
    *name = bo->name;
    return 0;
}

int drm_armada_bo_to_fd(struct drm_armada_bo *dbo, int *prime_fd)
{
    struct armada_bo *bo = to_armada_bo(dbo);
    int fd = bo->mgr->fd;

    if (drmPrimeHandleToFD(fd, bo->bo.handle, DRM_CLOEXEC, prime_fd))
        return -1;

    return 0;
}

int drm_armada_bo_map(struct drm_armada_bo *dbo)
{
    struct armada_bo *bo = to_armada_bo(dbo);
    void *map;
    int ret, fd = bo->mgr->fd;

    if (bo->bo.ptr)
        return 0;

    if (bo->bo.type == DRM_ARMADA_BO_DUMB) {
        struct drm_mode_map_dumb arg;

        memset(&arg, 0, sizeof(arg));
        arg.handle = bo->bo.handle;

        ret = drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &arg);
        if (ret)
            return ret;

        map = mmap(0, bo->alloc_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                   arg.offset);

        if (map == MAP_FAILED)
            return -1;
    } else if (bo->bo.type == DRM_ARMADA_BO_SHMEM) {
        struct drm_armada_gem_mmap arg;

        memset(&arg, 0, sizeof(arg));
        arg.handle = bo->bo.handle;
        arg.offset = 0;
        arg.size = bo->alloc_size;

        ret = drmIoctl(fd, DRM_IOCTL_ARMADA_GEM_MMAP, &arg);
        if (ret)
            return -1;

        map = (void *)(uintptr_t)arg.addr;
    } else {
        errno = EINVAL;
        return -1;
    }

    bo->bo.ptr = map;

    return 0;
}

uint32_t drm_armada_bo_phys(struct drm_armada_bo *dbo)
{
    struct armada_bo *bo = to_armada_bo(dbo);
    struct drm_armada_gem_prop arg;
    int ret, fd = bo->mgr->fd;

    memset(&arg, 0, sizeof(arg));
    arg.handle = bo->bo.handle;

    ret = drmIoctl(fd, DRM_IOCTL_ARMADA_GEM_PROP, &arg);

    return ret ? -1 : (uint32_t)arg.phys;
}

int drm_armada_bo_subdata(struct drm_armada_bo *dbo, unsigned long offset,
    unsigned long size, const void *data)
{
    struct armada_bo *bo = to_armada_bo(dbo);
    struct drm_armada_gem_pwrite arg;
    int fd = bo->mgr->fd;

    memset(&arg, 0, sizeof(arg));
    arg.ptr = (uint64_t)(uintptr_t)data;
    arg.handle = bo->bo.handle;
    arg.offset = offset;
    arg.size = size;

    return drmIoctl(fd, DRM_IOCTL_ARMADA_GEM_PWRITE, &arg);
}

int drm_armada_init(int fd, struct drm_armada_bufmgr **mgrp)
{
    struct drm_armada_bufmgr *mgr;

    mgr = calloc(1, sizeof(*mgr));
    if (!mgr)
        return -1;

    armada_bo_cache_init(&mgr->cache);
    mgr->fd = fd;
    *mgrp = mgr;

    return 0;
}

void drm_armada_fini(struct drm_armada_bufmgr *mgr)
{
    armada_bo_cache_fini(&mgr->cache);
    free(mgr);
}
