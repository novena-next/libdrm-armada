#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include <drm.h>

#include "dove_bufmgr.h"
#include "dove_ioctl.h"

#ifndef container_of
#define container_of(ptr, type, member) ({ \
    const typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

struct dove_bo {
	struct drm_dove_bo bo;
	uint32_t ref;
	uint32_t name;          /* Global name */
};

#define to_dove_bo(_bo) container_of(_bo, struct dove_bo, bo)

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

struct drm_dove_bo *drm_dove_bo_create_phys(int fd, uint32_t phys, size_t size)
{
    struct dove_bo *bo;

    bo = calloc(1, sizeof *bo);
    if (bo) {
        struct drm_dove_gem_create_phys arg;
        int ret;

        memset(&arg, 0, sizeof(arg));
        arg.phys = phys;
        arg.size = size;

        ret = drmIoctl(fd, DRM_IOCTL_DOVE_GEM_CREATE_PHYS, &arg);
        if (ret) {
            free(bo);
            return NULL;
        }
        bo->bo.ref = 1;
        bo->bo.handle = arg.handle;
        bo->bo.size = size;
        bo->bo.phys = phys;
        bo->bo.type = DRM_DOVE_BO_LINEAR;
        bo->ref = 1;
    }
    return &bo->bo;
}

struct drm_dove_bo *drm_dove_bo_create(int fd, unsigned w, unsigned h, unsigned bpp)
{
    struct dove_bo *bo;

    bo = calloc(1, sizeof *bo);
    if (bo) {
        struct drm_dove_gem_create arg;
        int ret;

        memset(&arg, 0, sizeof(arg));
        arg.width = w;
        arg.height = h;
        arg.bpp = bpp;

        ret = drmIoctl(fd, DRM_IOCTL_DOVE_GEM_CREATE, &arg);
        if (ret) {
            free(bo);
            return NULL;
        }

        bo->bo.ref = 1;
        bo->bo.handle = arg.handle;
        bo->bo.size = arg.size;
        bo->bo.pitch = arg.pitch;
        bo->bo.type = DRM_DOVE_BO_SHMEM;
        bo->ref = 1;
    }
    return &bo->bo;
}

struct drm_dove_bo *drm_dove_bo_create_from_name(int fd, uint32_t name)
{
    struct dove_bo *bo;

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
        bo->bo.type = DRM_DOVE_BO_LINEAR; /* assumed */
        bo->ref = 1;
        bo->name = name;
    }
    return &bo->bo;
}

struct drm_dove_bo *drm_dove_bo_dumb_create(int fd, unsigned w, unsigned h,
    unsigned bpp)
{
    struct dove_bo *bo;

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
        bo->bo.type = DRM_DOVE_BO_DUMB;
        bo->ref = 1;
    }
    return &bo->bo;
}

void drm_dove_bo_get(int fd, struct drm_dove_bo *dbo)
{
    struct dove_bo *bo = to_dove_bo(dbo);
    bo->ref++;
}

void drm_dove_bo_put(int fd, struct drm_dove_bo *dbo)
{
    struct dove_bo *bo = to_dove_bo(dbo);

    if (bo->ref-- == 1) {
        int ret;

        if (bo->bo.ptr) {
            munmap(bo->bo.ptr, bo->bo.size);
            bo->bo.ptr = NULL;
        }

        if (bo->bo.type == DRM_DOVE_BO_DUMB) {
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
}

int drm_dove_bo_flink(int fd, struct drm_dove_bo *dbo, uint32_t *name)
{
    struct dove_bo *bo = to_dove_bo(dbo);

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

int drm_dove_bo_map(int fd, struct drm_dove_bo *dbo)
{
    struct dove_bo *bo = to_dove_bo(dbo);
    void *map;
    int ret;

    if (bo->bo.ptr)
        return 0;

    if (bo->bo.type == DRM_DOVE_BO_DUMB) {
        struct drm_mode_map_dumb arg;

        memset(&arg, 0, sizeof(arg));
        arg.handle = bo->bo.handle;

        ret = drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &arg);
        if (ret)
            return ret;

        map = mmap(0, bo->bo.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                   arg.offset);

        if (map == MAP_FAILED)
            return -1;
    } else if (bo->bo.type == DRM_DOVE_BO_SHMEM) {
        struct drm_dove_gem_mmap arg;

        memset(&arg, 0, sizeof(arg));
        arg.handle = bo->bo.handle;
        arg.offset = 0;
        arg.size = bo->bo.size;

        ret = drmIoctl(fd, DRM_IOCTL_DOVE_GEM_MMAP, &arg);
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

uint32_t drm_dove_bo_phys(int fd, struct drm_dove_bo *dbo)
{
    struct dove_bo *bo = to_dove_bo(dbo);
    struct drm_dove_gem_prop arg;
    int ret;

    memset(&arg, 0, sizeof(arg));
    arg.handle = bo->bo.handle;

    ret = drmIoctl(fd, DRM_IOCTL_DOVE_GEM_PROP, &arg);

    return ret ? -1 : (uint32_t)arg.phys;
}

int drm_dove_bo_subdata(int fd, struct drm_dove_bo *bo, unsigned long offset,
    unsigned long size, const void *data)
{
    struct drm_dove_gem_pwrite arg;

    memset(&arg, 0, sizeof(arg));
    arg.handle = bo->handle;
    arg.offset = offset;
    arg.size = size;
    arg.ptr = (uint64_t)(uintptr_t)data;

    return drmIoctl(fd, DRM_IOCTL_DOVE_GEM_PWRITE, &arg);
}

