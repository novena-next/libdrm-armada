#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include <drm.h>

#include "dove_bufmgr.h"

#include "dove_ioctl.h"

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
    struct drm_dove_bo *bo;

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
        bo->ref = 1;
        bo->handle = arg.handle;
        bo->size = size;
        bo->phys = phys;
        bo->type = DRM_DOVE_BO_LINEAR;
    }
    return bo;
}

struct drm_dove_bo *drm_dove_bo_create(int fd, unsigned w, unsigned h, unsigned bpp)
{
    struct drm_dove_bo *bo;

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
        bo->ref = 1;
        bo->handle = arg.handle;
        bo->size = arg.size;
        bo->pitch = arg.pitch;
        bo->type = DRM_DOVE_BO_SHMEM;
    }
    return bo;
}



struct drm_dove_bo *drm_dove_bo_dumb_create(int fd, unsigned w, unsigned h,
    unsigned bpp)
{
    struct drm_dove_bo *bo;

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
        bo->ref = 1;
        bo->handle = arg.handle;
        bo->size = arg.size;
        bo->pitch = arg.pitch;
        bo->type = DRM_DOVE_BO_DUMB;
    }
    return bo;
}

static void drm_dove_bo_dumb_destroy(int fd, struct drm_dove_bo *bo)
{
    struct drm_mode_destroy_dumb arg;
    int ret;

    if (bo->ptr) {
        munmap(bo->ptr, bo->size);
        bo->ptr = NULL;
    }

    memset(&arg, 0, sizeof(arg));
    arg.handle = bo->handle;
    ret = drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &arg);
    if (ret == 0) {
        free(bo);
    }
}

void drm_dove_bo_get(int fd, struct drm_dove_bo *bo)
{
    bo->ref++;
}

void drm_dove_bo_put(int fd, struct drm_dove_bo *bo)
{
    if (bo->ref-- == 1)
        drm_dove_bo_dumb_destroy(fd, bo);
}

int drm_dove_bo_map(int fd, struct drm_dove_bo *bo)
{
    void *map;
    int ret;

    if (bo->type == DRM_DOVE_BO_DUMB) {
        struct drm_mode_map_dumb arg;

        memset(&arg, 0, sizeof(arg));
        arg.handle = bo->handle;

        ret = drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &arg);
        if (ret)
            return ret;

        map = mmap(0, bo->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                   arg.offset);

        if (map == MAP_FAILED)
            return -1;
    } else if (bo->type == DRM_DOVE_BO_SHMEM) {
        struct drm_dove_gem_mmap arg;

        memset(&arg, 0, sizeof(arg));
        arg.handle = bo->handle;
        arg.offset = 0;
        arg.size = bo->size;

        ret = drmIoctl(fd, DRM_IOCTL_DOVE_GEM_MMAP, &arg);
        if (ret)
            return -1;

        map = (void *)(uintptr_t)arg.addr;
    } else {
        errno = EINVAL;
        return -1;
    }

    bo->ptr = map;

    return 0;
}

uint32_t drm_dove_bo_phys(int fd, struct drm_dove_bo *bo)
{
    struct drm_dove_gem_prop arg;
    int ret;

    memset(&arg, 0, sizeof(arg));
    arg.handle = bo->handle;

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

