#ifndef DRM_ARMADA_GEM_H
#define DRM_ARMADA_GEM_H

enum drm_armada_bo_type {
	DRM_ARMADA_BO_DUMB,
	DRM_ARMADA_BO_LINEAR,
	DRM_ARMADA_BO_SHMEM
};

struct drm_armada_bufmgr;

struct drm_armada_bo {
	uint32_t ref;
	uint32_t handle;
	uint32_t size;
	uint32_t pitch;
	void *ptr;
	enum drm_armada_bo_type type;
};

int drm_armada_init(int fd, struct drm_armada_bufmgr **mgr);
void drm_armada_fini(struct drm_armada_bufmgr *);

struct drm_armada_bo *drm_armada_bo_create(struct drm_armada_bufmgr *,
    unsigned w, unsigned h, unsigned bpp);
struct drm_armada_bo *drm_armada_bo_dumb_create(struct drm_armada_bufmgr *,
    unsigned w, unsigned h, unsigned bpp);

/* Create a BO from a global name */
struct drm_armada_bo *drm_armada_bo_create_from_name(struct drm_armada_bufmgr *,
    uint32_t name);

/* Create a global name from a BO */
int drm_armada_bo_flink(struct drm_armada_bo *bo, uint32_t *name);

/* Create a dmabuf fd for the BO */
int drm_armada_bo_to_fd(struct drm_armada_bo *bo, int *fd);

int drm_armada_bo_map(struct drm_armada_bo *bo);
void drm_armada_bo_get(struct drm_armada_bo *bo);
void drm_armada_bo_put(struct drm_armada_bo *bo);
int drm_armada_bo_subdata(struct drm_armada_bo *bo, unsigned long offset,
    unsigned long size, const void *data);

#endif
