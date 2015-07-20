/*
 * Copyright (c) 2015, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * set.c -- pool set utilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <time.h>
#include <uuid/uuid.h>

#include "libpmem.h"

#include "util.h"
#include "out.h"
#include "valgrind_internal.h"

extern unsigned long Pagesize;

/*
 * util_poolset_parse -- (internal) parse pool set config file
 *
 * Parses the pool set file and opens or creates all the part files.
 * Returns 1 if the file is a valid pool set config file.  In such case,
 * it opens all the files comprising the pool set, and returns a pointer to
 * newly allocated structure containing the info of all the parts of the pool,
 * and all the replicas.
 * Returns 0 if the file is not a pool set header, and -1 in case of any error.
 */
static int
util_poolset_parse(int fd, struct pool_set **setp, int create)
{
	LOG(3, "fd %d setp %p create %d", fd, setp, create);

	/* XXX */
	return -1;
}

/*
 * util_poolset_create -- (internal) create a new memory pool set
 *
 * On success returns 0 and a pointer to a newly allocated structure
 * containing the info of all the parts of the pool set and replicas.
 */
static int
util_poolset_create(const char *path, size_t poolsize, size_t minsize,
	mode_t mode, struct pool_set **setp)
{
	LOG(3, "path %s poolsize %zu minsize %zu mode %o setp %p",
		path, poolsize, minsize, mode, setp);

	int ret = 0;
	int fd;
	size_t size = 0;

	if (poolsize != 0) {
		/* create a new file */
		fd = util_file_create(path, poolsize, minsize, mode);
		if (fd == -1)
			return -1;

		*setp = Malloc(sizeof (struct pool_set) +
				sizeof (struct pool_set_part));
		if (*setp == NULL) {
			ret = -1;
			goto err;
		}

		struct pool_set *set = *setp;
		/* round down to the nearest page boundary */
		set->part[0].filesize = poolsize;
		set->part[0].path = path;
		set->part[0].fd = fd;
		set->part[0].created = 1;

		set->nparts = 1;
		set->nreplicas = 1;
		set->poolsize = set->part[0].filesize;
		set->zeroed = 1;

		/* do not close the file */
		return 0;
	}

	/* do not check minsize */
	if ((fd = util_file_open(path, &size, 0)) == -1)
		return -1;

	char signature[POOLSET_HDR_SIG_LEN];
	if (read(fd, signature, POOLSET_HDR_SIG_LEN) < 0) {
		ERR("!read %d", fd);
		ret = -1;
		goto err;
	}

	if (strncmp(signature, POOLSET_HDR_SIG, POOLSET_HDR_SIG_LEN)) {
		LOG(4, "not a pool set header");

		if (size < minsize) {
			ERR("size %zu smaller than %zu", size, minsize);
			errno = EINVAL;
			ret = -1;
			goto err;
		}

		*setp = Malloc(sizeof (struct pool_set) +
				sizeof (struct pool_set_part));
		if (*setp == NULL) {
			ret = -1;
			goto err;
		}

		struct pool_set *set = *setp;
		/* round down to the nearest page boundary */
		set->part[0].filesize = size & ~(Pagesize - 1);
		set->part[0].path = path;
		set->part[0].fd = fd;
		set->part[0].created = 0;

		set->nparts = 1;
		set->nreplicas = 1;
		set->poolsize = set->part[0].filesize;
		set->zeroed = 0;

		/* do not close the file */
		return 0;
	}

	LOG(4, "parsing pool set file");
	ret = util_poolset_parse(fd, setp, 1);

err:
	(void) close(fd);
	return ret;
}


/*
 * util_poolset_open -- (internal) open memory pool set
 *
 * On success returns 0 and a pointer to a newly allocated structure
 * containing the info of all the parts of the pool set and replicas.
 */
static int
util_poolset_open(const char *path, size_t minsize, struct pool_set **setp)
{
	LOG(3, "path %s minsize %zu setp %p", path, minsize, setp);

	int ret = 0;
	int fd;
	size_t size = 0;

	/* do not check minsize */
	if ((fd = util_file_open(path, &size, 0)) == -1)
		return -1;

	char signature[POOLSET_HDR_SIG_LEN];
	if (read(fd, signature, POOLSET_HDR_SIG_LEN) < 0) {
		ERR("!read %d", fd);
		ret = -1;
		goto err;
	}

	if (strncmp(signature, POOLSET_HDR_SIG, POOLSET_HDR_SIG_LEN)) {
		LOG(4, "not a pool set header");

		if (size < minsize) {
			ERR("size %zu smaller than %zu", size, minsize);
			errno = EINVAL;
			ret = -1;
			goto err;
		}

		*setp = Malloc(sizeof (struct pool_set) +
				sizeof (struct pool_set_part));
		if (*setp == NULL) {
			ret = -1;
			goto err;
		}

		struct pool_set *set = *setp;
		/* round down to the nearest page boundary */
		set->part[0].filesize = size & ~(Pagesize - 1);
		set->part[0].path = path;
		set->part[0].fd = fd;
		set->part[0].created = 0;

		set->nparts = 1;
		set->nreplicas = 1;
		set->poolsize = set->part[0].filesize;

		/* do not close the file */
		return 0;
	}

	LOG(4, "parsing pool set file");
	ret = util_poolset_parse(fd, setp, 0);

err:
	(void) close(fd);
	return ret;
}

/*
 * util_poolset_free -- ...
 */
void
util_poolset_free(struct pool_set *set)
{
	LOG(3, "set %p", set);
	Free(set);
}

/*
 * util_poolset_close -- unmap and close all the files of the pool set
 *
 * Optionally, it also unlinks the newly created pool set files.
 */
int
util_poolset_close(struct pool_set *set, int del)
{
	LOG(3, "set %p del %d", set, del);

	for (int i = 0; i < set->nparts; i++) {
		util_unmap_part(&set->part[i]);
		if (set->part[i].fd != -1)
			(void) close(set->part[i].fd);
		if (del && set->part[i].created)
			unlink(set->part[i].path);
	}

	util_poolset_free(set);
	return 0;
}

/*
 * util_map_part -- map a part of a pool set
 */
int
util_map_part(struct pool_set_part *part, void *addr, size_t size,
	off_t offset, int flags)
{
	LOG(3, "part %p addr %p size %zu offset %ju flags %d",
		part, addr, size, offset, flags);

	ASSERTeq((uintptr_t)addr % Pagesize, 0);
	ASSERTeq(offset % Pagesize, 0);
	ASSERTeq(size % Pagesize, 0);
	ASSERTeq(part->filesize % Pagesize, 0);

	part->size = size ? size : part->filesize - offset;

	part->addr = mmap(addr, part->size,
		PROT_READ|PROT_WRITE, flags, part->fd, offset);

	if (part->addr == MAP_FAILED) {
		ERR("!mmap: %s", part->path);
		return -1;
	}

	if (addr != NULL && (flags & MAP_FIXED) && part->addr != addr) {
		ERR("!mmap: %s", part->path);
		munmap(addr, size);
		return -1;
	}

	VALGRIND_REGISTER_PMEM_MAPPING(part->addr, part->size);
	VALGRIND_REGISTER_PMEM_FILE(part->fd, part->addr, part->size, offset);

	return 0;
}

/*
 * util_unmap_part -- unmap a part of a pool set
 */
int
util_unmap_part(struct pool_set_part *part)
{
	LOG(3, "part %p", part);

	if (part->addr != NULL && part->size != 0) {
		LOG(3, "munmap: addr %p size %zu", part->addr, part->size);
		if (munmap(part->addr, part->size) != 0) {
			ERR("!munmap: %s", part->path);
		}
		VALGRIND_REMOVE_PMEM_MAPPING(part->addr, part->size);
	}
	return 0;
}

#define	PART(set, i)\
	((set)->part[(i) % (set)->nparts])

#define	HDR(set, i)\
	((struct pool_hdr *)(PART(set, i).addr))

/*
 * util_header_create -- create header of a single pool set file
 */
int
util_header_create(struct pool_set *set, int i, const char *sig,
	uint32_t major, uint32_t compat, uint32_t incompat, uint32_t ro_compat)
{
	LOG(3, "set %p part %d sig %s major %u "
		"compat %#x incompat %#x ro_comapt %#x",
		set, i, sig, major, compat, incompat, ro_compat);

	/* opaque info lives at the beginning of mapped memory pool */
	struct pool_hdr *hdrp = set->part[i].addr;

	/* check if the pool header is all zeros */
	if (!util_is_zeroed(hdrp, sizeof (*hdrp))) {
		ERR("Non-empty file detected");
		errno = EINVAL;
		return -1;
	}

	/* create pool's header */
	strncpy(hdrp->signature, sig, POOL_HDR_SIG_LEN);
	hdrp->major = htole32(major);
	hdrp->compat_features = htole32(compat);
	hdrp->incompat_features = htole32(incompat);
	hdrp->ro_compat_features = htole32(ro_compat);

	memcpy(hdrp->poolset_uuid, set->uuid, POOL_HDR_UUID_LEN);

	memcpy(hdrp->uuid, PART(set, i).uuid, POOL_HDR_UUID_LEN);
	memcpy(hdrp->prev_part_uuid, PART(set, i - 1).uuid, POOL_HDR_UUID_LEN);
	memcpy(hdrp->next_part_uuid, PART(set, i + 1).uuid, POOL_HDR_UUID_LEN);

	/* XXX - replicas */
	memcpy(hdrp->prev_repl_uuid, PART(set, 0).uuid, POOL_HDR_UUID_LEN);
	memcpy(hdrp->next_repl_uuid, PART(set, 0).uuid, POOL_HDR_UUID_LEN);

	hdrp->crtime = htole64((uint64_t)time(NULL));

	if (util_get_arch_flags(&hdrp->arch_flags)) {
		ERR("Reading architecture flags failed\n");
		errno = EINVAL;
		return -1;
	}

	hdrp->arch_flags.alignment_desc =
		htole64(hdrp->arch_flags.alignment_desc);
	hdrp->arch_flags.e_machine =
		htole16(hdrp->arch_flags.e_machine);

	util_checksum(hdrp, sizeof (*hdrp), &hdrp->checksum, 1);

	/* store pool's header */
	pmem_msync(hdrp, sizeof (*hdrp));

	return 0;
}

/*
 * util_header_check -- validate header of a single pool set file
 */
int
util_header_check(struct pool_set *set, int i, const char *sig,
	uint32_t major, uint32_t compat, uint32_t incompat, uint32_t ro_compat)
{
	LOG(3, "set %p part %d sig %s major %u "
		"compat %#x incompat %#x ro_comapt %#x",
		set, i, sig, major, compat, incompat, ro_compat);

	/* opaque info lives at the beginning of mapped memory pool */
	struct pool_hdr *hdrp = set->part[i].addr;
	struct pool_hdr hdr;

	memcpy(&hdr, hdrp, sizeof (hdr));

	if (!util_convert_hdr(&hdr)) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * valid header found
	 */
	if (strncmp(hdr.signature, sig, POOL_HDR_SIG_LEN)) {
		ERR("wrong pool type: \"%s\"", hdr.signature);
		errno = EINVAL;
		return -1;
	}

	if (hdr.major != major) {
		ERR("pool version %d (library expects %d)",
			hdr.major, major);
		errno = EINVAL;
		return -1;
	}

	if (util_check_arch_flags(&hdr.arch_flags)) {
		ERR("wrong architecture flags");
		errno = EINVAL;
		return -1;
	}

	/* check pool set linkage */
	if (memcmp(HDR(set, i - 1)->uuid, hdr.prev_part_uuid,
						POOL_HDR_UUID_LEN) ||
	    memcmp(HDR(set, i + 1)->uuid, hdr.next_part_uuid,
						POOL_HDR_UUID_LEN)) {
		ERR("wrong UUID");
		errno = EINVAL;
		return -1;
	}

	/* XXX - check replicas linkage */
	if (memcmp(HDR(set, 0)->uuid, hdr.prev_repl_uuid, POOL_HDR_UUID_LEN) ||
	    memcmp(HDR(set, 0)->uuid, hdr.next_repl_uuid, POOL_HDR_UUID_LEN)) {
		ERR("wrong UUID");
		errno = EINVAL;
		return -1;
	}

	int retval = util_feature_check(&hdr, incompat, ro_compat, compat);
	if (retval < 0)
		return -1;
	else if (retval == 0)
		set->part[i].rdonly = 1;

	return 0;
}

/*
 * util_pool_create -- create a new memory pool (set or a single file)
 *
 * On success returns 0 and a pointer to a newly allocated structure
 * containing the info of all the parts of the pool set and replicas.
 */
void *
util_pool_create(const char *path, size_t poolsize, size_t minsize, mode_t mode,
	struct pool_set **setp, size_t hdrsize, const char *sig,
	uint32_t major, uint32_t compat, uint32_t incompat, uint32_t ro_compat)
{
	LOG(3, "path %s poolsize %zu minsize %zu mode %o "
		"setp %p hdrsize %zu sig %s major %u "
		"compat %#x incompat %#x ro_comapt %#x",
		path, poolsize, minsize, mode, setp, hdrsize,
		sig, major, compat, incompat, ro_compat);

	int oerrno;
	int flags = MAP_SHARED;

	int ret = util_poolset_create(path, poolsize, minsize, mode, setp);
	if (ret < 0) {
		LOG(2, "cannot open pool set");
		return NULL;
	}

	struct pool_set *set = *setp;

	/* generate pool set UUID */
	uuid_generate(set->uuid);

	/* generate UUID's for newly created files */
	for (int i = 0; i < set->nparts; i++)
		uuid_generate(set->part[i].uuid);

	/* determine a hint address for mmap() */
	void *addr = util_map_hint(set->poolsize); /* XXX - randomize? */
	if (addr == NULL) {
		ERR("cannot find a contiguous region of given size");
		goto err2;
	}

	/* map the first part and reserve space for remaining parts */
	if (util_map_part(&set->part[0], addr, set->poolsize, 0, flags) != 0) {
		LOG(2, "pool mapping failed - part #0");
		goto err2;
	}

	VALGRIND_REGISTER_PMEM_MAPPING(set->part[0].addr, set->poolsize);
	VALGRIND_REGISTER_PMEM_FILE(set->part[0].fd,
				set->part[0].addr, set->poolsize, 0);

	void *pop = set->part[0].addr;
	addr = set->part[0].addr;
	size_t mapsize = set->part[0].filesize;
	addr += set->part[0].filesize;

	(void) close(set->part[0].fd);
	set->part[0].fd = -1;

	/* map all the remaining headers - don't care about the address */
	for (int i = 1; i < set->nparts; i++) {
		if (util_map_part(&set->part[i], NULL,
				hdrsize, 0, flags) != 0) {
			LOG(2, "header mapping failed - part #%d", i);
			goto err;
		}
	}

	set->is_pmem = pmem_is_pmem(set->part[0].addr, set->part[0].filesize);

	/* create headers, set UUID's */
	for (int i = 0; i < set->nparts; i++) {
		if (util_header_create(set, i, sig, major,
				compat, incompat, ro_compat) != 0) {
			LOG(2, "header creation failed - part #%d", i);
			goto err;
		}
	}

	/*
	 * unmap headers;
	 * map the remaining parts of the usable pool space (4K-aligned)
	 */
	for (int i = 1; i < set->nparts; i++) {
		/* unmap header */
		if (util_unmap_part(&set->part[i]) != 0) {
			LOG(2, "header unmapping failed - part #%d", i);
		}

		/* map data part */
		if (util_map_part(&set->part[i], addr, 0, hdrsize,
				flags | MAP_FIXED) != 0) {
			LOG(2, "heap mapping failed - part #%d", i);
			goto err;
		}

		mapsize += set->part[i].size;
		set->is_pmem &= pmem_is_pmem(addr, set->part[i].size);
		addr += set->part[i].size;

		(void) close(set->part[i].fd);
		set->part[i].fd = -1;
	}

	ASSERTeq(mapsize, set->poolsize);

	LOG(3, "pop %p", pop);
	return pop;

err:
	LOG(4, "error clean up");
	oerrno = errno;
	VALGRIND_REMOVE_PMEM_MAPPING(pop, set->poolsize);
	util_unmap(pop, set->poolsize);
	errno = oerrno;

err2:
	LOG(4, "close pool set files");
	oerrno = errno;
	util_poolset_close(set, 1);
	errno = oerrno;
	return NULL;
}

/*
 * util_pool_open -- open a memory pool (set or a single file)
 *
 * This routine does all the work, but takes a rdonly flag so internal
 * calls can map a read-only pool if required.
 */
void *
util_pool_open(const char *path, int rdonly, size_t minsize,
	struct pool_set **setp, size_t hdrsize, const char *sig,
	uint32_t major, uint32_t compat, uint32_t incompat, uint32_t ro_compat)
{
	LOG(3, "path %s rdonly %d minsize %zu "
		"setp %p hdrsize %zu sig %s major %u "
		"compat %#x incompat %#x ro_comapt %#x",
		path, rdonly, minsize, setp, hdrsize,
		sig, major, compat, incompat, ro_compat);

	int oerrno;
	int flags = rdonly ? MAP_PRIVATE|MAP_NORESERVE : MAP_SHARED;

	int ret = util_poolset_open(path, minsize, setp);
	if (ret < 0) {
		LOG(2, "cannot open pool set");
		return NULL;
	}

	struct pool_set *set = *setp;

	/* determine a hint address for mmap() */
	void *addr = util_map_hint(set->poolsize); /* XXX - randomize */
	if (addr == NULL) {
		ERR("cannot find a contiguous region of given size");
		goto err2;
	}

	/* map the first part and reserve space for remaining parts */
	if (util_map_part(&set->part[0], addr, set->poolsize, 0, flags) != 0) {
		LOG(2, "pool mapping failed - part #0");
		goto err2;
	}

	VALGRIND_REGISTER_PMEM_MAPPING(set->part[0].addr, set->poolsize);
	VALGRIND_REGISTER_PMEM_FILE(set->part[0].fd,
				set->part[0].addr, set->poolsize, 0);

	void *pop = set->part[0].addr;
	addr = set->part[0].addr;
	size_t mapsize = set->part[0].filesize;
	addr += set->part[0].filesize;

	(void) close(set->part[0].fd);
	set->part[0].fd = -1;

	/* map all the remaining headers - don't care about the address */
	for (int i = 1; i < set->nparts; i++) {
		if (util_map_part(&set->part[i], NULL,
				hdrsize, 0, flags) != 0) {
			LOG(2, "header mapping failed - part #%d", i);
			goto err;
		}
	}

	set->is_pmem = pmem_is_pmem(set->part[0].addr, set->part[0].filesize);
	rdonly |= set->part[0].rdonly;

	/* check headers, check UUID's */
	for (int i = 0; i < set->nparts; i++) {
		if ((util_header_check(set, i,  sig, major,
				compat, incompat, ro_compat)) != 0) {
			LOG(2, "header check failed - part #%d", i);
			goto err;
		}
	}

	/*
	 * unmap headers;
	 * map the remaining parts of the heap (4K-aligned)
	 */
	for (int i = 1; i < set->nparts; i++) {
		/* unmap header */
		if (util_unmap_part(&set->part[i]) != 0) {
			LOG(2, "header unmapping failed - part #%d", i);
		}

		/* map data part */
		if (util_map_part(&set->part[i], addr, 0, hdrsize,
				flags | MAP_FIXED) != 0) {
			LOG(2, "heap mapping failed - part #%d", i);
			goto err;
		}

		mapsize += set->part[i].size;
		set->is_pmem &= pmem_is_pmem(addr, set->part[i].size);
		rdonly |= set->part[i].rdonly;
		addr += set->part[i].size;

		(void) close(set->part[i].fd);
		set->part[i].fd = -1;
	}

	ASSERTeq(mapsize, set->poolsize);

	LOG(3, "pop %p", pop);
	return pop;

err:
	LOG(4, "error clean up");
	oerrno = errno;
	VALGRIND_REMOVE_PMEM_MAPPING(pop, set->poolsize);
	util_unmap(pop, set->poolsize);
	errno = oerrno;

err2:
	LOG(4, "close pool set files");
	oerrno = errno;
	util_poolset_close(set, 0);
	errno = oerrno;
	return NULL;
}
