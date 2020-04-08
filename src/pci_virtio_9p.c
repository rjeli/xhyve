#include <sys/cdefs.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#include <lib9p.h>
#include <backend/fs.h>
#pragma clang diagnostic pop

#include <xhyve/xhyve.h>
#include <xhyve/pci_emul.h>
#include <xhyve/virtio.h>

#define VT9P_RINGSZ 64

struct pci_vt9p_config {
    uint16_t tag_len;
    char tag[];
} __attribute__((packed));

// #define DPRINTF(...) fprintf(stderr, __VA_ARGS__)
#define DPRINTF(...) ((void) 0)

struct pci_vt9p_softc;

struct pci_vt9p_request {
    struct iovec *vsr_iov;
    size_t vsr_niov;
    size_t vsr_respidx;
    size_t vsr_iolen;
};

struct pci_vt9p_softc {
    struct virtio_softc vsc_vs;
    struct vqueue_info vsc_vq;
    pthread_mutex_t vsc_mtx;
    uint64_t vsc_cfg;
    uint64_t vsc_features;
    char *vsc_rootpath;
    struct pci_vt9p_config *vsc_config;
    struct l9p_backend *vsc_fs_backend;
    struct l9p_server *vsc_server;
    struct l9p_connection *vsc_conn;
};

static void 
pci_vt9p_reset(void *vsc)
{
    struct pci_vt9p_softc *sc = vsc;
    DPRINTF("vt9p: reset\n");
    vi_reset_dev(&sc->vsc_vs);
}

static void 
pci_vt9p_notify(void *vsc, struct vqueue_info *vq)
{
    struct pci_vt9p_softc *sc = vsc;
    struct pci_vt9p_request preq;
    struct iovec iov[8];
    uint16_t idx, flags[8];
    int i, n;

    while (vq_has_descs(vq)) {
        n = vq_getchain(vq, &idx, iov, 8, flags);
        preq.vsr_iov = iov;
        preq.vsr_niov = (size_t) n;
        preq.vsr_respidx = 0;
        for (i = 0; i < n; i++) {
            if (flags[i] & VRING_DESC_F_WRITE) break;
            preq.vsr_respidx++;
        }
        l9p_connection_recv(sc->vsc_conn, iov, preq.vsr_respidx, &preq, 1);
        vq_relchain(vq, idx, (uint32_t) preq.vsr_iolen);
    }
    vq_endchains(vq, 1);
}

static int 
pci_vt9p_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
    struct pci_vt9p_softc *sc = vsc;
    void *p = (uint8_t *) sc->vsc_config + offset;
    memcpy(retval, p, size);
    return 0;
}

static void 
pci_vt9p_neg_features(void *vsc, uint64_t negotiated_features)
{
    struct pci_vt9p_softc *sc = vsc;
    sc->vsc_features = negotiated_features;
}

static struct virtio_consts vt9p_vi_consts = {
    .vc_name = "vt9p",
    .vc_nvq = 1,
    .vc_cfgsize = 0,
    .vc_reset = pci_vt9p_reset,
    .vc_qnotify = pci_vt9p_notify,
    .vc_cfgread = pci_vt9p_cfgread,
    .vc_cfgwrite = NULL,
    .vc_apply_features = pci_vt9p_neg_features,
    .vc_hv_caps = (1 << 0),
};

static int
pci_vt9p_get_buffer(struct l9p_request *req, struct iovec *iov,
    size_t *niov, void *arg __unused)
{
    struct pci_vt9p_request *preq = req->lr_aux;
    size_t n = preq->vsr_niov - preq->vsr_respidx;
    DPRINTF("pci_vt9p_get_buffer\n");
    memcpy(iov, preq->vsr_iov + preq->vsr_respidx, 
        n*sizeof(struct iovec));
    *niov = n;
    return 0;
}

static int
pci_vt9p_send(struct l9p_request *req, const struct iovec *iov __unused,
    const size_t niov __unused, const size_t iolen, void *arg __unused)
{
    struct pci_vt9p_request *preq = req->lr_aux;
    DPRINTF("pci_vt9p_send\n");
    preq->vsr_iolen = iolen;
    return 0;
}

static void
pci_vt9p_drop(struct l9p_request *req __unused, 
    const struct iovec *iov __unused, size_t niov __unused, void *arg __unused)
{
    printf("pci_vt9p_drop??\n");
}

static int
pci_vt9p_init(struct pci_devinst *pi, char *opts)
{
    struct pci_vt9p_softc *sc;
    char *opt, *sharename = NULL, *rootpath = NULL;
    int rootfd;
    uint16_t i;

	DPRINTF("init virtio-9p\n");

    if (!opts) {
        DPRINTF("virtio-9p: share name & path required\n");
        return 1;
    }

    sc = calloc(1, sizeof(struct pci_vt9p_softc));
    sc->vsc_config = calloc(1, sizeof(struct pci_vt9p_config) + 128);

    while ((opt = strsep(&opts, ","))) {
        if (!sharename) {
            sharename = strsep(&opt, "=");
            rootpath = strdup(opt);
            continue;
        }
    }

    DPRINTF("sharename: %s\n", sharename);
    DPRINTF("rootpath: %s\n", rootpath);

    sc->vsc_config->tag_len = (uint16_t) strlen(sharename);
    strncpy(sc->vsc_config->tag, sharename, strlen(sharename));

    DPRINTF("tag_len: %d\n", sc->vsc_config->tag_len);
    DPRINTF("strlen(sharename): %zu\n", strlen(sharename));

    rootfd = open(rootpath, O_DIRECTORY);
    if (rootfd < 0) {
        DPRINTF("error opening rootfd\n");
        return 1;
    }

    if (l9p_backend_fs_init(&sc->vsc_fs_backend, rootfd, false)) {
        DPRINTF("error backend_fs_init\n");
        return 1;
    }

    if (l9p_server_init(&sc->vsc_server, sc->vsc_fs_backend)) {
        DPRINTF("error server_init\n");
        return 1;
    }

    if (l9p_connection_init(sc->vsc_server, &sc->vsc_conn)) {
        DPRINTF("error connection_init\n");
        return 1;
    }

    sc->vsc_conn->lc_lt.lt_aux = NULL;
    sc->vsc_conn->lc_lt.lt_get_response_buffer = pci_vt9p_get_buffer;
    sc->vsc_conn->lc_lt.lt_send_response = pci_vt9p_send;
    sc->vsc_conn->lc_lt.lt_drop_response = pci_vt9p_drop;

    vi_softc_linkup(&sc->vsc_vs, &vt9p_vi_consts, sc, pi, &sc->vsc_vq);
    sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
    sc->vsc_vq.vq_qsize = VT9P_RINGSZ;

    pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_9P);
    pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
    pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_STORAGE);
    pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_TYPE_9P);
    pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);

    if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix())) {
        DPRINTF("failed vi_intr_init\n");
        return 1;
    }
    vi_set_io_bar(&sc->vsc_vs, 0);

	return 0;
}

static struct pci_devemu pci_dev_9p = {
	.pe_emu = "virtio-9p",
	.pe_init = pci_vt9p_init,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
};
PCI_EMUL_SET(pci_dev_9p);
