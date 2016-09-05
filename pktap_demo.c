/*
 * Copyright (c) 2013 Masaya Yamamoto <pandax381@gmail.com>
 *
 * This software is released under the MIT License.
 *
 * Please refer http://opensource.org/licenses/mit-license.php for detail.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <net/if.h>
#include <net/bpf.h>
//#include <net/pktap.h>
#include "pktap.h"

/* copy from http://opensource.apple.com/source/xnu/xnu-3248.60.10/bsd/net/bpf.h */
#ifdef PRIVATE
#define DLT_PKTAP DLT_USER2
#define BIOCGWANTPKTAP _IOR('B', 127, u_int)
#define BIOCSWANTPKTAP _IOWR('B', 127, u_int)
#endif

#define BPF_DEVICE_NUM 4

struct bpf_device {
    int fd;
    int buffer_size;
    char *buffer;
};

static char *
pktap_create (char *dst, size_t size);
static void
pktap_destroy (const char *ptname);
static int
pktap_set_if (const char *ptname, char *ifaces[], size_t num);
static void
pktap_debug_print (struct pktap_header *hdr);
struct bpf_device *
bpf_device_open (const char *name);
static void
bpf_device_close (struct bpf_device *device);
static void
hexdump (FILE *fp, void *data, size_t size);

volatile sig_atomic_t terminate = 0;

void
signal_handler (int signo) {
    (void)signo;
    terminate = 1;
}

int
main (int argc, char *argv[]) {
    struct sigaction sa;
    char ptname[PKTAP_IFXNAMESIZE];
    struct bpf_device *device;
    struct timeval base, now;
    struct pollfd pfd;
    ssize_t len;
    struct bpf_hdr *bh;
    struct pktap_header *pth;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);

    if (!pktap_create(ptname, sizeof(ptname))) {
        return -1;
    }
    if (argc > 1) {
        if (pktap_set_if(ptname, argv + 1, argc - 1) == -1) {
            pktap_destroy(ptname);
            return -1;
        }
    }
    device = bpf_device_open(ptname);
    if (!device) {
        pktap_destroy(ptname);
        return -1;
    }
    gettimeofday(&base, NULL);
    pfd.fd = device->fd;
    pfd.events = POLLIN;
    while (!terminate) {
        gettimeofday(&now, NULL);
        if (now.tv_sec - base.tv_sec > 10) {
            break;
        }
        if (poll(&pfd, 1, 1000) <= 0) {
            continue;
        }
        len = read(device->fd, device->buffer, device->buffer_size);
        if (len <= 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        bh = (struct bpf_hdr *)device->buffer;
        while ((caddr_t)bh < (caddr_t)device->buffer + len) {
            if (bh->bh_caplen > sizeof(struct pktap_header)) {
                pth = (struct pktap_header *)((caddr_t)bh + bh->bh_hdrlen);
                pktap_debug_print(pth);
                hexdump(stderr, pth + 1, bh->bh_caplen - pth->pth_length);
            }
            bh = (struct bpf_hdr *)((caddr_t)bh + BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen));
        }
    }
    pktap_destroy(ptname);
    return 0;
}

static char *
pktap_create (char *dst, size_t size) {
    int soc;
    struct ifreq ifr;

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        perror("socket");
        return NULL;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, PKTAP_IFNAME, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCIFCREATE, &ifr) == -1) {
        perror("ioctl");
        close(soc);
        return NULL;
    }
    strncpy(dst, ifr.ifr_name, size - 1);
    close(soc);
    return dst;
}

static void
pktap_destroy (const char *ptname) {
    int soc;
    struct ifreq ifr;

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        perror("socket");
        return;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ptname, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCIFDESTROY, &ifr) == -1) {
        perror("ioctl");
    }
    close(soc);
}

static int
pktap_set_if (const char *ptname, char *ifaces[], size_t num) {
    int soc;
    struct pktap_filter entry[PKTAP_MAX_FILTERS];
    size_t index;
    struct ifdrv ifdr;

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        perror("socket");
        return -1;
    }
    memset(&entry, 0, sizeof(entry));
    for (index = 0; index < num; index++) {
        entry[index].filter_op = PKTAP_FILTER_OP_PASS;
        entry[index].filter_param = PKTAP_FILTER_PARAM_IF_NAME;
        strncpy(entry[index].filter_param_if_name, ifaces[index], PKTAP_IFXNAMESIZE - 1);
    }
    memset(&ifdr, 0, sizeof(struct ifdrv));
    snprintf(ifdr.ifd_name, sizeof(ifdr.ifd_name), "%s", ptname);
    ifdr.ifd_cmd = PKTP_CMD_FILTER_SET;
    ifdr.ifd_len = sizeof(entry);
    ifdr.ifd_data = entry;
    if (ioctl(soc, SIOCSDRVSPEC, &ifdr) == -1) {
        perror("ioctl");
        close(soc);
        return -1;
    }
    close(soc);
    return 0;
}

static void
pktap_debug_print (struct pktap_header *hdr) {
    fprintf(stderr, "### pktap_debug_print ###\n");
    fprintf(stderr, "pth_length: %u\n", hdr->pth_length);
    fprintf(stderr, "pth_type_next: %u\n", hdr->pth_type_next);
    fprintf(stderr, "pth_dlt: %u\n", hdr->pth_dlt);
    fprintf(stderr, "pth_ifname: %s\n", hdr->pth_ifname);
    fprintf(stderr, "pth_flags: %u\n", hdr->pth_flags);
    fprintf(stderr, "pth_protocol_family: %u\n", hdr->pth_protocol_family);
    fprintf(stderr, "pth_frame_pre_length: %u\n", hdr->pth_frame_pre_length);
    fprintf(stderr, "pth_frame_post_length: %u\n", hdr->pth_frame_post_length);
    fprintf(stderr, "pth_pid: %d\n", hdr->pth_pid);
    fprintf(stderr, "pth_comm: %s\n", hdr->pth_comm);
    fprintf(stderr, "pth_svc: %u\n", hdr->pth_svc);
    fprintf(stderr, "pth_iftype: %u\n", hdr->pth_iftype);
    fprintf(stderr, "pth_ifunit: %u\n", hdr->pth_ifunit);
    fprintf(stderr, "pth_epid: %d\n", hdr->pth_epid);
    fprintf(stderr, "pth_ecomm: %s\n", hdr->pth_ecomm);
}

struct bpf_device *
bpf_device_open (const char *name) {
    struct bpf_device *device;
    int index, enable = 1;
    char dev[16];
    struct ifreq ifr;

    if ((device = malloc(sizeof(struct bpf_device))) == NULL) {
        perror("malloc");
        goto ERROR;
    }
    device->fd = -1;
    device->buffer_size = 0;
    device->buffer = NULL;
    for (index = 0; index < BPF_DEVICE_NUM; index++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", index);
        if ((device->fd = open(dev, O_RDWR, 0)) != -1) {
            break;
        }
    }
    if (device->fd == -1) {
        perror("open");
        goto ERROR;
    }
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(device->fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl [BIOCSETIF]");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCGBLEN, &device->buffer_size) == -1) {
        perror("ioctl [BIOCGBLEN]");
        goto ERROR;
    }
    if ((device->buffer = malloc(device->buffer_size)) == NULL) {
        perror("malloc");
        goto ERROR;
    }
/*
    if (ioctl(device->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl [BIOCPROMISC]");
        goto ERROR;
    }
*/
    if (ioctl(device->fd, BIOCSSEESENT, &enable) == -1) {
        perror("ioctl [BIOCSSEESENT]");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl [BIOCIMMEDIATE]");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCSHDRCMPLT, &enable) == -1) {
        perror("ioctl [BIOCSHDRCMPLT]");
        goto ERROR;
    }
#ifdef BIOCSWANTPKTAP
    if (ioctl(device->fd, BIOCSWANTPKTAP, &enable) == -1) {
        perror("ioctl [BIOCSWANTPKTAP]");
        goto ERROR;
    }
#endif
#ifdef DLT_PKTAP
    int dlt = DLT_PKTAP;
    if (ioctl(device->fd, BIOCSDLT, &dlt) == -1) {
        perror("ioctl [BIOCSDLT]");
        goto ERROR;
    }
#endif
    return device;
ERROR:
    if (device) {
        bpf_device_close(device);
    }
    return NULL;
}

static void
bpf_device_close (struct bpf_device *device) {
    if (device->fd != -1) {
        close(device->fd);
    }
    free(device->buffer);
    free(device);
}

static void
hexdump (FILE *fp, void *data, size_t size) {
    unsigned char *src;
    int offset, index;

    src = (unsigned char *)data;
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    for(offset = 0; offset < (int)size; offset += 16) {
        fprintf(fp, "| %04x | ", offset);
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                fprintf(fp, "%02x ", 0xff & src[offset + index]);
            } else {
                fprintf(fp, "   ");
            }
        }
        fprintf(fp, "| ");
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                if(isascii(src[offset + index]) && isprint(src[offset + index])) {
                    fprintf(fp, "%c", src[offset + index]);
                } else {
                    fprintf(fp, ".");
                }
            } else {
                fprintf(fp, " ");
            }
        }
        fprintf(fp, " |\n");
    }
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
}
