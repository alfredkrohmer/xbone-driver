#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "ieee802_11_defs.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

static int expectedId;

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

struct nlapp {
    char *interface;
    u8 mac[6];

    int sk;

    uint16_t freq;
    uint16_t seq_cnt;
};


int nl80211_init(struct nlapp *app) {
    int ret;

    int sk = socket(AF_PACKET, SOCK_RAW, 0);
    if(sk < 0)
        return sk;

    int if_idx = if_nametoindex(app->interface);

    /* get MAC address of interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, app->interface);
    if((ret = ioctl(sk, SIOCGIFHWADDR, &ifr) < 0))
        return ret;
    memcpy(app->mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

    /* bind socket to interface */
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = PF_PACKET;
    sa.sll_ifindex  = if_nametoindex(app->interface);
    sa.sll_protocol = htons(ETH_P_ALL);
    if(bind(sk, (struct sockaddr*) &sa, sizeof(sa)) != 0) {
        perror("bind");
        return -1;
    }

    app->sk = sk;

    return 0;
}

const uint8_t nl80211_assoc_resp_ie[] = {
    0x00, 0x50, 0xf2, 0x11, 0x02, 0x10, 0x00, 0xa1,
    0x28, 0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

struct nl80211_radiotap_hdr {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
} STRUCT_PACKED;

enum {
    CCK  = 0x0020,
    OFDM = 0x0040,
    GHZ2 = 0x0080,
    GHZ5 = 0x0100
};
struct nl80211_radiotap_channel {
    uint16_t freq;
    uint16_t flags;
} STRUCT_PACKED;
#define NL802211_RADIOTAP_CHANNEL_PRESENT (1 << 3)

struct nl80211_radiotap_rate {
    uint8_t rate;
} STRUCT_PACKED;
#define NL802211_RADIOTAP_RATE_PRESENT (1 << 2)

struct nl80211_radiotap_flags {
    uint8_t flags;
} STRUCT_PACKED;
#define NL802211_RADIOTAP_FLAGS_PRESENT (1 << 1)

struct nl80211_radiotap_timestamp {
    uint64_t timestamp;
} STRUCT_PACKED;
#define NL802211_RADIOTAP_TIMESTAMP_PRESENT (1 << 0)

struct nl80211_ie_hdr {
    uint8_t number;
    uint8_t len;
} STRUCT_PACKED;

static inline uint64_t get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1e6 + tv.tv_usec;
}

int nl80211_write_radiotap_header(struct nlapp *app, void *buf) {
    struct nl80211_radiotap_hdr *rt = buf;
    rt->it_version = 0;
    rt->it_pad     = 0; 

    struct nl80211_radiotap_timestamp *ts = (buf += sizeof(*rt));
    ts->timestamp = get_timestamp();

    struct nl80211_radiotap_flags *flags = (buf += sizeof(*ts));
    flags->flags = 0;

    struct nl80211_radiotap_rate *rate = (buf += sizeof(*flags));
    rate->rate = 6000 / 500;

    struct nl80211_radiotap_channel *channel = (buf += sizeof(*rate));
    channel->freq = app->freq;
    channel->flags = OFDM | (app->freq < 4000 ? GHZ2 : GHZ5);

    rt->it_present = NL802211_RADIOTAP_TIMESTAMP_PRESENT |
                     NL802211_RADIOTAP_FLAGS_PRESENT |
                     NL802211_RADIOTAP_RATE_PRESENT |
                     NL802211_RADIOTAP_CHANNEL_PRESENT;
    rt->it_len     = buf - (void*) rt + sizeof(*channel);

    return rt->it_len;
}

static inline int nl80211_write_ie(void *buf, uint8_t number, uint8_t len, void *data) {
    struct nl80211_ie_hdr *hdr = buf;
    hdr->number = number;
    hdr->len    = len;
    if(len > 0)
        memcpy((buf + sizeof(*hdr)), data, len);
    return len + sizeof(*hdr);
}

static const uint8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static inline int nl80211_write_header(struct nlapp *app, void *buf, uint16_t fc, uint16_t du, uint8_t *mac) {
    struct ieee80211_mgmt *hdr = buf;
    hdr->frame_control = fc;
    hdr->duration      = du;
    memcpy(hdr->da,    mac,      6);
    memcpy(hdr->sa,    app->mac, 6);
    memcpy(hdr->bssid, app->mac, 6);
    hdr->seq_ctrl = app->seq_cnt++ << 4;
    return sizeof(struct ieee80211_hdr); 
}

int nl80211_write_beacon(struct nlapp *app, void *buf) {
    struct ieee80211_mgmt *hdr = buf;

    buf += nl80211_write_header(app, buf, 0x0080, 0x0000, (void*) broadcast_mac);

    uint64_t ts = get_timestamp();
    memcpy(hdr->u.beacon.timestamp, &ts, 8);
    hdr->u.beacon.beacon_int = 0x0064; /* 102.4 ms */
    hdr->u.beacon.capab_info = 0xc631;
    buf += sizeof(hdr->u.beacon);

    buf += nl80211_write_ie(buf,    0, 0, NULL);
    buf += nl80211_write_ie(buf, 0xdd,
            sizeof(nl80211_assoc_resp_ie), (void*) nl80211_assoc_resp_ie);

    return buf - (void*) hdr;
}

int write_qos_null_data(struct nlapp *app, void *buf, uint8_t *mac) {
    struct ieee80211_mgmt *hdr = buf;

    buf += nl80211_write_header(app, buf, 0x02c8, 0x0064, mac);
    *((uint16_t*) (buf += 2)) = 0; /* QoS no flags */

    return buf - (void*) hdr;
}

int write_probe_resp(struct nlapp *app, void *buf, uint8_t *mac) {
    struct ieee80211_mgmt *hdr = buf;

    buf += nl80211_write_header(app, buf, 0x0050, 0x002c, mac);

    uint64_t ts = get_timestamp();
    memcpy(hdr->u.beacon.timestamp, &ts, 8);
    hdr->u.beacon.beacon_int = 0x0064; /* 102.4 ms */
    hdr->u.beacon.capab_info = 0xc631;
    buf += sizeof(hdr->u.beacon);

    buf += nl80211_write_ie(buf,    0, 0, NULL);
    buf += nl80211_write_ie(buf, 0xdd,
            sizeof(nl80211_assoc_resp_ie), (void*) nl80211_assoc_resp_ie);

    return buf - (void*) hdr;
}

void* nl80211_send_beacons(void *papp) {
    struct nlapp *app = papp;
    uint8_t buf[1024];
    void *ptr;

    uint64_t ts = get_timestamp();

    while(1) {
        ptr = buf;

        ptr += nl80211_write_radiotap_header(app, ptr);
        ptr += nl80211_write_beacon(app, ptr);
        //hexDump("beacon", buf, ptr - (void*) buf);

        write(app->sk, buf, ptr - (void*) buf);

        /* sleep for beacon interval */
        usleep(102400 - (get_timestamp() - ts));
        ts = get_timestamp();
    }

    return NULL;
}

static inline int write_ack(struct nlapp *app, void *buf, uint8_t *mac) {
    struct ieee80211_hdr *hdr = buf;
    hdr->frame_control = 0x00d4;
    hdr->duration_id   = 0x0074;
    memcpy(hdr->addr1, mac, 6);
    return 10;
}

static inline int nl80211_send_frame(struct nlapp *app, void *buf, size_t len) {
    if(unlikely(write(app->sk, buf, len) < 0)) {
        perror("write");
        return -1;
    }

    return 0;
}

#define RADIOTAP_SIZE 22
#define ASSOC_RESP_SIZE 38

static inline int write_assoc_resp(struct nlapp *app, void *buf, uint8_t *mac) {
    struct ieee80211_mgmt *hdr = buf;

    buf += nl80211_write_header(app, buf, 0x0010, 0x002c, mac); 

    hdr->u.assoc_resp.capab_info  = 0x0000;
    hdr->u.assoc_resp.status_code = 0x0110;
    hdr->u.assoc_resp.aid         = 0x0f00;
    buf += sizeof(hdr->u.assoc_resp);

    buf += nl80211_write_ie(buf, 0, 0, NULL);
    buf += nl80211_write_ie(buf, 0, 0, NULL);
    buf += nl80211_write_ie(buf, 0, 0, NULL);
    buf += nl80211_write_ie(buf, 0, 0, NULL);

    return buf - (void*) hdr;
}

struct controller_input {
    uint16_t __const1;
    uint8_t cnt;
    uint8_t __const2;
    uint16_t button_map;
    uint16_t lt, rt, ls_h, ls_v, rs_h, rs_v;
} STRUCT_PACKED;

enum {
    BUTTON_RS = 1 << 15,
    BUTTON_LS = 1 << 14,
    BUTTON_RB = 1 << 13,
    BUTTON_LB = 1 << 12,
    BUTTON_DR = 1 << 11,
    BUTTON_DL = 1 << 10,
    BUTTON_DD = 1 << 9,
    BUTTON_DU = 1 << 8,

    BUTTON_Y  = 1 << 7,
    BUTTON_X  = 1 << 6,
    BUTTON_B  = 1 << 5,
    BUTTON_A  = 1 << 4,
    BUTTON_L  = 1 << 3,
    BUTTON_R  = 1 << 2,
};

int nl80211_run(struct nlapp *app) {
    pthread_t tid;
    pthread_create(&tid, NULL, nl80211_send_beacons, app);

    uint8_t buf[1024];
    uint8_t send_buf[1024];
    int rd;
    void *ptr;
    void *send_ptr;

    while((rd = read(app->sk, buf, 1024)) > 0) {
        ptr = buf;
        send_ptr = send_buf;

        /* read and skip radiotap header */
        if(unlikely(rd < sizeof(struct nl80211_radiotap_hdr)))
            continue;
        struct nl80211_radiotap_hdr *rt_hdr = ptr;
        if(unlikely(rd < rt_hdr->it_len))
            continue;
        ptr += rt_hdr->it_len;
        rd  -= rt_hdr->it_len;

        /* read 802.11 MAC header */
        if(unlikely(rd < sizeof(struct ieee80211_hdr)))
            continue;
        struct ieee80211_mgmt *hdr = ptr;

        if(unlikely(memcmp(hdr->da, broadcast_mac, 6) == 0)) {
            // handle probe req.
            continue;
        }
        else if(unlikely(memcmp(hdr->da, app->mac, 6) != 0)) {
            /* skip packages that are not for us */
            continue;
        }
        else if(unlikely((hdr->frame_control & 0x0800) != 0)) {
            /* retransmitted frame */
            continue;
        }
 
        /* acknowledge the packet */
        send_ptr += nl80211_write_radiotap_header(app, send_buf);
        send_ptr += write_ack(app, send_ptr, hdr->sa);
        nl80211_send_frame(app, send_buf, send_ptr - (void*) send_buf);

        /* handle actual packet contents */
        send_ptr = send_buf + nl80211_write_radiotap_header(app, send_buf);
        switch(hdr->frame_control & 0xff) {
            case 0x00: /* assoc req */
                send_ptr += write_assoc_resp(app, send_ptr, hdr->sa);
                printf("assoc resp\n");
                //add_station(app, hdr->sa);
                break;

            case 0x40: /* probe req */
                send_ptr += write_probe_resp(app, send_ptr, hdr->sa);
                break;

            case 0xc8: /* QoS null data */
                send_ptr += write_qos_null_data(app, send_ptr, hdr->sa);
                break;
            
            case 0x88: /* QoS data (actual controller data) */
                continue;

            default:
                continue;
        }

        nl80211_send_frame(app, send_buf, send_ptr - (void*) send_buf);
    }

    perror("read");
    return -1;
}

int main(int argc, char** argv)
{
    struct nlapp app;
    memset(&app, 0, sizeof(app));
    int ret;

    app.freq = atoi(argv[2]);
    
    u8 mac[] = { 0x62, 0x45, 0xb4, 0xf4, 0x41, 0x51 };
    app.interface = argv[1];

    if(nl80211_init(&app) < 0) return 1;

    memcpy(app.mac, mac, sizeof(mac));
    
    return nl80211_run(&app);
}

