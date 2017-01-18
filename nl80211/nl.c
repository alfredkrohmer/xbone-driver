#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <net/if.h>

#include <linux/nl80211.h>
#include "ieee802_11_defs.h"

#include <errno.h>
#include <stdio.h>

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
    int if_idx;
    u8 if_mac[6];
    
    struct nl_sock *sk;
    int nl80211_id;
};

static int nl80211_callback(struct nl_msg* msg, void* arg)
{
    printf("OK\n");
    struct nlmsghdr* ret_hdr = nlmsg_hdr(msg);
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

    if (ret_hdr->nlmsg_type != expectedId)
    {
        // what is this??
        return NL_STOP;
    }

    struct genlmsghdr *gnlh = (struct genlmsghdr*) nlmsg_data(ret_hdr);

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (tb_msg[NL80211_ATTR_IFTYPE]) {
        int type = nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]);

        printf("Type: %d", type);
    }

    return 0;
}

int nl80211_init(struct nlapp *app) {
    //struct nl_cb *cb = nl_cb_alloc(NL_CB_VERBOSE);
    //nl_cb_err(cb, NL_CB_VERBOSE, NULL, stdout);
    
    // resolve interface index
    app->if_idx = if_nametoindex(app->interface);
    fprintf(stderr, "device index: %d\n", app->if_idx);

    // create NetLink socket
    app->sk = nl_socket_alloc();
    if(!app->sk) {
        printf("%s", strerror(errno));
        return -1;
        // TODO failed
    }

    // connect to generic netlink
    if(genl_connect(app->sk)) {
        printf("%s", strerror(errno));
        return -1;
        // TODO failed
    }

    // find the nl80211 driver ID
    app->nl80211_id = genl_ctrl_resolve(app->sk, "nl80211");
    
    // attach callback
    nl_socket_modify_cb(app->sk, NL_CB_VALID, NL_CB_CUSTOM, nl80211_callback, NULL);
    
    return 0;
}

#define NLA_SET_CMD(__msg__, __family__, __cmd__) (genlmsg_put(__msg__, 0, 0, __family__, 0, 0, __cmd__, 0))

const uint8_t nl80211_assoc_resp_ie[] = {
    0xdd, 0x10, 0x00, 0x50, 0xf2, 0x11, 0x02, 0x10, 0x00,
    0xa1, 0x28, 0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int nl80211_send_and_receive(struct nlapp *app, struct nl_msg *msg) {
    int ret = nl_send_auto(app->sk, msg);
    if(ret < 0) {
        nl_perror(ret, "nl_send_auto");
        return ret;
    }
    ret = nl_recvmsgs_default(app->sk);
    if(ret) {
        nl_perror(ret, "nl_recvmsgs_default");
        return ret;
    }

    return 0;
}

/* creates a nl802111 netlink message and pre-fills it with the genl header and
 * the interface index */
struct nl_msg* nl80211_create_msg(struct nlapp *app, u32 cmd) {
    struct nl_msg *msg = nlmsg_alloc();
    if(!msg)
    	return NULL;

    if(!genlmsg_put(msg, 0, 0, app->nl80211_id, 0, 0, cmd, 0))
    	goto nla_put_failure;

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, app->if_idx);

    return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

int nl80211_set_ap(struct nlapp *app, int freq) {
    int ret;
    struct nl_msg *msg;
    
    // set interface to AP mode
    fprintf(stderr, "set interface mode\n");
    msg = nl80211_create_msg(app, NL80211_CMD_SET_INTERFACE);
    NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE,  NL80211_IFTYPE_AP);
    if((ret = nl80211_send_and_receive(app, msg))) return ret;
/*
    // set data rate
    fprintf(stderr, "set data rate\n");
    msg = nl80211_create_msg(app, NL80211_CMD_SET_TX_BITRATE_MASK);
    struct nlattr
        *rates = nla_nest_start(msg, NL80211_ATTR_TX_RATES),
        *bands = nla_nest_start(msg, NL80211_BAND_5GHZ);
    if(!rates || !bands)
        goto nla_put_failure;
    NLA_PUT_U8(msg, NL80211_TXRATE_LEGACY, 6 * 2);
    nla_nest_end(msg, bands);
    nla_nest_end(msg, rates);
    if((ret = nl80211_send_and_receive(app, msg))) return ret;
  */  
    /*
     * set up beacon frame
     */
    struct ieee80211_mgmt *head = malloc(256);

    /* MAC addresses */
    memcpy(head->bssid, app->if_mac, 6);
    memcpy(head->sa,    app->if_mac, 6);
    memset(head->da,    0xff,        6); // broadcast

    // other beacon fields
    head->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_BEACON);
    head->duration      = 0;
    head->u.beacon.beacon_int = 100;
    head->u.beacon.capab_info = 0xc631;

    u8 *pos = head->u.beacon.variable;
    *pos++ = 0;
    *pos++ = 0;
    memcpy(pos, nl80211_assoc_resp_ie, sizeof(nl80211_assoc_resp_ie));
    pos += sizeof(nl80211_assoc_resp_ie);

    u8 head_len = pos - (u8*) head;

    hexDump("beacon", head, head_len);

    fprintf(stderr, "start AP\n");
    msg = nl80211_create_msg(app, NL80211_CMD_START_AP);
    NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, 100); // 102.4 milliseconds
    NLA_PUT_U32(msg, NL80211_ATTR_DTIM_PERIOD,     100);
    NLA_PUT    (msg, NL80211_ATTR_BEACON_HEAD,     head_len, head);
    NLA_PUT    (msg, NL80211_ATTR_IE,              sizeof(nl80211_assoc_resp_ie), nl80211_assoc_resp_ie);
    NLA_PUT    (msg, NL80211_ATTR_IE_PROBE_RESP,   sizeof(nl80211_assoc_resp_ie), nl80211_assoc_resp_ie);
    NLA_PUT    (msg, NL80211_ATTR_IE_ASSOC_RESP,   sizeof(nl80211_assoc_resp_ie), nl80211_assoc_resp_ie);
    NLA_PUT_U32   (msg, NL80211_ATTR_WIPHY_FREQ,      freq); // channel 6
    NLA_PUT_U32   (msg, NL80211_ATTR_CHANNEL_WIDTH,   NL80211_CHAN_WIDTH_20_NOHT);
    NLA_PUT_STRING(msg, NL80211_ATTR_SSID,            "test");
    if((ret = nl80211_send_and_receive(app, msg))) return ret;

    fprintf(stderr, "AP setup complete\n");
    
    return 0;
    
nla_put_failure:
	nlmsg_free(msg);
    return -1;
}

int nl80211_run(struct nlapp *app) {
    while(1) {
        int ret = nl_recvmsgs_default(app->sk);
        printf("ok\n");
        if(ret) {
            nl_perror(ret, "nl_recvmsgs_default");
            return ret;
        }
    }
}

int main(int argc, char** argv)
{
    struct nlapp app;
    int ret;

    int freq = atoi(argv[2]);
    
    u8 mac[] = { 0x12, 0x34, 0x56, 0x79, 0x0a, 0xbc };
    app.interface = argv[1];
    memcpy(app.if_mac, mac, sizeof(mac));

    ret = nl80211_init(&app);
    if(ret < 0) return 1;

    ret = nl80211_set_ap(&app, freq);
    if(ret < 0) return 1;
    
    return nl80211_run(&app);
}

