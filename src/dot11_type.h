#ifndef __DOT11_TYPE_H_
#define __DOT11_TYPE_H_
/* value domain of 802.11 header FC.Tyte, which is b3..b2 of the 1st-byte of MAC header */
#define FC_TYPE_MGMT	0
#define FC_TYPE_CNTL	1
#define FC_TYPE_DATA	2
#define FC_TYPE_RSVED	3

/* value domain of 802.11 MGMT frame's FC.subtype, which is b7..4 of the 1st-byte of MAC header */
#define SUBTYPE_ASSOC_REQ           0
#define SUBTYPE_ASSOC_RSP           1
#define SUBTYPE_REASSOC_REQ         2
#define SUBTYPE_REASSOC_RSP         3
#define SUBTYPE_PROBE_REQ           4
#define SUBTYPE_PROBE_RSP           5
#define SUBTYPE_TIMING_ADV			6
#define SUBTYPE_BEACON              8
#define SUBTYPE_ATIM                9
#define SUBTYPE_DISASSOC            10
#define SUBTYPE_AUTH                11
#define SUBTYPE_DEAUTH              12
#define SUBTYPE_ACTION              13
#define SUBTYPE_ACTION_NO_ACK		14

/* value domain of 802.11 CNTL frame's FC.subtype, which is b7..4 of the 1st-byte of MAC header */
#define SUBTYPE_VHT_NDPA			5
#define SUBTYPE_WRAPPER				7
#define SUBTYPE_BLOCK_ACK_REQ       8
#define SUBTYPE_BLOCK_ACK           9
#define SUBTYPE_PS_POLL             10
#define SUBTYPE_RTS                 11
#define SUBTYPE_CTS                 12
#define SUBTYPE_ACK                 13
#define SUBTYPE_CFEND               14
#define SUBTYPE_CFEND_CFACK         15
// TODO: shiang-MT7615, remove this because SUBTYPE_XXX only used for SPEC defined!!
#define SUBTYPE_ALL					16

/* value domain of 802.11 DATA frame's FC.subtype, which is b7..4 of the 1st-byte of MAC header */
#define SUBTYPE_DATA                0
#define SUBTYPE_DATA_CFACK          1
#define SUBTYPE_DATA_CFPOLL         2
#define SUBTYPE_DATA_CFACK_CFPOLL   3
#define SUBTYPE_DATA_NULL           4
#define SUBTYPE_CFACK               5
#define SUBTYPE_CFPOLL              6
#define SUBTYPE_CFACK_CFPOLL        7
#define SUBTYPE_QDATA               8
#define SUBTYPE_QDATA_CFACK         9
#define SUBTYPE_QDATA_CFPOLL        10
#define SUBTYPE_QDATA_CFACK_CFPOLL  11
#define SUBTYPE_QOS_NULL            12
#define SUBTYPE_QOS_CFACK           13
#define SUBTYPE_QOS_CFPOLL          14
#define SUBTYPE_QOS_CFACK_CFPOLL    15

typedef struct __attribute__((packed))
{
    u16 Version : 2;  /* Protocol version */
    u16 Type : 2;     /* MSDU type, refer to FC_TYPE_XX */
    u16 SubType : 4;  /* MSDU subtype, refer to  SUBTYPE_XXX */
    u16 ToDs : 1;     /* To DS indication */
    u16 FrDs : 1;     /* From DS indication */
    u16 MoreFrag : 1; /* More fragment bit */
    u16 Retry : 1;    /* Retry status bit */
    u16 PwrMgmt : 1;  /* Power management bit */
    u16 MoreData : 1; /* More data bit */
    u16 Wep : 1;      /* Wep data */
    u16 Order : 1;    /* Strict order expected */
} frame_control_t;

typedef struct __attribute__((packed)) header_802_11_s
{
    frame_control_t FC; // 2
    u16 Duration; // 2
    u8 Dst[6];  // 6
    u8 Src[6];  // 6
    u8 Bssid[6];  // 6
    u16 Frag : 4;
    u16 Sequence : 12;  // 2
    u8 Octet[0];
} header_802_11_t;
#endif