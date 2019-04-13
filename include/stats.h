#ifndef __STATS_H__
#define __STATS_H__
#include "common.h"
#define DEBUG_ON
#ifdef DEBUG_ON
#define PRINT_DEBUG(...)  printf(__VA_ARGS__)
#define PRINT_ERROR(...)  printf(__VA_ARGS__)
#else
#define PRINT_DEBUG(...)  ;
#define PRINT_ERROR(...)  ;
#endif

#define HAL_NUM_OF_ANTS             (4)
#define NL_ATTR_HDR 4
/* Length of IEEE address (bytes) */
#define IEEE_ADDR_LEN                   (6)

/* This type is used for Source and Destination MAC addresses and also as   */
/* unique identifiers for Stations and Networks.                            */

typedef struct _IEEE_ADDR
{
    unsigned char au8Addr[IEEE_ADDR_LEN]; /* WARNING: Special case! No padding here! This structure must be padded externally! */
} IEEE_ADDR;

#define MAC_PRINTF_FMT "%02X:%02X:%02X:%02X:%02X:%02X"

#define __BYTE_ARG(b,i)            (((unsigned char *)(b))[i])
#define __BYTE_ARG_TYPE(t,b,i)     ((t)__BYTE_ARG((b),(i)))
#define _BYTE_ARG_U(b,i)            __BYTE_ARG_TYPE(unsigned int,(b),(i))
#define MAC_PRINTF_ARG(x) \
  _BYTE_ARG_U((x), 0),_BYTE_ARG_U((x), 1),_BYTE_ARG_U((x), 2),_BYTE_ARG_U((x), 3),_BYTE_ARG_U((x), 4),_BYTE_ARG_U((x), 5)

#define MAX_NL_REPLY 8192
#define MAX_LEN_VALID_VALUE 1024
#define MAX_USAGE_LEN 128
#define MAX_COMMAND_LEN 64
#define SZ sizeof(stats)
#define PRINT_DESCRIPTION(x)	printf("%s\n",x.description);
#define INDENTATION1(x)		if(x>0)\
					{while(x) { printf("  "); x--;}};

typedef enum{
  MTLK_WSSA_11A_SUPPORTED,
  MTLK_WSSA_11B_SUPPORTED,
  MTLK_WSSA_11G_SUPPORTED,
  MTLK_WSSA_11N_SUPPORTED,
  MTLK_WSSA_11AC_SUPPORTED,
  MTLK_WSSA_11AX_SUPPORTED,
}wssa_net_modes_supported_e;

typedef enum{
  VENDOR_UNKNOWN,
  VENDOR_LANTIQ,
  VENDOR_W101,
}wssa_peer_vendor_t;

typedef enum{
  MTLK_PHY_MODE_AG,
  MTLK_PHY_MODE_B,
  MTLK_PHY_MODE_N,
  MTLK_PHY_MODE_AC,
  MTLK_PHY_MODE_AX,
}wssa_phy_mode_e;

typedef struct peer_list{
  IEEE_ADDR addr;
  unsigned int is_sta_auth;
}peer_list_t;

typedef struct wssa_peer_traffic_stats{
  uint32_t BytesSent;
  uint32_t BytesReceived;
  uint32_t PacketsSent;
  uint32_t PacketsReceived;
}wssa_peer_traffic_stats_t;

typedef struct wssa_retrans_stats{
  uint32_t Retransmissions;
  uint32_t RetransCount;
  uint32_t RetryCount;
  uint32_t MultipleRetryCount;
  uint32_t FailedRetransCount;
}wssa_retrans_stats_t;

typedef struct wssa_drv_tr181_peer_stats{
  uint32_t StationId;
  uint32_t NetModesSupported;
  wssa_peer_traffic_stats_t traffic_stats;
  wssa_retrans_stats_t retrans_stats;
  uint32_t ErrorsSent;
  uint32_t LastDataDownlinkRate;
  uint32_t LastDataUplinkRate;
  int32_t SignalStrength;
}wssa_drv_tr181_peer_stats_t;

typedef struct wssa_drv_peer_stats{
  wssa_drv_tr181_peer_stats_t tr181_stats;
  int32_t ShortTermRSSIAverage[4];
  int8_t snr[4];
  uint32_t AirtimeEfficiency;
  uint8_t AirtimeUsage;
}wssa_drv_peer_stats_t;

typedef struct wssa_drv_peer_rate_info1{
  uint32_t InfoFlag;
  uint32_t PhyMode;
  int32_t CbwIdx;
  int32_t CbwMHz;
  int32_t Scp;
  int32_t Mcs;
  int32_t Nss;
}wssa_drv_peer_rate_info1_t;

typedef struct wssa_drv_peer_rates_info{
  wssa_drv_peer_rate_info1_t rx_mgmt_rate_info;
  uint32_t RxMgmtRate;
  wssa_drv_peer_rate_info1_t rx_data_rate_info;
  uint32_t RxDataRate;
  wssa_drv_peer_rate_info1_t tx_data_rate_info;
  uint32_t TxDataRate;
  uint32_t TxBfMode;
  uint32_t TxStbcMode;
  uint32_t TxPwrCur;
  uint32_t TxMgmtPwr;
}wssa_drv_peer_rates_info_t;

typedef struct wssa_drv_traffic_stats{
  uint64_t BytesSent;
  uint64_t BytesReceived;
  uint64_t PacketsSent;
  uint64_t PacketsReceived;
  uint32_t UnicastPacketsSent;
  uint32_t UnicastPacketsReceived;
  uint32_t MulticastPacketsSent;
  uint32_t MulticastPacketsReceived;
  uint32_t BroadcastPacketsSent;
  uint32_t BroadcastPacketsReceived;
}wssa_drv_traffic_stats_t;

typedef struct wssa_drv_tr181_error_stats{
  uint32_t ErrorsSent;
  uint32_t ErrorsReceived;
  uint32_t DiscardPacketsSent;
  uint32_t DiscardPacketsReceived;
}wssa_drv_tr181_error_stats_t;

typedef struct wssa_drv_tr181_wlan_stats{
  wssa_drv_traffic_stats_t traffic_stats;
  wssa_drv_tr181_error_stats_t error_stats;
  wssa_retrans_stats_t retrans_stats;
  uint32_t ACKFailureCount;
  uint32_t AggregatedPacketCount;
  uint32_t UnknownProtoPacketsReceived;
}wssa_drv_tr181_wlan_stats_t;

typedef struct wssa_drv_tr181_hw{
  uint8_t Enable;
  uint8_t Channel;
}wssa_drv_tr181_hw_t;

typedef struct wssa_drv_tr181_hw_stats{
  wssa_drv_traffic_stats_t traffic_stats;
  wssa_drv_tr181_error_stats_t error_stats;
  uint32_t FCSErrorCount;
  int32_t Noise;
}wssa_drv_tr181_hw_stats_t;

typedef struct wssa_drv_recovery_stats{
  uint32_t FastRcvryProcessed;
  uint32_t FullRcvryProcessed;
  uint32_t FastRcvryFailed;
  uint32_t FullRcvryFailed;
}wssa_drv_recovery_stats_t;

typedef struct wssa_drv_peer_capabilities{
  uint32_t NetModesSupported;
  uint32_t WMMSupported;
  uint32_t CBSupported;
  uint32_t SGI20Supported;
  uint32_t SGI40Supported;
  uint32_t STBCSupported;
  uint32_t LDPCSupported;
  uint32_t BFSupported;
  uint32_t Intolerant_40MHz;
  uint32_t Vendor;
  uint32_t MIMOConfigTX;
  uint32_t MIMOConfigRX;
  uint32_t AMPDUMaxLengthExp;
  uint32_t AMPDUMinStartSpacing;
  uint32_t AssociationTimestamp;
}wssa_drv_peer_capabilities_t;

typedef struct _PeerFlowStats_t {
  uint64_t cli_rx_bytes;
  uint64_t cli_tx_bytes;
  uint64_t cli_rx_frames;
  uint64_t cli_tx_frames;
  uint64_t cli_rx_retries;
  uint64_t cli_tx_retries;
  uint64_t cli_rx_errors;
  uint64_t cli_tx_errors;
  uint64_t cli_rx_rate;
  uint64_t cli_tx_rate;
} peerFlowStats;
typedef struct _PeerRateInfoRxStats_t {
  uint64_t flags;
  uint64_t bytes;
  uint64_t msdus;
  uint64_t mpdus;
  uint64_t ppdus;
  uint64_t retries;
  uint8_t rssi_combined;
  uint8_t rssi_array[HAL_NUM_OF_ANTS];
} peerRateInfoRxStats;

typedef struct _PeerRateInfoTxStats_t {
  uint64_t flags;
  uint64_t bytes;
  uint64_t msdus;
  uint64_t mpdus;
  uint64_t ppdus;
  uint64_t retries;
  uint64_t attempts;
} peerRateInfoTxStats;

typedef enum {
  LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_LIST = 316,
  LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_FLOW_STATUS = 317,
  LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_CAPABILITIES = 318,
  LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_RATE_INFO = 319,
  LTQ_NL80211_VENDOR_SUBCMD_GET_RECOVERY_STATS = 320,
  LTQ_NL80211_VENDOR_SUBCMD_GET_HW_FLOW_STATUS = 321,
  LTQ_NL80211_VENDOR_SUBCMD_GET_TR181_WLAN_STATS = 322,
  LTQ_NL80211_VENDOR_SUBCMD_GET_TR181_HW_STATS = 323,
  LTQ_NL80211_VENDOR_SUBCMD_GET_TR181_PEER_STATS = 324
}cmd_id;


typedef enum {
	PEER_FLOW_STATS=0,
	PEER_TRAFFIC_STAT,
	RETRANS_STAT,
	TR181_PEER_STATS,
	NETWORK_BITFIELD,
	PEER_CAPABILITY,
	VENDOR_ENUM,
	PEER_RATE_INFO,
	PEER_RATE_INFO1,
	PHY_ENUM,
	RECOVERY_STAT,
	HW_TXM_STAT,
	TRAFFIC_STATS,
	MGMT_STATS,
	HW_FLOW_STATUS,
	TR181_ERROR_STATS,
	TR181_WLAN_STATS,
	TR181_HW_STATS,
	PEER_LIST
}stat_id;

typedef struct 
{
	char cmd[MAX_COMMAND_LEN]; //command name
	cmd_id id; //NL command
	int num_arg; // number of arguments expected
	char usage[MAX_USAGE_LEN];
	stat_id c; //enum for each cmd
}stats_cmd;

typedef enum
{
	UCHAR=0,
	CHAR,
	BYTE,
	UINT,
	INT,
	LONG,
	SLONG,
	SLONGARRAY,
	SBYTEARRAY,
	FLAG,
	BITFIELD,
	ENUM,
	TIMESTAMP,
	LONGFRACT,
	SLONGFRACT,
	HUGE,
	NONE	
}type;

typedef struct
{
	stat_id c;
	char description[MAX_LEN_VALID_VALUE];
	type t;
	int element;
}stats;

struct print_struct {
	stat_id st;
	stats *sts;
	int size;
};

stats network_bitfield[] = {
{NETWORK_BITFIELD,	"802.11a",		BITFIELD,	0}, 
{NETWORK_BITFIELD,	"802.11b",		BITFIELD,	1}, 
{NETWORK_BITFIELD,	"802.11g",		BITFIELD,	2}, 
{NETWORK_BITFIELD,	"802.11n",		BITFIELD,	3}, 
{NETWORK_BITFIELD,	"802.11ac",		BITFIELD,	4},
{NETWORK_BITFIELD,	"802.11ax",		BITFIELD,	5}
};

stats phy_enum[] = {
{PHY_ENUM,	"802.11a/g",	ENUM,	0}, 
{PHY_ENUM,	"802.11b",	ENUM,	1}, 
{PHY_ENUM,	"802.11n",	ENUM,	2}, 
{PHY_ENUM,	"802.11ac",	ENUM,	3},
{PHY_ENUM,	"802.11ax",	ENUM,	4}
};

stats vendor_enum[] = {
{VENDOR_ENUM,	"Unknown",	ENUM,	0},
{VENDOR_ENUM,	"Lantiq",	ENUM,	1},
{VENDOR_ENUM,	"W101",		ENUM,	2}
};

stats peer_traffic_stat[] = {
{PEER_TRAFFIC_STAT,	"Peer Traffic Statistics",			                        NONE,	0},
{PEER_TRAFFIC_STAT,	"BytesSent                - Number of bytes sent successfully",		LONG,	0},
{PEER_TRAFFIC_STAT,	"BytesReceived            - Number of bytes received",			LONG,	0},
{PEER_TRAFFIC_STAT,	"PacketsSent              - Number of packets transmitted",		LONG,	0},
{PEER_TRAFFIC_STAT,	"PacketsReceived          - Number of packets received",		LONG,	0}	
};

stats peer_retrans_stat[] = {
{RETRANS_STAT,		"Retransmition Statistics",		                                                    	NONE,	0},
{RETRANS_STAT,		"Retransmissions          - Number of re-transmitted, from the last 100 packets sent",      	LONG,	0},
{RETRANS_STAT,		"RetransCount             - Total number of transmitted packets which were retransmissions",	LONG,	0},
{RETRANS_STAT,		"RetryCount               - Number of Tx packets succeeded after one or more retransmissions",  LONG,	0},
{RETRANS_STAT,		"MultipleRetryCount       - Number of Tx packets succeeded after more than one retransmission",	LONG,	0},
{RETRANS_STAT,		"FailedRetransCount       - Number of Tx packets dropped because of retry limit exceeded",	LONG,	0}
};

stats tr181_peer_stat[] = {
{TR181_PEER_STATS,	"TR-181 Device.WiFi.AccessPoint.{i}.AssociatedDevice",					NONE,	0},
{TR181_PEER_STATS,	"StationID",					        				LONG,	0},
{NETWORK_BITFIELD,	"OperatingStandard    - Supported network modes",       				NONE,	0},
{PEER_TRAFFIC_STAT,	"Traffic statistics",				        				NONE,	0},
{RETRANS_STAT,		  "Retransmission statistics",			        				NONE,	0},
{TR181_PEER_STATS,	"ErrorsSent           - Number of Tx packets not transmitted because of errors",	LONG,	0},
{TR181_PEER_STATS,	"LastDataDownlinkRate - Last data transmit rate (to peer) [kbps]",			LONG,	0},
{TR181_PEER_STATS,	"LastDataUplinkRate   - Last data receive rate (from peer) [kbps]",			LONG,	0},
{TR181_PEER_STATS,	"SignalStrength       - Radio signal strength of the uplink [dBm]",			SLONG,	0}
};

stats peer_flow_stats[] = {
{PEER_FLOW_STATS,	"Peer packets flow statistics",						NONE,		0},
{TR181_PEER_STATS,"TR-181 statistics",				                                NONE,		0},
{PEER_FLOW_STATS,	"ShortTermRSSI        - Short-term RSSI average per antenna [dBm]",	SLONGARRAY,	4},
{PEER_FLOW_STATS,	"SNR                  - Signal to Noise ratio per antenna [dB]",	SBYTEARRAY,	4},
{PEER_FLOW_STATS,	"AirtimeEfficiency    - Efficiency of used air time [bytes/sec]",	LONG,		0},
{PEER_FLOW_STATS,	"AirtimeUsage         - Air Time Used by RX/TX to/from STA [%]",	BYTE,		0}
};

stats peer_rate_info1[] = {
{PEER_RATE_INFO1,	"Rate info is valid",	  FLAG,	0},
{PHY_ENUM,		    "Network (Phy) Mode",	  NONE,	0},
{PEER_RATE_INFO1,	"BW index",		        SLONG,	0},
{PEER_RATE_INFO1,	"BW [MHz]",		        SLONG,	0},
{PEER_RATE_INFO1,	"SGI",			          SLONG,	0},
{PEER_RATE_INFO1,	"MCS index",		      SLONG,	0},
{PEER_RATE_INFO1,	"NSS",			          SLONG,	0}
};

stats peer_rate_info[] = {
{PEER_RATE_INFO,	"Peer TX/RX info",			NONE,		0},
{PEER_RATE_INFO1,	"Mgmt uplink rate info",		NONE,		0},
{PEER_RATE_INFO,	"Last mgmt uplink rate [Mbps]",		LONGFRACT,	1},
{PEER_RATE_INFO1,	"Data uplink rate info",		NONE,		0},
{PEER_RATE_INFO,	"Last data uplink rate [Mbps]",		LONGFRACT,	1},
{PEER_RATE_INFO1,	"Data downlink rate info",		NONE,		0},
{PEER_RATE_INFO,	"Last data downlink rate [Mbps]",	LONGFRACT,	1},
{PEER_RATE_INFO,	"Beamforming mode",			LONG,		0},
{PEER_RATE_INFO,	"STBC mode",				LONG,		0},
{PEER_RATE_INFO,	"TX power for current rate [dBm]",	LONGFRACT,	2},
{PEER_RATE_INFO,	"TX management power       [dBm]",	LONGFRACT,	2}
};

stats peer_capability[] = {
{PEER_CAPABILITY,	"Peer capabilities",			NONE,		0},
{NETWORK_BITFIELD,	"Supported network modes",		NONE,		0},
{PEER_CAPABILITY,	"WMM is supported",			FLAG,		0},
{PEER_CAPABILITY,	"Channel bonding supported",		FLAG,		0},
{PEER_CAPABILITY,	"SGI20 supported",			FLAG,		0},
{PEER_CAPABILITY,	"SGI40 supported",			FLAG,		0},
{PEER_CAPABILITY,	"STBC supported",	                FLAG,		0}, 
{PEER_CAPABILITY,	"LDPC supported",	                FLAG,		0},
{PEER_CAPABILITY,	"Explicit beam forming supported",	FLAG,		0},
{PEER_CAPABILITY,	"40MHz intolerant",			FLAG,		0},
{VENDOR_ENUM,		"Vendor",				NONE,		0},
{PEER_CAPABILITY,	"Max TX spatial streams",		LONG,		0},
{PEER_CAPABILITY,	"Max RX spatial streams",		LONG,		0},
{PEER_CAPABILITY,	"Maximum A-MPDU Length Exponent",	LONG,		0},
{PEER_CAPABILITY,	"Minimum MPDU Start Spacing",		LONG,		0},
{PEER_CAPABILITY,	"Timestamp of station association",	TIMESTAMP,	0}
};

stats recovery_stat[] =
{
{RECOVERY_STAT,		"Recovery statistics",					NONE,	0},
{RECOVERY_STAT,		"Number of FAST recovery processed successfully",	LONG,	0},
{RECOVERY_STAT,		"Number of FULL recovery processed successfully",	LONG,	0},
{RECOVERY_STAT,		"Number of FAST recovery failed",			LONG,	0},
{RECOVERY_STAT,		"Number of FULL recovery failed",			LONG,	0}
};

stats hw_txm_stat[] = {
{HW_TXM_STAT,		"HW TXM Statistics",					NONE,	0},
{HW_TXM_STAT,		"Number of FW MAN messages sent",			LONG,	0},
{HW_TXM_STAT,		"Number of FW MAN messages confirmed",			LONG,	0},
{HW_TXM_STAT,		"Peak number of FW MAN messages sent simultaneously",	LONG,	0},
{HW_TXM_STAT,		"Number of FW DBG messages sent",			LONG,	0},
{HW_TXM_STAT,		"Number of FW DBG messages confirmed",			LONG,	0},
{HW_TXM_STAT,		"Peak number of FW DBG messages sent simultaneously",	LONG,	0}
};

stats traffic_stats[] = {
{TRAFFIC_STATS,		"Traffic Statistics",				                                NONE,	0},
{TRAFFIC_STATS,		"BytesSent                - Number of bytes sent successfully (64-bit)",	HUGE,	0},
{TRAFFIC_STATS,		"BytesReceived            - Number of bytes received (64-bit)",			HUGE,	0},
{TRAFFIC_STATS,		"PacketsSent              - Number of packets transmitted (64-bit)",		HUGE,	0},
{TRAFFIC_STATS,		"PacketsReceived          - Number of packets received (64-bit)",		HUGE,	0},
{TRAFFIC_STATS,		"UnicastPacketsSent       - Number of unicast packets transmitted",		LONG,	0},
{TRAFFIC_STATS,		"UnicastPacketsReceived   - Number of unicast packets received",		LONG,	0},
{TRAFFIC_STATS,		"MulticastPacketsSent     - Number of multicast packets transmitted",		LONG,	0},
{TRAFFIC_STATS,		"MulticastPacketsReceived - Number of multicast packets received",		LONG,	0},
{TRAFFIC_STATS,		"BroadcastPacketsSent     - Number of broadcast packets transmitted",		LONG,	0},
{TRAFFIC_STATS,		"BroadcastPacketsReceived - Number of broadcast packets received",		LONG,	0}
};

stats mgmt_stats[] = {
{MGMT_STATS,		"Management frames statistics",					NONE,	0},
{MGMT_STATS,		"Number of management frames in reserved queue",		LONG,	0},
{MGMT_STATS,		"Number of management frames sent",		                LONG,	0},
{MGMT_STATS,		"Number of management frames confirmed",			LONG,	0},
{MGMT_STATS,		"Number of management frames received",				LONG,	0},
{MGMT_STATS,		"Number of management frames dropped due to retries",		LONG,	0},
{MGMT_STATS,		"Number of management frames dropped due to TX que full",	LONG,	0},
{MGMT_STATS,		"Number of probe responses sent",                         	LONG,0},
{MGMT_STATS,		"Number of probe responses dropped",                      	LONG,0}
};

stats hw_flow_status[] = {
{RECOVERY_STAT,	"HW Recovery Statistics",		NONE,	0},
{HW_TXM_STAT,	"HW TXM statistics",			NONE,	0},
{TRAFFIC_STATS,	"Radio Traffic statistics",		NONE,	0},
{MGMT_STATS,	"Radio MGMT statistics",		NONE,	0},
{HW_FLOW_STATUS,"Radars detected",	                LONG,	0},
{HW_FLOW_STATUS,"Channel Load [%]",	                BYTE,	0},
{HW_FLOW_STATUS,"Channel Utilization [%]",		BYTE,	0},
{HW_FLOW_STATUS,"Total Airtime [%]",			BYTE,	0},
{HW_FLOW_STATUS,"Total Airtime Efficiency [bytes/sec]",	LONG,	0}
};

stats tr181_error_stats[] = {
{TR181_ERROR_STATS,	"TR-181 Errors",			                                                NONE,	0},
{TR181_ERROR_STATS,	"ErrorsSent               - Number of Tx packets not transmitted because of errors",	LONG,	0},
{TR181_ERROR_STATS,	"ErrorsReceived           - Number of Rx packets that contained errors",		LONG,	0},
{TR181_ERROR_STATS,	"DiscardPacketsSent       - Number of Tx packets discarded",				LONG,	0},
{TR181_ERROR_STATS,	"DiscardPacketsReceived   - Number of Rx packets discarded",				LONG,	0}
};

stats tr181_wlan_stats[] = {
{TR181_WLAN_STATS,  	"TR-181 Device.WiFi.SSID.{i}.Stats",							NONE,	0},
{TRAFFIC_STATS,		"Traffic Statistics",			                                                NONE,	0},
{TR181_ERROR_STATS,	"Erros Statistics",									NONE,	0},
{RETRANS_STAT,		"Retransmission statistics",								NONE,	0},
{TR181_WLAN_STATS,	"ACKFailureCount             - Number of expected ACKs never received",			LONG,	0},
{TR181_WLAN_STATS,	"AggregatedPacketCount       - Number of aggregated packets transmitted",		LONG,	0},
{TR181_WLAN_STATS,	"UnknownProtoPacketsReceived - Number of Rx packets unknown or unsupported protocol",	LONG,	0}
};

stats tr181_hw_stats[] = {
{TR181_HW_STATS,	"TR-181 Device.WiFi.Radio.{i}.Stats",						NONE,	0},
{TRAFFIC_STATS,		"Traffic Statistics",			                                        NONE,	0},
{TR181_ERROR_STATS,	"Erros Statistics",			                                        NONE,	0},
{TR181_HW_STATS,	"FCSErrorCount            - Number of Rx packets with detected FCS error",	LONG,	0},
{TR181_HW_STATS,	"Noise                    - Average noise strength received [dBm]",		SLONG,	0}
};

struct print_struct gStat[] = {
{PEER_FLOW_STATS,	peer_flow_stats,	sizeof(peer_flow_stats)/SZ},
{PEER_TRAFFIC_STAT,	peer_traffic_stat,	sizeof(peer_traffic_stat)/SZ},
{RETRANS_STAT,		peer_retrans_stat,	sizeof(peer_retrans_stat)/SZ},
{TR181_PEER_STATS,	tr181_peer_stat,	sizeof(tr181_peer_stat)/SZ},
{NETWORK_BITFIELD,	network_bitfield,	sizeof(network_bitfield)/SZ},
{PEER_CAPABILITY,	peer_capability,	sizeof(peer_capability)/SZ},
{VENDOR_ENUM,		vendor_enum,		sizeof(vendor_enum)/SZ},
{PEER_RATE_INFO,	peer_rate_info,		sizeof(peer_rate_info)/SZ},
{PEER_RATE_INFO1,	peer_rate_info1,	sizeof(peer_rate_info1)/SZ},
{PHY_ENUM,		phy_enum,		sizeof(phy_enum)/SZ},
{RECOVERY_STAT,		recovery_stat,		sizeof(recovery_stat)/SZ},
{HW_TXM_STAT,		hw_txm_stat,		sizeof(hw_txm_stat)/SZ},
{TRAFFIC_STATS,		traffic_stats,		sizeof(traffic_stats)/SZ},
{MGMT_STATS,		mgmt_stats,		sizeof(mgmt_stats)/SZ},
{HW_FLOW_STATUS,	hw_flow_status,		sizeof(hw_flow_status)/SZ},
{TR181_ERROR_STATS,	tr181_error_stats,	sizeof(tr181_error_stats)/SZ},
{TR181_WLAN_STATS,	tr181_wlan_stats,	sizeof(tr181_wlan_stats)/SZ},
{TR181_HW_STATS,	tr181_hw_stats,		sizeof(tr181_hw_stats)/SZ}
};

stats_cmd gCmd[] =
{
{"PeerList", LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_LIST, 1, 
		"usage: dwpal_cli [INTERFACENAME] PeerList",PEER_LIST},
{"PeerFlowStatus", LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_FLOW_STATUS, 2, 
		"usage: dwpal_cli [INTERFACENAME] PeerFlowStatus [MACADDR]", PEER_FLOW_STATS},
{"PeerCapabilities", LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_CAPABILITIES, 2, 
		"usage: dwpal_cli [INTERFACENAME] PeerCapabilities [MACADDR]", PEER_CAPABILITY},
{"PeerRatesInfo", LTQ_NL80211_VENDOR_SUBCMD_GET_PEER_RATE_INFO, 2, 
		"usage: dwpal_cli [INTERFACENAME] PeerRatesInfo [MACADDR]", PEER_RATE_INFO},
{"RecoveryStats", LTQ_NL80211_VENDOR_SUBCMD_GET_RECOVERY_STATS, 1,
		"usage: dwpal_cli [INTERFACENAME] RecoveryStats", RECOVERY_STAT},
{"HWFlowStatus", LTQ_NL80211_VENDOR_SUBCMD_GET_HW_FLOW_STATUS, 1,
		"usage: dwpal_cli [INTERFACENAME] HWFlowStatus", HW_FLOW_STATUS},
{"TR181WLANStat", LTQ_NL80211_VENDOR_SUBCMD_GET_TR181_WLAN_STATS, 1,
		"usage: dwpal_cli [INTERFACENAME] TR181WLANStat", TR181_WLAN_STATS},
{"TR181HWStat", LTQ_NL80211_VENDOR_SUBCMD_GET_TR181_HW_STATS, 1,
		"usage: dwpal_cli [INTERFACENAME] TR181HWStat", TR181_HW_STATS},
{"TR181PeerStat", LTQ_NL80211_VENDOR_SUBCMD_GET_TR181_PEER_STATS, 2,
		"usage: dwpal_cli [INTERFACENAME] TR181PeerStat [MACADDR]", TR181_PEER_STATS}
};


int check_stats_cmd(int argc,char *argv[]);
#endif
