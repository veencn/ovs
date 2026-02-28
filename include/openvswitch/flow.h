/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OPENVSWITCH_FLOW_H
#define OPENVSWITCH_FLOW_H 1

#include "openflow/nicira-ext.h"
#include "openvswitch/packets.h"
#include "openvswitch/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This sequence number should be incremented whenever anything involving flows
 * or the wildcarding of flows changes.  This will cause build assertion
 * failures in places which likely need to be updated. */
#define FLOW_WC_SEQ 43

/* Number of Open vSwitch extension 32-bit registers. */
#define FLOW_N_REGS 32
BUILD_ASSERT_DECL(FLOW_N_REGS <= NXM_NX_MAX_REGS);
BUILD_ASSERT_DECL(FLOW_N_REGS % 4 == 0); /* Handle xxregs. */

/* Number of OpenFlow 1.5+ 64-bit registers.
 *
 * Each of these overlays a pair of Open vSwitch 32-bit registers, so there
 * are half as many of them.*/
#define FLOW_N_XREGS (FLOW_N_REGS / 2)

/* Number of 128-bit registers.
 *
 * Each of these overlays four Open vSwitch 32-bit registers, so there
 * are a quarter as many of them.*/
#define FLOW_N_XXREGS (FLOW_N_REGS / 4)

/* Used for struct flow's dl_type member for frames that have no Ethernet
 * type, that is, pure 802.2 frames. */
#define FLOW_DL_TYPE_NONE 0x5ff

/* Fragment bits, used for IPv4 and IPv6, always zero for non-IP flows. */
#define FLOW_NW_FRAG_ANY   (1 << 0) /* Set for any IP frag. */
#define FLOW_NW_FRAG_LATER (1 << 1) /* Set for IP frag with nonzero offset. */
#define FLOW_NW_FRAG_MASK  (FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER)

BUILD_ASSERT_DECL(FLOW_NW_FRAG_ANY == NX_IP_FRAG_ANY);
BUILD_ASSERT_DECL(FLOW_NW_FRAG_LATER == NX_IP_FRAG_LATER);

BUILD_ASSERT_DECL(FLOW_TNL_F_OAM == NX_TUN_FLAG_OAM);

const char *flow_tun_flag_to_string(uint32_t flags);

/* Maximum number of supported MPLS labels. */
#define FLOW_MAX_MPLS_LABELS 3

/* Maximum number of supported SAMPLE action nesting. */
#define FLOW_MAX_SAMPLE_NESTING 10

/* Maximum number of supported VLAN headers.
 *
 * We require this to be a multiple of 2 so that vlans[] in struct flow is a
 * multiple of 64 bits. */
#define FLOW_MAX_VLAN_HEADERS 2
BUILD_ASSERT_DECL(FLOW_MAX_VLAN_HEADERS % 2 == 0);

/* Legacy maximum VLAN headers */
#define LEGACY_MAX_VLAN_HEADERS 1

/*
 * A flow in the network.
 *
 * Must be initialized to all zeros to make any compiler-induced padding
 * zeroed.  Helps also in keeping unused fields (such as mutually exclusive
 * IPv4 and IPv6 addresses) zeroed out.
 *
 * The meaning of 'in_port' is context-dependent.  In most cases, it is a
 * 16-bit OpenFlow 1.0 port number.  In the software datapath interface (dpif)
 * layer and its implementations (e.g. dpif-netlink, dpif-netdev), it is
 * instead a 32-bit datapath port number.
 *
 * The fields are organized in four segments to facilitate staged lookup, where
 * lower layer fields are first used to determine if the later fields need to
 * be looked at.  This enables better wildcarding for datapath flows.
 *
 * NOTE: Order of the fields is significant, any change in the order must be
 * reflected in miniflow_extract()!
 */
/* OVS 流匹配结构体 — 描述一个数据包的所有可匹配字段。
 *
 * 这是 OVS 中最核心的数据结构之一，贯穿整个数据包处理流水线：
 *   miniflow_extract() 从数据包中提取字段填充此结构
 *   → OpenFlow 流表匹配基于此结构的字段
 *   → datapath 流表（EMC/SMC/dpcls）的 key 是此结构的压缩形式（miniflow）
 *
 * 字段按协议层次组织：Metadata → L2 → L3 → L4
 * 每个字段都是 64 位对齐的（用 pad 填充），这对 miniflow 的位图压缩至关重要。
 *
 * 注意：字段顺序不能随意改变！miniflow_extract() 依赖此顺序。
 * 修改此结构时必须同步更新 FLOW_WC_SEQ 序列号。 */
struct flow {
    /* === Metadata（元数据）===
     * 非数据包本身的字段，而是 OVS 内部的匹配上下文。 */
    struct flow_tnl tunnel;     /* 隧道参数（VXLAN/GRE/Geneve 的外层头信息） */
    ovs_be64 metadata;          /* OpenFlow metadata（64 位，流表间传递状态） */
    uint32_t regs[FLOW_N_REGS]; /* OpenFlow 寄存器（用于流表间传递临时数据） */
    uint32_t skb_priority;      /* QoS 优先级（映射到 Linux tc 的 skb->priority） */
    uint32_t pkt_mark;          /* 数据包标记（映射到 Linux 的 skb->mark） */
    uint32_t dp_hash;           /* 数据路径计算的哈希值（用于 select group 负载均衡，
                                 * 具体算法对用户空间不透明） */
    union flow_in_port in_port; /* 入端口（OpenFlow 端口号或 datapath 端口号） */
    uint32_t recirc_id;         /* Recirculation ID（标识第几轮处理，必须精确匹配） */
    uint8_t ct_state;           /* conntrack 状态（NEW/EST/REL/RPL/INV/TRK 等标志位） */
    uint8_t ct_nw_proto;        /* conntrack 原始元组的 IP 协议号 */
    uint16_t ct_zone;           /* conntrack zone（隔离不同租户的连接跟踪表） */
    uint32_t ct_mark;           /* conntrack mark（32 位用户自定义标记） */
    ovs_be32 packet_type;       /* OpenFlow 包类型（区分 Ethernet/IP 等） */
    ovs_u128 ct_label;          /* conntrack label（128 位用户自定义标签） */
    uint32_t conj_id;           /* conjunction ID（实现 AND 逻辑的流表匹配） */
    ofp_port_t actset_output;   /* action set 中的输出端口（OpenFlow 1.1+） */

    /* === L2（数据链路层）===
     * 字段顺序与以太网头一致！64 位对齐。 */
    struct eth_addr dl_dst;     /* 目的 MAC 地址 */
    struct eth_addr dl_src;     /* 源 MAC 地址 */
    ovs_be16 dl_type;           /* 以太网类型（如 0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6）
                                   对 PACKET_TYPE(1, Ethertype) 的 L3 包也使用此字段 */
    uint8_t pad1[2];            /* 填充到 64 位对齐 */
    union flow_vlan_hdr vlans[FLOW_MAX_VLAN_HEADERS]; /* VLAN 标签（支持 QinQ 双层 VLAN） */
    ovs_be32 mpls_lse[ROUND_UP(FLOW_MAX_MPLS_LABELS, 2)]; /* MPLS 标签栈
                                                             （含填充对齐） */
    /* === L3（网络层）=== 64 位对齐 */
    ovs_be32 nw_src;            /* IPv4 源地址（或 ARP 发送方 IP） */
    ovs_be32 nw_dst;            /* IPv4 目的地址（或 ARP 目标 IP） */
    ovs_be32 ct_nw_src;         /* conntrack 原始元组的 IPv4 源地址 */
    ovs_be32 ct_nw_dst;         /* conntrack 原始元组的 IPv4 目的地址 */
    struct in6_addr ipv6_src;   /* IPv6 源地址（128 位） */
    struct in6_addr ipv6_dst;   /* IPv6 目的地址（128 位） */
    struct in6_addr ct_ipv6_src; /* conntrack 原始元组的 IPv6 源地址 */
    struct in6_addr ct_ipv6_dst; /* conntrack 原始元组的 IPv6 目的地址 */
    ovs_be32 ipv6_label;        /* IPv6 流标签（20 位） */
    uint8_t nw_frag;            /* IP 分片标志（FLOW_FRAG_ANY / FLOW_FRAG_LATER） */
    uint8_t nw_tos;             /* IP ToS 字段（包含 DSCP 6 位 + ECN 2 位） */
    uint8_t nw_ttl;             /* IP TTL / IPv6 Hop Limit */
    uint8_t nw_proto;           /* IP 协议号（如 6=TCP, 17=UDP）或 ARP 操作码低 8 位 */

    /* === L4（传输层）=== 64 位对齐 */
    struct in6_addr nd_target;  /* IPv6 邻居发现（ND）目标地址 */
    struct eth_addr arp_sha;    /* ARP/ND 源硬件地址（发送方 MAC） */
    struct eth_addr arp_tha;    /* ARP/ND 目标硬件地址（目标 MAC） */
    ovs_be16 tcp_flags;         /* TCP 标志位（SYN/ACK/FIN 等）/ ICMPv6 ND 选项类型 */
    ovs_be16 pad2;              /* 填充到 64 位对齐 */
    struct ovs_key_nsh nsh;     /* NSH（Network Service Header）字段（SFC 服务链） */

    ovs_be16 tp_src;            /* TCP/UDP/SCTP 源端口 或 ICMP 类型 */
    ovs_be16 tp_dst;            /* TCP/UDP/SCTP 目的端口 或 ICMP 代码 */
    ovs_be16 ct_tp_src;         /* conntrack 原始元组的源端口 / ICMP 类型 */
    ovs_be16 ct_tp_dst;         /* conntrack 原始元组的目的端口 / ICMP 代码 */
    ovs_be32 igmp_group_ip4;    /* IGMP 组播组 IPv4 地址 / ICMPv6 ND 保留字段
                                 * 必须是最后一个有效字段（BUILD_ASSERT_DECL 检查） */
    ovs_be32 pad3;              /* 填充到 64 位对齐 */
};
BUILD_ASSERT_DECL(sizeof(struct flow) % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(sizeof(struct flow_tnl) % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(sizeof(struct ovs_key_nsh) % sizeof(uint64_t) == 0);

#define FLOW_U64S (sizeof(struct flow) / sizeof(uint64_t))

/* Remember to update FLOW_WC_SEQ when changing 'struct flow'. */
BUILD_ASSERT_DECL(offsetof(struct flow, igmp_group_ip4) + sizeof(uint32_t)
                  == sizeof(struct flow_tnl) + sizeof(struct ovs_key_nsh) + 364
                  && FLOW_WC_SEQ == 43);

/* Incremental points at which flow classification may be performed in
 * segments.
 * This is located here since this is dependent on the structure of the
 * struct flow defined above:
 * Each offset must be on a distinct, successive U64 boundary strictly
 * within the struct flow. */
enum {
    FLOW_SEGMENT_1_ENDS_AT = offsetof(struct flow, dl_dst),
    FLOW_SEGMENT_2_ENDS_AT = offsetof(struct flow, nw_src),
    FLOW_SEGMENT_3_ENDS_AT = offsetof(struct flow, nd_target),
};
BUILD_ASSERT_DECL(FLOW_SEGMENT_1_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(FLOW_SEGMENT_2_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(FLOW_SEGMENT_3_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(                     0 < FLOW_SEGMENT_1_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_1_ENDS_AT < FLOW_SEGMENT_2_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_2_ENDS_AT < FLOW_SEGMENT_3_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_3_ENDS_AT < sizeof(struct flow));

/* Wildcards for a flow.
 *
 * A 1-bit in each bit in 'masks' indicates that the corresponding bit of
 * the flow is significant (must match).  A 0-bit indicates that the
 * corresponding bit of the flow is wildcarded (need not match). */
struct flow_wildcards {
    struct flow masks;
};

#define WC_MASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0xff, sizeof (WC)->masks.FIELD)
#define WC_MASK_FIELD_MASK(WC, FIELD, MASK)     \
    ((WC)->masks.FIELD |= (MASK))
#define WC_UNMASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0, sizeof (WC)->masks.FIELD)

void flow_wildcards_init_catchall(struct flow_wildcards *);

void flow_wildcards_init_for_packet(struct flow_wildcards *,
                                    const struct flow *);

void flow_wildcards_clear_non_packet_fields(struct flow_wildcards *);

bool flow_wildcards_is_catchall(const struct flow_wildcards *);

void flow_wildcards_set_reg_mask(struct flow_wildcards *,
                                 int idx, uint32_t mask);
void flow_wildcards_set_xreg_mask(struct flow_wildcards *,
                                  int idx, uint64_t mask);
void flow_wildcards_set_xxreg_mask(struct flow_wildcards *,
                                   int idx, ovs_u128 mask);

void flow_wildcards_and(struct flow_wildcards *dst,
                        const struct flow_wildcards *src1,
                        const struct flow_wildcards *src2);
void flow_wildcards_or(struct flow_wildcards *dst,
                       const struct flow_wildcards *src1,
                       const struct flow_wildcards *src2);
bool flow_wildcards_has_extra(const struct flow_wildcards *,
                              const struct flow_wildcards *);
uint32_t flow_wildcards_hash(const struct flow_wildcards *, uint32_t basis);
bool flow_wildcards_equal(const struct flow_wildcards *,
                          const struct flow_wildcards *);

#ifdef __cplusplus
}
#endif

#endif /* flow.h */
