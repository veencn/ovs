/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 * Copyright (c) 2019, 2020, 2021 Intel Corporation.
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

#ifndef DPIF_NETDEV_PRIVATE_FLOW_H
#define DPIF_NETDEV_PRIVATE_FLOW_H 1

#include "dpif.h"
#include "dpif-netdev-private-dpcls.h"

#include <stdbool.h>
#include <stdint.h>

#include "cmap.h"
#include "openvswitch/thread.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Contained by struct dp_netdev_flow's 'stats' member.  */
/* 流统计信息结构体 — 嵌入在 dp_netdev_flow 的 'stats' 成员中。
 * 所有字段都是原子类型，因为统计更新发生在 PMD 快速路径上，
 * 而读取（dump/get）可能在其他线程中进行。 */
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
                                   /* 最后使用时间（单调毫秒），用于流老化判断 */
    atomic_ullong packet_count;    /* Number of packets matched. */
                                   /* 匹配的数据包计数 */
    atomic_ullong byte_count;      /* Number of bytes matched. */
                                   /* 匹配的字节计数 */
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */
                                   /* 所有匹配包的 TCP 标志位的按位或（累积 SYN/ACK/FIN 等） */
};

/* Contained by struct dp_netdev_flow's 'last_attrs' member.  */
/* 流属性结构体 — 记录流的卸载状态，用于 flow dump 时向用户展示。
 * 这些属性由 offload 线程异步更新，因此使用原子类型。 */
struct dp_netdev_flow_attrs {
    atomic_bool offloaded;         /* True if flow is offloaded to HW. */
                                   /* 是否已卸载到硬件（智能网卡） */
    ATOMIC(const char *) dp_layer; /* DP layer the flow is handled in. */
                                   /* 流处理所在的数据路径层
                                    * （如 "ovs"=软件处理, "offloaded"=硬件处理,
                                    *  "non-offloaded"=硬件卸载失败后回退软件） */
};

/* A flow in 'dp_netdev_pmd_thread's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its pmd thread's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed during an RCU
 * grace period.  Code that needs to hold onto a flow for a while
 * should try incrementing 'flow->ref_cnt' with dp_netdev_flow_ref().
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' and it doesn't protect members of 'flow'
 * from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
/* OVS 用户态数据路径的流表项结构体。
 *
 * 这是 datapath 中最核心的数据结构之一，代表一条已安装的 megaflow 规则。
 * 生命周期：upcall 未命中 → ofproto 查 OpenFlow 表 → 调用 dp_netdev_flow_add() 创建
 *          → PMD 快速路径匹配使用 → 超时老化或显式删除时释放。
 *
 * 内存布局要求：'cr'（dpcls_rule）必须是最后一个成员，因为 dpcls_rule
 * 的 miniflow mask 使用了柔性数组（变长尾部）。
 *
 * 线程安全：const 成员在创建后不可变，其他成员通过原子操作或 RCU 保护。
 * 详见上方注释中的 Thread-safety 章节。 */
struct dp_netdev_flow {
    const struct flow flow;      /* Unmasked flow that created this entry. */
                                 /* 创建此流表项的原始未掩码流（精确匹配 key）。
                                  * 注意：这不是 megaflow 的掩码后 key，
                                  * 而是触发 upcall 的那个具体数据包的流信息。 */
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */
                                 /* 'flow_table'. */
                                 /* cmap 节点，用于在 PMD 线程的 flow_table 中
                                  * 按 ufid 哈希进行精确查找（flow dump/get 使用）。 */
    const struct cmap_node simple_match_node; /* In dp_netdev_pmd_thread's
                                                 'simple_match_table'. */
                                 /* cmap 节点，用于 simple_match 优化路径的哈希表。
                                  * 仅当流满足 simple_match 条件（4 字段匹配）时使用。 */
    const ovs_u128 ufid;         /* Unique flow identifier. */
                                 /* 唯一流标识符（128 位），由未掩码 flow 的哈希生成。
                                  * 用于 flow_table 的 cmap 查找 key。 */
    const ovs_u128 mega_ufid;    /* Unique mega flow identifier. */
                                 /* megaflow 唯一标识符（128 位），由掩码后 flow + mask 生成。
                                  * 用于硬件卸载等场景的流标识。 */
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */
                                 /* flow. */
                                 /* 拥有此流的 PMD 线程的 core_id。
                                  * 每条流归属于一个特定的 PMD 线程。 */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt; /* 引用计数。分类器（dpcls）持有一个引用，
                                  * 其他线程如需保持流不被释放，需增加引用。
                                  * 降为 0 时触发 RCU 延迟释放。 */

    bool dead;                   /* 标记流已"逻辑删除"。设为 true 后，
                                  * 流不再参与匹配，等待 RCU 宽限期后物理释放。 */
    bool offloaded;              /* 缓存的硬件卸载状态（非权威，供快速检查用）。 */
    atomic_int offload_queue_depth; /* 排队等待卸载操作的数量（原子计数器）。
                                     * 用于限制 offload 请求队列深度，防止积压。 */
    uint64_t simple_match_mark;  /* Unique flow mark for the simple match. */
                                 /* simple_match 优化路径的唯一标记值。
                                  * 用于 simple_match_table 中的快速 4 字段匹配。 */
    odp_port_t orig_in_port;     /* 原始入端口号（datapath 端口号）。
                                  * 用于 simple_match 查找时的端口匹配。 */

    /* Statistics. */
    struct dp_netdev_flow_stats stats; /* 流统计信息（包数/字节数/TCP标志/最后使用时间）。
                                        * 在 packet_batch_per_flow_execute() 中更新。 */

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions; /* RCU 保护的动作列表。
                                                      * 包含 OVS_ACTION_ATTR_* 序列。
                                                      * 可被 flow_put 原子替换（RCU swap），
                                                      * 读者（PMD）无需加锁即可安全读取旧版本。 */

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch; /* 批处理指针 — 指向当前正在为此流累积的包批次。
                                          * 工作流程：
                                          *   dp_netdev_queue_batches() 将包加入批次
                                          *   → packet_batch_per_flow_execute() 执行动作
                                          *   → 重置为 NULL。
                                          * 仅在单次 dp_netdev_input__() 调用期间有效。 */

    /* Packet classification. */
    char *dp_extra_info;         /* String to return in a flow dump/get. */
                                 /* 额外信息字符串（如 "miniflow_bits" 描述）。
                                  * 在 flow dump/get 时返回给用户，辅助调试。 */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */
                                 /* dpcls 分类规则 — 嵌入在 dpcls 子表中用于 megaflow 匹配。
                                  * 包含 miniflow 格式的 flow 和 mask。
                                  * 必须是最后一个成员，因为 dpcls_rule 内部的
                                  * miniflow 使用柔性数组（struct miniflow 的 values[]）。 */
    /* 'cr' must be the last member. */
};

/* 根据 ufid 计算哈希值 — 直接取 ufid 的低 32 位。
 * ufid 本身已经是哈希生成的，所以低 32 位已有足够随机性，
 * 无需再做额外哈希运算。用于 flow_table (cmap) 的桶定位。 */
static inline uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

/* Given the number of bits set in miniflow's maps, returns the size of the
 * 'netdev_flow_key.mf' */
/* 根据 miniflow 位图中置位数量，计算 netdev_flow_key.mf 的实际大小。
 * = miniflow 头（两个 64 位 map）+ 实际存储的非零 uint64_t 值数组。
 * 这决定了 flow key 的内存占用——字段越少，key 越小，缓存越友好。 */
static inline size_t
netdev_flow_key_size(size_t flow_u64s)
{
    return sizeof(struct miniflow) + MINIFLOW_VALUES_SIZE(flow_u64s);
}

/* forward declaration required for EMC to unref flows */
/* 前向声明：释放流引用。EMC 缓存替换旧条目时需要调用此函数
 * 对被驱逐的流执行 unref，引用计数归零时触发 RCU 延迟释放。 */
void dp_netdev_flow_unref(struct dp_netdev_flow *);

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' is protected with RCU. */
/* 数据路径动作集合 — 描述匹配某条流后要执行的所有动作。
 *
 * 通过 RCU 保护：当 flow_put 更新动作时，会分配新的 dp_netdev_actions，
 * 通过 ovsrcu_set() 原子替换，旧版本在 RCU 宽限期后释放。
 * 因此 PMD 线程读取动作时无需加锁。
 *
 * 使用柔性数组成员 actions[]，结构体大小 = sizeof(头) + size 字节。 */
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
                                /* 动作数据的总字节数 */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
                                /* Netlink 属性序列，包含 OUTPUT/SET/PUSH_VLAN 等动作。
                                 * 柔性数组 — 实际大小由 size 决定。
                                 * 由 dp_netdev_execute_actions() 解析并执行。 */
};

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-flow.h */
