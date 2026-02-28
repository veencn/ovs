/*
 * Copyright (c) 2009-2014, 2016-2018 Nicira, Inc.
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

/*
 * dpif-netdev.c — OVS 用户空间数据路径（datapath）核心实现。
 *
 * 本文件实现基于 netdev 的用户空间数据路径（即 DPDK datapath），
 * 是 OVS-DPDK 的核心模块。与内核数据路径（dpif-netlink）不同，
 * 此数据路径完全运行在用户空间，使用 PMD（Poll Mode Driver）线程
 * 进行高速轮询收发包，避免内核态-用户态切换开销。
 *
 * 主要功能：
 * - PMD 线程管理：创建、销毁、调度轮询线程
 * - 多级流表：EMC（精确匹配缓存）→ SMC（签名匹配缓存）→ dpcls（通配符分类器）
 * - 收发包路径：netdev 收包 → miniflow 提取 → 流表查找 → 执行 action → 发包
 * - 端口管理：添加/删除端口、RXQ 到 PMD 的分配
 * - Meter 计量：QoS 速率限制
 * - 连接跟踪：与 conntrack 模块集成
 * - 自动负载均衡：RXQ 在 PMD 线程间的动态重分配
 */
#include <config.h>
#include "dpif-netdev.h"           /* 本模块对外接口声明 */
#include "dpif-netdev-private.h"   /* 内部私有数据结构（PMD 线程、流表等） */
#include "dpif-netdev-private-dfc.h" /* DFC（数据路径流缓存）私有结构 */
#include "dpif-offload.h"          /* 硬件卸载相关接口 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "ccmap.h"
#include "cmap.h"
#include "conntrack.h"
#include "conntrack-tp.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-lookup.h"
#include "dpif-netdev-perf.h"
#include "dpif-netdev-private-extract.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "id-fpool.h"
#include "id-pool.h"
#include "ipf.h"
#include "mov-avg.h"
#include "mpsc-queue.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "pvector.h"
#include "random.h"
#include "seq.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"

/* 定义本模块日志名为 dpif_netdev，
 * 可通过 ovs-appctl vlog/set dpif_netdev:dbg 调整日志级别。 */
VLOG_DEFINE_THIS_MODULE(dpif_netdev);

/* @veencn_260223: Latency measurement helper functions. */
/* 延迟测量辅助函数：用于测量 PMD 各处理阶段的时延（CPU 周期数），
 * 包括 miniflow 提取、EMC/SMC/dpcls 查找、upcall、action 执行等阶段。
 * 通过 ovs-appctl dpif-netdev/latency-* 命令控制。 */

/* 将 CPU 时钟周期数转换为纳秒。 */
static inline uint64_t
latency_cycles_to_ns(uint64_t cycles)
{
    uint64_t hz = pmd_perf_get_tsc_hz();
    return hz > 1 ? cycles * 1000000000ULL / hz : 0;
}

/* 更新某个阶段的延迟统计：累加计数/总周期数，更新最小/最大值，
 * 并将转换后的纳秒值放入直方图桶中（<100ns, 100-200ns, ... >=100us）。 */
static inline void
latency_stage_update(struct latency_stage_stats *stage, uint64_t cycles)
{
    stage->count++;
    stage->total_cycles += cycles;
    if (cycles < stage->min_cycles) {
        stage->min_cycles = cycles;
    }
    if (cycles > stage->max_cycles) {
        stage->max_cycles = cycles;
    }

    uint64_t ns = latency_cycles_to_ns(cycles);
    int bucket;
    if (ns < 100) {
        bucket = 0;
    } else if (ns < 200) {
        bucket = 1;
    } else if (ns < 500) {
        bucket = 2;
    } else if (ns < 1000) {
        bucket = 3;
    } else if (ns < 10000) {
        bucket = 4;
    } else if (ns < 100000) {
        bucket = 5;
    } else {
        bucket = 6;
    }
    stage->histogram[bucket]++;
}

/* 初始化延迟统计结构，将所有阶段的 min_cycles 设为 UINT64_MAX。 */
static void
latency_stats_init(struct pmd_latency_stats *s)
{
    memset(s, 0, sizeof *s);
    s->enabled = false;
    s->miniflow.min_cycles = UINT64_MAX;
    s->emc_lookup.min_cycles = UINT64_MAX;
    s->smc_lookup.min_cycles = UINT64_MAX;
    s->dpcls_lookup.min_cycles = UINT64_MAX;
    s->upcall.min_cycles = UINT64_MAX;
    s->action_exec.min_cycles = UINT64_MAX;
    s->total.min_cycles = UINT64_MAX;
}

/* 清除延迟统计数据但保留 enabled 状态。 */
static void
latency_stats_clear(struct pmd_latency_stats *s)
{
    bool was_enabled = s->enabled;
    latency_stats_init(s);
    s->enabled = was_enabled;
}
/* 核心单包测量：从 rx_tsc 到 t_now 的延迟。
 * 返回 true 表示记录成功（rx_tsc 有效），调用者可据此决定是否计数。 */
static inline bool
latency_mark_pkt(struct latency_stage_stats *stage,
                 const struct dp_packet *pkt, uint64_t t_now)
{
    uint64_t rx = dp_packet_get_rx_tsc(pkt);
    if (rx) {
        latency_stage_update(stage, t_now - rx);
        return true;
    }
    return false;
}

/* 批量计算端到端总延迟：遍历 batch，对每个包算 t_end - rx_tsc。 */
static inline void
latency_batch_total(struct pmd_latency_stats *ls,
                    struct dp_packet_batch *batch, uint64_t t_end)
{
    struct dp_packet *pkt;
    DP_PACKET_BATCH_FOR_EACH (i, pkt, batch) {
        latency_mark_pkt(&ls->total, pkt, t_end);
    }
}

/* @veencn_260223: Latency instrumentation macros.
 *
 * 统一入口: LATENCY(pmd, TYPE, ...)
 * TYPE: STAMP_BATCH, MARK, MARK_BATCH, BEGIN, END
 *
 * _LATENCY_END 内部变量 _lend 保存结束时间戳，
 * 可在可变参数中引用（如 latency_batch_total(..., _lend)）。 */

#define LATENCY(PMD, TYPE, ...) _LATENCY_##TYPE(PMD, ##__VA_ARGS__)

/* T1: 批量给包打 rx_tsc 时间戳 */
#define _LATENCY_STAMP_BATCH(PMD, BATCH)                                \
    do {                                                                \
        if (OVS_UNLIKELY((PMD)->latency_stats.enabled)) {              \
            struct dp_packet *_lpkt;                                    \
            uint64_t _tsc = cycles_counter_update(&(PMD)->perf_stats); \
            DP_PACKET_BATCH_FOR_EACH (_li, _lpkt, (BATCH)) {          \
                dp_packet_set_rx_tsc(_lpkt, _tsc);                     \
            }                                                           \
        }                                                               \
    } while (0)

/* T2/T3a/T3b: 单包测量（可变参数仅在 rx_tsc 有效时执行） */
#define _LATENCY_MARK(PMD, PKT, STAGE, ...)                             \
    do {                                                                \
        if (OVS_UNLIKELY((PMD)->latency_stats.enabled)) {              \
            uint64_t _now = cycles_counter_update(&(PMD)->perf_stats); \
            if (latency_mark_pkt(&(PMD)->latency_stats.STAGE,          \
                                 (PKT), _now)) {                        \
                __VA_ARGS__;                                            \
            }                                                           \
        }                                                               \
    } while (0)

/* T3c: 批量测量 + 条件过滤 + 命中计数 */
#define _LATENCY_MARK_BATCH(PMD, BATCH, STAGE, COUNTER, FILTER)         \
    do {                                                                \
        if (OVS_UNLIKELY((PMD)->latency_stats.enabled)) {              \
            struct dp_packet *_lpkt;                                    \
            uint64_t _now = cycles_counter_update(&(PMD)->perf_stats); \
            DP_PACKET_BATCH_FOR_EACH (_li, _lpkt, (BATCH)) {          \
                if ((FILTER)[_li]                                       \
                    && latency_mark_pkt(&(PMD)->latency_stats.STAGE,   \
                                        _lpkt, _now)) {                 \
                    (PMD)->latency_stats.COUNTER++;                     \
                }                                                       \
            }                                                           \
        }                                                               \
    } while (0)

/* T3d前/T4前: 区间测量起点（声明变量，不能用 do-while 包装） */
#define _LATENCY_BEGIN(PMD, VAR)                                        \
    uint64_t VAR = 0;                                                   \
    if (OVS_UNLIKELY((PMD)->latency_stats.enabled)) {                  \
        VAR = cycles_counter_update(&(PMD)->perf_stats);               \
    }

/* T3d后/T4后: 区间测量终点（_lend 可在可变参数中引用） */
#define _LATENCY_END(PMD, VAR, STAGE, ...)                              \
    do {                                                                \
        if (OVS_UNLIKELY((PMD)->latency_stats.enabled) && (VAR)) {    \
            uint64_t _lend = cycles_counter_update(                     \
                &(PMD)->perf_stats);                                    \
            latency_stage_update(&(PMD)->latency_stats.STAGE,          \
                                 _lend - (VAR));                        \
            __VA_ARGS__;                                                \
        }                                                               \
    } while (0)

/* @veencn_260223 end: latency helpers & macros */

/* Auto Load Balancing Defaults */
/* 自动负载均衡（ALB）默认参数：
 * ALB 会周期性检查各 PMD 线程的 RXQ 负载，
 * 当负载不均时自动重新分配 RXQ 到不同的 PMD 线程。 */
#define ALB_IMPROVEMENT_THRESHOLD    25    /* 重分配后负载改善至少 25% 才生效 */
#define ALB_LOAD_THRESHOLD           95    /* PMD 负载超过 95% 时触发重分配 */
#define ALB_REBALANCE_INTERVAL       1     /* 1 Min */
#define MAX_ALB_REBALANCE_INTERVAL   20000 /* 20000 Min */
#define MIN_TO_MSEC                  60000 /* 分钟转毫秒 */

#define FLOW_DUMP_MAX_BATCH 50  /* 流表 dump 时每次最多取 50 条 */
/* Use per thread recirc_depth to prevent recirculation loop. */
/* 每线程 recirculation 深度计数器，防止无限循环重入。 */
#define MAX_RECIRC_DEPTH 8
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Use instant packet send by default. */
/* 默认立即发送数据包（不做 output batching）。
 * 设为非零值可延迟发送，以攒批提升吞吐量。 */
#define DEFAULT_TX_FLUSH_INTERVAL 0

/* Configuration parameters. */
/* 配置参数上限。 */
enum { MAX_METERS = 1 << 18 };  /* Maximum number of meters. */  /* 最大 meter 数量 262144 */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */  /* 每个 meter 最多 8 个 band */

/* 数据路径丢包统计计数器定义。
 * 每种丢包原因对应一个 COVERAGE 计数器，
 * 可通过 ovs-appctl coverage/show 查看各类丢包数量。 */
COVERAGE_DEFINE(datapath_drop_meter);           /* meter 限速丢包 */
COVERAGE_DEFINE(datapath_drop_upcall_error);    /* upcall 失败丢包 */
COVERAGE_DEFINE(datapath_drop_lock_error);      /* 获取锁失败丢包 */
COVERAGE_DEFINE(datapath_drop_userspace_action_error); /* userspace action 失败 */
COVERAGE_DEFINE(datapath_drop_tunnel_push_error);  /* 隧道封装失败 */
COVERAGE_DEFINE(datapath_drop_tunnel_pop_error);   /* 隧道解封装失败 */
COVERAGE_DEFINE(datapath_drop_recirc_error);       /* recirculation 失败 */
COVERAGE_DEFINE(datapath_drop_invalid_port);       /* 无效端口 */
COVERAGE_DEFINE(datapath_drop_invalid_bond);       /* 无效 bond */
COVERAGE_DEFINE(datapath_drop_invalid_tnl_port);   /* 无效隧道端口 */
COVERAGE_DEFINE(datapath_drop_rx_invalid_packet);  /* 收到无效报文 */
COVERAGE_DEFINE(datapath_drop_hw_post_process);    /* 硬件后处理丢包 */
COVERAGE_DEFINE(datapath_drop_hw_post_process_consumed); /* 硬件后处理已消费 */

/* Protects against changes to 'dp_netdevs'. */
/* 全局互斥锁，保护 dp_netdevs 哈希表的并发修改。 */
struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
/* 全局字符串哈希表，存储所有 dp_netdev 实例（按名称索引）。
 * 通常只有一个 datapath（如 "netdev@ovs-netdev"）。 */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

/* upcall 日志速率限制：每秒最多 600 条日志。 */
static struct vlog_rate_limit upcall_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* 用户空间 datapath 支持的连接跟踪状态标志位掩码。 */
#define DP_NETDEV_CS_SUPPORTED_MASK (CS_NEW | CS_ESTABLISHED | CS_RELATED \
                                     | CS_INVALID | CS_REPLY_DIR | CS_TRACKED \
                                     | CS_SRC_NAT | CS_DST_NAT)
#define DP_NETDEV_CS_UNSUPPORTED_MASK (~(uint32_t)DP_NETDEV_CS_SUPPORTED_MASK)

/* 用户空间 datapath 的特性支持声明。
 * 表示本 datapath 支持的 ODP 功能：VLAN/MPLS 无限层数、
 * recirculation、conntrack 全部字段等。 */
static struct odp_support dp_netdev_support = {
    .max_vlan_headers = SIZE_MAX, /* 支持任意数量 VLAN 头 */
    .max_mpls_depth = SIZE_MAX,   /* 支持任意深度 MPLS 标签栈 */
    .recirc = true,               /* 支持 recirculation（重入处理） */
    .ct_state = true,             /* 支持 conntrack 状态匹配 */
    .ct_zone = true,              /* 支持 conntrack zone */
    .ct_mark = true,              /* 支持 conntrack mark */
    .ct_label = true,             /* 支持 conntrack label */
    .ct_state_nat = true,         /* 支持 conntrack NAT 状态 */
    .ct_orig_tuple = true,        /* 支持 conntrack 原始五元组(IPv4) */
    .ct_orig_tuple6 = true,       /* 支持 conntrack 原始五元组(IPv6) */
};


/* Simple non-wildcarding single-priority classifier. */
/* 简单非通配、单优先级分类器（dpcls）相关常量定义。 */

/* Time in microseconds between successive optimizations of the dpcls
 * subtable vector */
/* dpcls 子表向量优化间隔：每 1 秒重新排序子表，
 * 将命中率高的子表排在前面以加速查找。 */
#define DPCLS_OPTIMIZATION_INTERVAL 1000000LL

/* Time in microseconds of the interval in which rxq processing cycles used
 * in rxq to pmd assignments is measured and stored. */
/* RXQ 处理周期采样间隔：每 5 秒记录一次各 RXQ 消耗的 CPU 周期数，
 * 用于负载均衡时评估 RXQ 的负载大小。 */
#define PMD_INTERVAL_LEN 5000000LL
/* For converting PMD_INTERVAL_LEN to secs. */
#define INTERVAL_USEC_TO_SEC 1000000LL

/* Number of intervals for which cycles are stored
 * and used during rxq to pmd assignment. */
/* 保存最近 12 个采样间隔的数据（共 60 秒），
 * 用于 RXQ 分配时的负载统计。 */
#define PMD_INTERVAL_MAX 12

/* Time in microseconds to try RCU quiescing. */
/* PMD 线程每 10ms 尝试一次 RCU 静默期（quiescent state），
 * 使其他线程能安全释放 RCU 保护的资源。 */
#define PMD_RCU_QUIESCE_INTERVAL 10000LL

/* Timer resolution for PMD threads in nanoseconds. */
/* PMD 线程定时器精度：1 微秒。 */
#define PMD_TIMER_RES_NS 1000

/* Number of pkts Rx on an interface that will stop pmd thread sleeping. */
/* PMD 休眠唤醒阈值：收到超过此数量的包就停止休眠。 */
#define PMD_SLEEP_THRESH (NETDEV_MAX_BURST / 2)
/* Time in uS to increment a pmd thread sleep time. */
/* PMD 休眠时间递增步长：每次增加 1 微秒。 */
#define PMD_SLEEP_INC_US 1

/* PMD 线程休眠配置：允许为特定 core 设置最大休眠时间（微秒），
 * 用于在低负载时降低 CPU 使用率。 */
struct pmd_sleep {
    unsigned core_id;   /* 绑定的 CPU 核心 ID */
    uint64_t max_sleep; /* 最大休眠时间（微秒） */
};

/* dpcls — 数据路径分类器（Datapath Classifier）。
 * 每个入端口（in_port）对应一个 dpcls 实例，存储该端口的所有通配符流表规则。
 * 内部使用多个子表（subtable），每个子表对应一种 mask 模式。
 * 查找时按 pvector 排序依次匹配子表，命中率高的子表排在前面。 */
struct dpcls {
    struct cmap_node node;      /* Within dp_netdev_pmd_thread.classifiers */
    odp_port_t in_port;         /* 此分类器对应的入端口号 */
    struct cmap subtables_map;  /* 子表哈希映射（按 mask 索引） */
    struct pvector subtables;   /* 子表优先级向量（按命中率排序） */
};

/* Data structure to keep packet order till fastpath processing. */
/* 数据包-流表映射：在批处理中将每个包与其匹配的流表项关联，
 * 保持包的原始顺序直到快速路径处理完成。 */
struct dp_packet_flow_map {
    struct dp_packet *packet;       /* 指向数据包的指针 */
    struct dp_netdev_flow *flow;    /* 匹配到的流表项（NULL 表示未命中） */
    uint16_t tcp_flags;             /* 提取的 TCP 标志位 */
};

/* dpcls 分类器操作函数的前向声明。 */
static void dpcls_init(struct dpcls *);       /* 初始化分类器 */
static void dpcls_destroy(struct dpcls *);    /* 销毁分类器 */
static void dpcls_sort_subtable_vector(struct dpcls *);  /* 按命中率排序子表 */
static uint32_t dpcls_subtable_lookup_reprobe(struct dpcls *cls); /* 重新探测子表查找函数 */
static void dpcls_insert(struct dpcls *, struct dpcls_rule *,
                         const struct netdev_flow_key *mask); /* 插入规则 */
static void dpcls_remove(struct dpcls *, struct dpcls_rule *); /* 删除规则 */

/* Set of supported meter flags */
/* 支持的 meter 标志：统计、按包计速、按 Kbps 计速、突发。 */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Set of supported meter band types */
/* 支持的 meter band 类型：仅支持 DROP（丢弃）。 */
#define DP_SUPPORTED_METER_BAND_TYPES           \
    ( 1 << OFPMBT13_DROP )

/* Meter band：meter 的一个速率段，超过此速率则执行对应动作（如丢弃）。 */
struct dp_meter_band {
    uint32_t rate;
    uint32_t burst_size;
    atomic_uint64_t bucket;          /* In 1/1000 packets for PKTPS,
                                      * or in bits for KBPS. */
    atomic_uint64_t packet_count;
    atomic_uint64_t byte_count;
};

/* dp_meter — OpenFlow meter 实例。
 * 用于 QoS 速率限制：对匹配流量进行计量，超速时执行 band 动作。 */
struct dp_meter {
    struct cmap_node node;          /* 在 dp_netdev.meters 哈希表中的节点 */
    uint32_t id;                    /* meter ID */
    uint16_t flags;                 /* meter 标志（PKTPS/KBPS/BURST 等） */
    uint16_t n_bands;               /* band 数量 */
    uint32_t max_delta_t;           /* 最大时间差（防止溢出） */
    atomic_uint64_t used;  /* Time of a last use in milliseconds. */
    atomic_uint64_t packet_count;   /* 累计处理的包数 */
    atomic_uint64_t byte_count;     /* 累计处理的字节数 */
    struct dp_meter_band bands[];   /* 柔性数组：包含 n_bands 个 band */
};

/* 自动负载均衡（Auto Load Balancing）状态。
 * 周期性检测各 PMD 线程的 RXQ 负载分布，
 * 当 PMD 负载超过阈值时自动重分配 RXQ。 */
struct pmd_auto_lb {
    bool do_dry_run;                     /* 是否先模拟运行（不实际迁移） */
    bool recheck_config;                 /* 是否需要重新检查配置 */
    bool is_enabled;            /* Current status of Auto load balancing. */
    uint64_t rebalance_intvl;            /* 重平衡检查间隔（毫秒） */
    uint64_t rebalance_poll_timer;       /* 下次检查的时间戳 */
    uint8_t rebalance_improve_thresh;    /* 改善阈值百分比 */
    atomic_uint8_t rebalance_load_thresh; /* 负载触发阈值百分比 */
};

/* RXQ 到 PMD 线程的分配策略枚举。 */
enum sched_assignment_type {
    SCHED_ROUNDROBIN,  /* 轮询分配：按顺序将 RXQ 分配给各 PMD */
    SCHED_CYCLES, /* Default.*/  /* 基于周期的分配（默认）：按 CPU 周期消耗均衡 */
    SCHED_GROUP        /* 分组分配：将相同端口的 RXQ 分给同一 PMD */
};

/* Datapath based on the network device interface from netdev.h.
 *
 * dp_netdev — 用户空间数据路径的核心结构体。
 * 每个 OVS bridge 对应一个 dp_netdev 实例，管理所有端口、PMD 线程、
 * 流表、meter、bond 等资源。通常整个系统只有一个 datapath。
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 * 锁获取顺序（从外到内）：
 *    dp_netdev_mutex (global)  — 全局锁，保护 dp_netdevs
 *    port_rwlock               — 读写锁，保护端口列表
 *    bond_mutex                — 保护 bond 配置
 *    non_pmd_mutex             — 保护 non-PMD 线程
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    const char *const full_name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_rwlock'. */
    struct ovs_rwlock port_rwlock;
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;

    /* Meters. */
    struct ovs_mutex meters_lock;
    struct cmap meters;

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    atomic_uint32_t emc_insert_min;
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;
    /* Default max load based sleep request. */
    uint64_t pmd_max_sleep_default;
    /* Enable the SMC cache from ovsdb config */
    atomic_bool smc_enable_db;

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;
    /* id pool for per thread static_tx_qid. */
    struct id_pool *tx_qid_pool;
    struct ovs_mutex tx_qid_pool_mutex;
    /* Rxq to pmd assignment type. */
    enum sched_assignment_type pmd_rxq_assign_type;
    bool pmd_iso;

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;

    struct seq *reconfigure_seq;
    uint64_t last_reconfigure_seq;

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;

    /* PMD max load based sleep request user string. */
    char *max_sleep_list;

    uint64_t last_tnl_conf_seq;

    struct conntrack *conntrack;
    struct pmd_auto_lb pmd_alb;

    /* Bonds. */
    struct ovs_mutex bond_mutex; /* Protects updates of 'tx_bonds'. */
    struct cmap tx_bonds; /* Contains 'struct tx_bond'. */
};

static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQ_RDLOCK(dp->port_rwlock);

/* RXQ 处理周期计数器类型。
 * 用于统计每个 RXQ 消耗的 CPU 周期数，为负载均衡提供依据。 */
enum rxq_cycles_counter_type {
    RXQ_CYCLES_PROC_CURR,       /* Cycles spent successfully polling and
                                   processing packets during the current
                                   interval. */
                                /* 当前采样间隔内轮询和处理包消耗的周期数 */
    RXQ_CYCLES_PROC_HIST,       /* Total cycles of all intervals that are used
                                   during rxq to pmd assignment. */
                                /* 所有历史间隔的累计周期数（用于 RXQ 分配决策） */
    RXQ_N_CYCLES
};

/* XPS（Transmit Packet Steering）超时：500ms 内无流量则释放 TX 队列绑定。 */
#define XPS_TIMEOUT 500000LL    /* In microseconds. */

/* Contained by struct dp_netdev_port's 'rxqs' member.  */
/* dp_netdev_rxq — 端口的一个接收队列。
 * 每个物理/虚拟端口可有多个 RXQ，每个 RXQ 被分配给一个 PMD 线程轮询。 */
struct dp_netdev_rxq {
    struct dp_netdev_port *port;
    struct netdev_rxq *rx;
    unsigned core_id;                  /* Core to which this queue should be
                                          pinned. OVS_CORE_UNSPEC if the
                                          queue doesn't need to be pinned to a
                                          particular core. */
    atomic_count intrvl_idx;           /* Write index for 'cycles_intrvl'. */
    struct dp_netdev_pmd_thread *pmd;  /* pmd thread that polls this queue. */
    bool is_vhost;                     /* Is rxq of a vhost port. */

    /* Counters of cycles spent successfully polling and processing pkts. */
    atomic_ullong cycles[RXQ_N_CYCLES];
    /* We store PMD_INTERVAL_MAX intervals of data for an rxq and then
       sum them to yield the cycles used for an rxq. */
    atomic_ullong cycles_intrvl[PMD_INTERVAL_MAX];
};

/* TX 队列请求模式枚举（用户配置）。 */
enum txq_req_mode {
    TXQ_REQ_MODE_THREAD,  /* 按线程静态分配 TX 队列 */
    TXQ_REQ_MODE_HASH,    /* 按哈希动态选择 TX 队列 */
};

/* TX 队列实际运行模式枚举。 */
enum txq_mode {
    TXQ_MODE_STATIC,    /* 静态模式：每个 PMD 固定使用一个 TXQ */
    TXQ_MODE_XPS,       /* XPS 模式：基于包的源端口选择 TXQ */
    TXQ_MODE_XPS_HASH,  /* XPS 哈希模式：基于流哈希选择 TXQ */
};

/* A port in a netdev-based datapath. */
/* dp_netdev_port — 数据路径中的一个端口。
 * 对应物理网卡（dpdk 类型）、vhost 端口、internal 端口等。
 * 每个端口包含若干 RXQ 和 TXQ。 */
struct dp_netdev_port {
    odp_port_t port_no;         /* ODP 端口号 */
    enum txq_mode txq_mode;     /* static, XPS, XPS_HASH. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;      /* 底层网络设备抽象 */
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf; /* 保存的网络设备标志 */
    struct dp_netdev_rxq *rxqs; /* 接收队列数组 */
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    bool emc_enabled;           /* If true EMC will be used. */
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
    enum txq_req_mode txq_requested_mode; /* 用户请求的 TXQ 模式 */
};

/* 流表和 action 操作的前向声明。 */
static bool dp_netdev_flow_ref(struct dp_netdev_flow *); /* 增加流表项引用计数 */
static int dpif_netdev_flow_from_nlattrs(const struct nlattr *, uint32_t,
                                         struct flow *, bool); /* 从 netlink 属性解析流 */

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t); /* 创建 action 列表 */
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *); /* 获取流表项的 action（RCU 安全） */
static void dp_netdev_actions_free(struct dp_netdev_actions *); /* 释放 action */

/* PMD 线程轮询的队列快照。
 * PMD 主循环开始前从 poll_list 拷贝一份到栈上，避免加锁。 */
struct polled_queue {
    struct dp_netdev_rxq *rxq;  /* 指向接收队列 */
    odp_port_t port_no;         /* 端口号 */
    bool emc_enabled;           /* 此端口是否启用 EMC */
    bool rxq_enabled;           /* 此 RXQ 是否启用 */
    uint64_t change_seq;        /* 端口变更序号（检测配置变化） */
};

/* Contained by struct dp_netdev_pmd_thread's 'poll_list' member. */
/* rxq_poll — PMD 轮询列表的元素，记录哪些 RXQ 分配给了此 PMD。 */
struct rxq_poll {
    struct dp_netdev_rxq *rxq;  /* 待轮询的接收队列 */
    struct hmap_node node;      /* 在 pmd->poll_list 哈希表中的节点 */
};

/* Contained by struct dp_netdev_pmd_thread's 'send_port_cache',
 * 'tnl_port_cache' or 'tx_ports'. */
/* tx_port — PMD 线程的发送端口缓存。
 * 每个 PMD 为其可能发往的每个端口维护一个 tx_port，
 * 用于 output batching（攒批发送）以提升吞吐量。 */
struct tx_port {
    struct dp_netdev_port *port;   /* 目标端口 */
    int qid;                       /* 使用的 TX 队列 ID */
    long long last_used;           /* 上次使用的时间戳（用于 XPS 超时） */
    struct hmap_node node;         /* 哈希表节点 */
    long long flush_time;          /* 下次强制刷新的时间 */
    struct dp_packet_batch output_pkts;  /* 输出包的攒批缓冲 */
    struct dp_packet_batch *txq_pkts; /* Only for hash mode. */
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST]; /* 每个包对应的源 RXQ */
};

/* Contained by struct tx_bond 'member_buckets'. */
/* Bond 成员条目：记录一个哈希桶对应的 bond 成员端口及流量统计。 */
struct member_entry {
    odp_port_t member_id;       /* 成员端口 ID */
    atomic_ullong n_packets;    /* 此桶发送的包数 */
    atomic_ullong n_bytes;      /* 此桶发送的字节数 */
};

/* Contained by struct dp_netdev_pmd_thread's 'tx_bonds'. */
/* tx_bond — 数据路径中的 bond（链路聚合）。
 * 使用哈希桶将流量分配到不同成员端口。 */
struct tx_bond {
    struct cmap_node node;      /* 在 pmd->tx_bonds 中的节点 */
    uint32_t bond_id;           /* bond 标识符 */
    struct member_entry member_buckets[BOND_BUCKETS]; /* 哈希桶数组 */
};

/* Interface to netdev-based datapath. */
/* dpif_netdev — dpif 接口的 netdev 实现。
 * 将通用 dpif 接口"继承"并关联到具体的 dp_netdev 实例。
 * 上层通过 dpif 指针调用虚函数表中的操作。 */
struct dpif_netdev {
    struct dpif dpif;           /* 基类：通用 dpif 接口 */
    struct dp_netdev *dp;       /* 关联的数据路径实例 */
    uint64_t last_port_seq;     /* 上次读取的端口变更序号 */
};

/* 以下为各子系统的静态函数前向声明。
 * OVS_REQ_RDLOCK/WRLOCK 标注表示调用时需要持有的锁。 */

/* 端口查找/管理 */
static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock);   /* 按端口号查找端口 */
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock);   /* 按设备名查找端口 */
static void dp_netdev_free(struct dp_netdev *)
    OVS_REQUIRES(dp_netdev_mutex);     /* 释放 datapath */
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock);   /* 添加端口到 datapath */
static void do_del_port(struct dp_netdev *dp, struct dp_netdev_port *)
    OVS_REQ_WRLOCK(dp->port_rwlock);   /* 从 datapath 删除端口 */
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **); /* 打开/创建 dpif */
/* 在 PMD 线程上执行给定的 action 列表。 */
static void dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                                      struct dp_packet_batch *,
                                      bool should_steal,
                                      const struct flow *flow,
                                      const struct nlattr *actions,
                                      size_t actions_len);
/* 将包送入 recirculation（重入处理，如 ct/bond 后续查找）。 */
static void dp_netdev_recirculate(struct dp_netdev_pmd_thread *,
                                  struct dp_packet_batch *);

/* PMD 线程管理相关前向声明 */
static void dp_netdev_disable_upcall(struct dp_netdev *); /* 禁用 upcall */
static void dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd); /* 通知 PMD 重载完成 */
static void dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd,
                                    struct dp_netdev *dp, unsigned core_id,
                                    int numa_id); /* 配置/初始化 PMD 线程 */
static void dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd); /* 销毁 PMD 线程 */
static void dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock); /* 设置 non-PMD 线程（处理非轮询操作） */

static void *pmd_thread_main(void *); /* PMD 线程主函数入口 */
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp,
                                                      unsigned core_id); /* 按核心 ID 获取 PMD */
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos); /* 遍历 PMD */
static void dp_netdev_del_pmd(struct dp_netdev *dp,
                              struct dp_netdev_pmd_thread *pmd); /* 删除 PMD */
static void dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd); /* 销毁所有 PMD */
static void dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd); /* 清除 PMD 的端口列表 */
static void dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                     struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                       struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex);
static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force);
static void dp_netdev_add_bond_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct tx_bond *bond, bool update)
    OVS_EXCLUDED(pmd->bond_mutex);
static void dp_netdev_del_bond_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           uint32_t bond_id)
    OVS_EXCLUDED(pmd->bond_mutex);

/* datapath 重配置及 PMD 引用计数管理 */
static void reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock);  /* 重新配置 datapath（端口/PMD 变更后调用） */
static bool dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd); /* 尝试增加 PMD 引用 */
static void dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd);   /* 减少 PMD 引用 */
static void dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd); /* 清空 PMD 的所有流表 */
static void pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex); /* 加载端口缓存到 PMD 本地 */
/* 尝试优化 dpcls 子表排序和 miniflow 提取函数。 */
static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt);
static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type);
static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                           unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx);
static uint64_t
get_interval_values(atomic_ullong *source, atomic_count *cur_idx,
                    int num_to_read);
static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge);
static int dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                                      struct tx_port *tx);
inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port);

static void dp_netdev_request_reconfigure(struct dp_netdev *dp);
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd);

/* simple_match 是一种优化路径：对于只匹配 in_port 的简单流表规则，
 * 可以跳过完整的 dpcls 查找，直接匹配。 */
static void dp_netdev_simple_match_insert(struct dp_netdev_pmd_thread *pmd,
                                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex);  /* 插入简单匹配流 */
static void dp_netdev_simple_match_remove(struct dp_netdev_pmd_thread *pmd,
                                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex);  /* 移除简单匹配流 */

static bool dp_netdev_flow_is_simple_match(const struct match *); /* 判断是否为简单匹配 */

/* Updates the time in PMD threads context and should be called in three cases:
 *
 *     1. PMD structure initialization:
 *         - dp_netdev_configure_pmd()
 *
 *     2. Before processing of the new packet batch:
 *         - dpif_netdev_execute()
 *         - dp_netdev_process_rxq_port()
 *
 *     3. At least once per polling iteration in main polling threads if no
 *        packets received on current iteration:
 *         - dpif_netdev_run()
 *         - pmd_thread_main()
 *
 * 'pmd->ctx.now' should be used without update in all other cases if possible.
 */
static inline void
pmd_thread_ctx_time_update(struct dp_netdev_pmd_thread *pmd)
{
    pmd->ctx.now = time_usec();
}

/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
/* 判断给定的 dpif 是否为 netdev 类型（用户空间 datapath）。
 * 通过比较 open 函数指针来判断。 */
bool
dpif_is_netdev(const struct dpif *dpif)
{
    return dpif->dpif_class->open == dpif_netdev_open;
}

/* 将通用 dpif 指针向下转型为 dpif_netdev（类似 C++ 的 static_cast）。 */
static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif_is_netdev(dpif));
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

/* 从 dpif 指针获取底层的 dp_netdev 实例。 */
static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
}

/* PMD 信息查询类型枚举（用于 ovs-appctl dpif-netdev/pmd-* 命令）。 */
enum pmd_info_type {
    PMD_INFO_SHOW_STATS,  /* Show how cpu cycles are spent. */   /* 显示 CPU 周期统计 */
    PMD_INFO_CLEAR_STATS, /* Set the cycles count to 0. */       /* 清零统计 */
    PMD_INFO_SHOW_RXQ,    /* Show poll lists of pmd threads. */  /* 显示 RXQ 分配情况 */
    PMD_INFO_PERF_SHOW,   /* Show pmd performance details. */    /* 显示详细性能指标 */
    PMD_INFO_SLEEP_SHOW,  /* Show max sleep configuration details. */ /* 显示休眠配置 */
};

/* 格式化输出 PMD 线程标识信息（numa_id, core_id）。 */
static void
format_pmd_thread(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    ds_put_cstr(reply, (pmd->core_id == NON_PMD_CORE_ID)
                        ? "main thread" : "pmd thread");
    if (pmd->numa_id != OVS_NUMA_UNSPEC) {
        ds_put_format(reply, " numa_id %d", pmd->numa_id);
    }
    if (pmd->core_id != OVS_CORE_UNSPEC && pmd->core_id != NON_PMD_CORE_ID) {
        ds_put_format(reply, " core_id %u", pmd->core_id);
    }
    ds_put_cstr(reply, ":\n");
}

/* 显示 PMD 线程的统计信息（对应 dpif-netdev/pmd-stats-show 命令）。
 * 输出内容包括：收包数、recirculation 次数、各级缓存命中数、
 * upcall 成功/失败数、空闲/繁忙 CPU 周期比例等。 */
static void
pmd_info_show_stats(struct ds *reply,
                    struct dp_netdev_pmd_thread *pmd)
{
    uint64_t stats[PMD_N_STATS];
    uint64_t total_cycles, total_packets;
    double passes_per_pkt = 0;
    double lookups_per_hit = 0;
    double packets_per_batch = 0;

    pmd_perf_read_counters(&pmd->perf_stats, stats);
    total_cycles = stats[PMD_CYCLES_ITER_IDLE]
                         + stats[PMD_CYCLES_ITER_BUSY];
    total_packets = stats[PMD_STAT_RECV];

    format_pmd_thread(reply, pmd);

    if (total_packets > 0) {
        passes_per_pkt = (total_packets + stats[PMD_STAT_RECIRC])
                            / (double) total_packets;
    }
    if (stats[PMD_STAT_MASKED_HIT] > 0) {
        lookups_per_hit = stats[PMD_STAT_MASKED_LOOKUP]
                            / (double) stats[PMD_STAT_MASKED_HIT];
    }
    if (stats[PMD_STAT_SENT_BATCHES] > 0) {
        packets_per_batch = stats[PMD_STAT_SENT_PKTS]
                            / (double) stats[PMD_STAT_SENT_BATCHES];
    }

    ds_put_format(reply,
                  "  packets received: %"PRIu64"\n"
                  "  packet recirculations: %"PRIu64"\n"
                  "  avg. datapath passes per packet: %.02f\n"
                  "  phwol hits: %"PRIu64"\n"
                  "  mfex opt hits: %"PRIu64"\n"
                  "  simple match hits: %"PRIu64"\n"
                  "  emc hits: %"PRIu64"\n"
                  "  smc hits: %"PRIu64"\n"
                  "  megaflow hits: %"PRIu64"\n"
                  "  avg. subtable lookups per megaflow hit: %.02f\n"
                  "  miss with success upcall: %"PRIu64"\n"
                  "  miss with failed upcall: %"PRIu64"\n"
                  "  avg. packets per output batch: %.02f\n",
                  total_packets, stats[PMD_STAT_RECIRC],
                  passes_per_pkt, stats[PMD_STAT_PHWOL_HIT],
                  stats[PMD_STAT_MFEX_OPT_HIT],
                  stats[PMD_STAT_SIMPLE_HIT],
                  stats[PMD_STAT_EXACT_HIT],
                  stats[PMD_STAT_SMC_HIT],
                  stats[PMD_STAT_MASKED_HIT],
                  lookups_per_hit, stats[PMD_STAT_MISS], stats[PMD_STAT_LOST],
                  packets_per_batch);

    if (total_cycles == 0) {
        return;
    }

    ds_put_format(reply,
                  "  idle cycles: %"PRIu64" (%.02f%%)\n"
                  "  processing cycles: %"PRIu64" (%.02f%%)\n",
                  stats[PMD_CYCLES_ITER_IDLE],
                  stats[PMD_CYCLES_ITER_IDLE] / (double) total_cycles * 100,
                  stats[PMD_CYCLES_ITER_BUSY],
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_cycles * 100);

    if (total_packets == 0) {
        return;
    }

    ds_put_format(reply,
                  "  avg cycles per packet: %.02f (%"PRIu64"/%"PRIu64")\n",
                  total_cycles / (double) total_packets,
                  total_cycles, total_packets);

    ds_put_format(reply,
                  "  avg processing cycles per packet: "
                  "%.02f (%"PRIu64"/%"PRIu64")\n",
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_packets,
                  stats[PMD_CYCLES_ITER_BUSY], total_packets);
}

/* 显示 PMD 线程的详细性能指标（对应 dpif-netdev/pmd-perf-show 命令）。
 * 包括：整体统计、直方图分布、迭代历史、毫秒级历史等。 */
static void
pmd_info_show_perf(struct ds *reply,
                   struct dp_netdev_pmd_thread *pmd,
                   struct pmd_perf_params *par)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        char *time_str =
                xastrftime_msec("%H:%M:%S.###", time_wall_msec(), true);
        long long now = time_msec();
        double duration = (now - pmd->perf_stats.start_ms) / 1000.0;

        ds_put_cstr(reply, "\n");
        ds_put_format(reply, "Time: %s\n", time_str);
        ds_put_format(reply, "Measurement duration: %.3f s\n", duration);
        ds_put_cstr(reply, "\n");
        format_pmd_thread(reply, pmd);
        ds_put_cstr(reply, "\n");
        pmd_perf_format_overall_stats(reply, &pmd->perf_stats, duration);
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Prevent parallel clearing of perf metrics. */
            ovs_mutex_lock(&pmd->perf_stats.clear_mutex);
            if (par->histograms) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_histograms(reply, &pmd->perf_stats);
            }
            if (par->iter_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_iteration_history(reply, &pmd->perf_stats,
                        par->iter_hist_len);
            }
            if (par->ms_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_ms_history(reply, &pmd->perf_stats,
                        par->ms_hist_len);
            }
            ovs_mutex_unlock(&pmd->perf_stats.clear_mutex);
        }
        free(time_str);
    }
}

/* 比较函数：按端口名和队列 ID 排序 RXQ 轮询列表。 */
static int
compare_poll_list(const void *a_, const void *b_)
{
    const struct rxq_poll *a = a_;
    const struct rxq_poll *b = b_;

    const char *namea = netdev_rxq_get_name(a->rxq->rx);
    const char *nameb = netdev_rxq_get_name(b->rxq->rx);

    int cmp = strcmp(namea, nameb);
    if (!cmp) {
        return netdev_rxq_get_queue_id(a->rxq->rx)
               - netdev_rxq_get_queue_id(b->rxq->rx);
    } else {
        return cmp;
    }
}

/* 获取 PMD 线程的 RXQ 轮询列表并按名称排序（用于 show 命令输出）。 */
static void
sorted_poll_list(struct dp_netdev_pmd_thread *pmd, struct rxq_poll **list,
                 size_t *n)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct rxq_poll *ret, *poll;
    size_t i;

    *n = hmap_count(&pmd->poll_list);
    if (!*n) {
        ret = NULL;
    } else {
        ret = xcalloc(*n, sizeof *ret);
        i = 0;
        HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
            ret[i] = *poll;
            i++;
        }
        ovs_assert(i == *n);
        qsort(ret, *n, sizeof *ret, compare_poll_list);
    }

    *list = ret;
}

/* 显示 PMD 线程的 RXQ 分配和使用率（对应 dpif-netdev/pmd-rxq-show 命令）。
 * 输出每个 RXQ 的端口名、队列 ID、启用状态、PMD 使用率百分比。 */
static void
pmd_info_show_rxq(struct ds *reply, struct dp_netdev_pmd_thread *pmd,
                  int secs)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        struct rxq_poll *list;
        size_t n_rxq;
        uint64_t total_pmd_cycles = 0;
        uint64_t busy_pmd_cycles = 0;
        uint64_t total_rxq_proc_cycles = 0;
        unsigned int intervals;

        ds_put_format(reply,
                      "pmd thread numa_id %d core_id %u:\n  isolated : %s\n",
                      pmd->numa_id, pmd->core_id, (pmd->isolated)
                                                  ? "true" : "false");

        ovs_mutex_lock(&pmd->port_mutex);
        sorted_poll_list(pmd, &list, &n_rxq);

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_pmd_cycles);
        /* Calculate how many intervals are to be used. */
        intervals = DIV_ROUND_UP(secs,
                                 PMD_INTERVAL_LEN / INTERVAL_USEC_TO_SEC);
        /* Estimate the cycles to cover all intervals. */
        total_pmd_cycles *= intervals;
        busy_pmd_cycles = get_interval_values(pmd->busy_cycles_intrvl,
                                              &pmd->intrvl_idx,
                                              intervals);
        if (busy_pmd_cycles > total_pmd_cycles) {
            busy_pmd_cycles = total_pmd_cycles;
        }

        for (int i = 0; i < n_rxq; i++) {
            struct dp_netdev_rxq *rxq = list[i].rxq;
            const char *name = netdev_rxq_get_name(rxq->rx);
            uint64_t rxq_proc_cycles = 0;

            rxq_proc_cycles = get_interval_values(rxq->cycles_intrvl,
                                                  &rxq->intrvl_idx,
                                                  intervals);
            total_rxq_proc_cycles += rxq_proc_cycles;
            ds_put_format(reply, "  port: %-16s  queue-id: %2d", name,
                          netdev_rxq_get_queue_id(list[i].rxq->rx));
            ds_put_format(reply, " %s", netdev_rxq_enabled(list[i].rxq->rx)
                                        ? "(enabled) " : "(disabled)");
            ds_put_format(reply, "  pmd usage: ");
            if (total_pmd_cycles) {
                ds_put_format(reply, "%2.0f %%",
                              (double) (rxq_proc_cycles * 100) /
                              total_pmd_cycles);
            } else {
                ds_put_format(reply, "%s", "NOT AVAIL");
            }
            ds_put_cstr(reply, "\n");
        }

        if (n_rxq > 0) {
            ds_put_cstr(reply, "  overhead: ");
            if (total_pmd_cycles) {
                uint64_t overhead_cycles = 0;

                if (total_rxq_proc_cycles < busy_pmd_cycles) {
                    overhead_cycles = busy_pmd_cycles - total_rxq_proc_cycles;
                }

                ds_put_format(reply, "%2.0f %%",
                              (double) (overhead_cycles * 100) /
                              total_pmd_cycles);
            } else {
                ds_put_cstr(reply, "NOT AVAIL");
            }
            ds_put_cstr(reply, "\n");
        }

        ovs_mutex_unlock(&pmd->port_mutex);
        free(list);
    }
}

/* 比较函数：按 core_id 排序 PMD 线程列表。 */
static int
compare_poll_thread_list(const void *a_, const void *b_)
{
    const struct dp_netdev_pmd_thread *a, *b;

    a = *(struct dp_netdev_pmd_thread **)a_;
    b = *(struct dp_netdev_pmd_thread **)b_;

    if (a->core_id < b->core_id) {
        return -1;
    }
    if (a->core_id > b->core_id) {
        return 1;
    }
    return 0;
}

/* Create a sorted list of pmd's from the dp->poll_threads cmap. We can use
 * this list, as long as we do not go to quiescent state. */
static void
sorted_poll_thread_list(struct dp_netdev *dp,
                        struct dp_netdev_pmd_thread ***list,
                        size_t *n)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (k >= n_pmds) {
            break;
        }
        pmd_list[k++] = pmd;
    }

    qsort(pmd_list, k, sizeof *pmd_list, compare_poll_thread_list);

    *list = pmd_list;
    *n = k;
}

/* ovs-appctl dpif-netdev/subtable-lookup-info-get 回调：
 * 显示当前可用的子表查找函数及其优先级。 */
static void
dpif_netdev_subtable_lookup_get(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[] OVS_UNUSED,
                                void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;

    dpcls_impl_print_stats(&reply);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/* ovs-appctl dpif-netdev/subtable-lookup-prio-set 回调：
 * 设置指定子表查找函数的优先级，并重新探测所有 dpcls 实例。 */
static void
dpif_netdev_subtable_lookup_set(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[], void *aux OVS_UNUSED)
{
    /* This function requires 2 parameters (argv[1] and argv[2]) to execute.
     *   argv[1] is subtable name
     *   argv[2] is priority
     */
    const char *func_name = argv[1];

    errno = 0;
    char *err_char;
    uint32_t new_prio = strtoul(argv[2], &err_char, 10);
    uint32_t lookup_dpcls_changed = 0;
    uint32_t lookup_subtable_changed = 0;
    struct shash_node *node;
    if (errno != 0 || new_prio > UINT8_MAX) {
        unixctl_command_reply_error(conn,
            "error converting priority, use integer in range 0-255\n");
        return;
    }

    int32_t err = dpcls_subtable_set_prio(func_name, new_prio);
    if (err) {
        unixctl_command_reply_error(conn,
            "error, subtable lookup function not found\n");
        return;
    }

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;

        /* Get PMD threads list, required to get DPCLS instances. */
        size_t n;
        struct dp_netdev_pmd_thread **pmd_list;
        sorted_poll_thread_list(dp, &pmd_list, &n);

        /* take port mutex as HMAP iters over them. */
        ovs_rwlock_rdlock(&dp->port_rwlock);

        for (size_t i = 0; i < n; i++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[i];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            struct dp_netdev_port *port = NULL;
            HMAP_FOR_EACH (port, node, &dp->ports) {
                odp_port_t in_port = port->port_no;
                struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
                if (!cls) {
                    continue;
                }
                ovs_mutex_lock(&pmd->flow_mutex);
                uint32_t subtbl_changes = dpcls_subtable_lookup_reprobe(cls);
                ovs_mutex_unlock(&pmd->flow_mutex);
                if (subtbl_changes) {
                    lookup_dpcls_changed++;
                    lookup_subtable_changed += subtbl_changes;
                }
            }
        }

        /* release port mutex before netdev mutex. */
        ovs_rwlock_unlock(&dp->port_rwlock);
        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    struct ds reply = DS_EMPTY_INITIALIZER;
    ds_put_format(&reply,
        "Lookup priority change affected %d dpcls ports and %d subtables.\n",
        lookup_dpcls_changed, lookup_subtable_changed);
    const char *reply_str = ds_cstr(&reply);
    unixctl_command_reply(conn, reply_str);
    VLOG_INFO("%s", reply_str);
    ds_destroy(&reply);
}

/* ovs-appctl dpif-netdev/dpif-impl-get 回调：
 * 显示当前各 PMD 线程使用的 DPIF 实现（如 dpif_netdev_input）。 */
static void
dpif_netdev_impl_get(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev_pmd_thread **pmd_list;
        struct dp_netdev *dp = node->data;
        size_t n;

        /* Get PMD threads list, required to get the DPIF impl used by each PMD
         * thread. */
        sorted_poll_thread_list(dp, &pmd_list, &n);
        dp_netdev_impl_get(&reply, pmd_list, n);
        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/* ovs-appctl dpif-netdev/dpif-impl-set 回调：
 * 设置 DPIF 实现（如切换到 AVX512 优化的输入处理函数）。 */
static void
dpif_netdev_impl_set(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[], void *aux OVS_UNUSED)
{
    /* This function requires just one parameter, the DPIF name. */
    const char *dpif_name = argv[1];
    struct shash_node *node;

    static const char *error_description[2] = {
        "Unknown DPIF implementation",
        "CPU doesn't support the required instruction for",
    };

    ovs_mutex_lock(&dp_netdev_mutex);
    int32_t err = dp_netdev_impl_set_default_by_name(dpif_name);

    if (err) {
        struct ds reply = DS_EMPTY_INITIALIZER;
        ds_put_format(&reply, "DPIF implementation not available: %s %s.\n",
                      error_description[ (err == -ENOTSUP) ], dpif_name);
        const char *reply_str = ds_cstr(&reply);
        unixctl_command_reply_error(conn, reply_str);
        VLOG_ERR("%s", reply_str);
        ds_destroy(&reply);
        ovs_mutex_unlock(&dp_netdev_mutex);
        return;
    }

    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;

        /* Get PMD threads list, required to get DPCLS instances. */
        size_t n;
        struct dp_netdev_pmd_thread **pmd_list;
        sorted_poll_thread_list(dp, &pmd_list, &n);

        for (size_t i = 0; i < n; i++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[i];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            /* Initialize DPIF function pointer to the newly configured
             * default. */
            atomic_store_relaxed(&pmd->netdev_input_func,
                                 dp_netdev_impl_get_default());
        };

        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    /* Reply with success to command. */
    struct ds reply = DS_EMPTY_INITIALIZER;
    ds_put_format(&reply, "DPIF implementation set to %s.\n", dpif_name);
    const char *reply_str = ds_cstr(&reply);
    unixctl_command_reply(conn, reply_str);
    VLOG_INFO("%s", reply_str);
    ds_destroy(&reply);
}

/* ovs-appctl dpif-netdev/miniflow-parser-get 回调：
 * 显示各 PMD 线程当前使用的 miniflow 提取实现。 */
static void
dpif_miniflow_extract_impl_get(struct unixctl_conn *conn, int argc OVS_UNUSED,
                               const char *argv[] OVS_UNUSED,
                               void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev_pmd_thread **pmd_list;
        struct dp_netdev *dp = node->data;
        size_t n;

        /* Get PMD threads list, required to get the DPIF impl used by each PMD
         * thread. */
        sorted_poll_thread_list(dp, &pmd_list, &n);
        dp_mfex_impl_get(&reply, pmd_list, n);
        free(pmd_list);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/* ovs-appctl dpif-netdev/miniflow-parser-set 回调：
 * 设置 miniflow 提取实现（如 study 模式自动学习最优实现，
 * 或手动指定 AVX512 等优化实现）。支持 -pmd 参数指定单个 PMD。 */
static void
dpif_miniflow_extract_impl_set(struct unixctl_conn *conn, int argc,
                               const char *argv[], void *aux OVS_UNUSED)
{
    /* This command takes some optional and mandatory arguments. The function
     * here first parses all of the options, saving results in local variables.
     * Then the parsed values are acted on.
     */
    unsigned int pmd_thread_to_change = NON_PMD_CORE_ID;
    unsigned int study_count = MFEX_MAX_PKT_COUNT;
    struct ds reply = DS_EMPTY_INITIALIZER;
    bool pmd_thread_update_done = false;
    bool mfex_name_is_study = false;
    const char *mfex_name = NULL;
    const char *reply_str = NULL;
    struct shash_node *node;
    int err;

    while (argc > 1) {
        /* Optional argument "-pmd" limits the commands actions to just this
         * PMD thread.
         */
        if ((!strcmp(argv[1], "-pmd") && !mfex_name)) {
            if (argc < 3) {
                ds_put_format(&reply,
                              "Error: -pmd option requires a thread id"
                              " argument.\n");
                goto error;
            }

            /* Ensure argument can be parsed to an integer. */
            if (!str_to_uint(argv[2], 10, &pmd_thread_to_change) ||
                (pmd_thread_to_change == NON_PMD_CORE_ID)) {
                ds_put_format(&reply,
                              "Error: miniflow extract parser not changed,"
                              " PMD thread passed is not valid: '%s'."
                              " Pass a valid pmd thread ID.\n",
                              argv[2]);
                goto error;
            }

            argc -= 2;
            argv += 2;

        } else if (!mfex_name) {
            /* Name of MFEX impl requested by user. */
            mfex_name = argv[1];
            mfex_name_is_study = strcmp("study", mfex_name) == 0;
            argc -= 1;
            argv += 1;

        /* If name is study and more args exist, parse study_count value. */
        } else if (mfex_name && mfex_name_is_study) {
            if (!str_to_uint(argv[1], 10, &study_count) ||
                (study_count == 0)) {
                ds_put_format(&reply,
                              "Error: invalid study_pkt_cnt value: %s.\n",
                              argv[1]);
                goto error;
            }

            argc -= 1;
            argv += 1;
        } else {
            ds_put_format(&reply, "Error: unknown argument %s.\n", argv[1]);
            goto error;
        }
    }

    /* Ensure user passed an MFEX name. */
    if (!mfex_name) {
        ds_put_format(&reply, "Error: no miniflow extract name provided."
                      " Output of miniflow-parser-get shows implementation"
                      " list.\n");
        goto error;
    }

    /* If the MFEX name is "study", set the study packet count. */
    if (mfex_name_is_study) {
        err = mfex_set_study_pkt_cnt(study_count, mfex_name);
        if (err) {
            ds_put_format(&reply, "Error: failed to set study count %d for"
                          " miniflow extract implementation %s.\n",
                          study_count, mfex_name);
            goto error;
        }
    }

    /* Set the default MFEX impl only if the command was applied to all PMD
     * threads. If a PMD thread was selected, do NOT update the default.
     */
    if (pmd_thread_to_change == NON_PMD_CORE_ID) {
        err = dp_mfex_impl_set_default_by_name(mfex_name);
        if (err == -ENODEV) {
            ds_put_format(&reply,
                          "Error: miniflow extract not available due to CPU"
                          " ISA requirements: %s",
                          mfex_name);
            goto error;
        } else if (err) {
            ds_put_format(&reply,
                          "Error: unknown miniflow extract implementation %s.",
                          mfex_name);
            goto error;
        }
    }

    /* Get the desired MFEX function pointer and error check its usage. */
    miniflow_extract_func mfex_func = NULL;
    err = dp_mfex_impl_get_by_name(mfex_name, &mfex_func);
    if (err) {
        if (err == -ENODEV) {
            ds_put_format(&reply,
                          "Error: miniflow extract not available due to CPU"
                          " ISA requirements: %s", mfex_name);
        } else {
            ds_put_format(&reply,
                          "Error: unknown miniflow extract implementation %s.",
                          mfex_name);
        }
        goto error;
    }

    /* Apply the MFEX pointer to each pmd thread in each netdev, filtering
     * by the users "-pmd" argument if required.
     */
    ovs_mutex_lock(&dp_netdev_mutex);

    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev_pmd_thread **pmd_list;
        struct dp_netdev *dp = node->data;
        size_t n;

        sorted_poll_thread_list(dp, &pmd_list, &n);

        for (size_t i = 0; i < n; i++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[i];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            /* If -pmd specified, skip all other pmd threads. */
            if ((pmd_thread_to_change != NON_PMD_CORE_ID) &&
                (pmd->core_id != pmd_thread_to_change)) {
                continue;
            }

            pmd_thread_update_done = true;
            atomic_store_relaxed(&pmd->miniflow_extract_opt, mfex_func);
        };

        free(pmd_list);
    }

    ovs_mutex_unlock(&dp_netdev_mutex);

    /* If PMD thread was specified, but it wasn't found, return error. */
    if (pmd_thread_to_change != NON_PMD_CORE_ID && !pmd_thread_update_done) {
        ds_put_format(&reply,
                      "Error: miniflow extract parser not changed, "
                      "PMD thread %d not in use, pass a valid pmd"
                      " thread ID.\n", pmd_thread_to_change);
        goto error;
    }

    /* Reply with success to command. */
    ds_put_format(&reply, "Miniflow extract implementation set to %s",
                  mfex_name);
    if (pmd_thread_to_change != NON_PMD_CORE_ID) {
        ds_put_format(&reply, ", on pmd thread %d", pmd_thread_to_change);
    }
    if (mfex_name_is_study) {
        ds_put_format(&reply, ", studying %d packets", study_count);
    }
    ds_put_format(&reply, ".\n");

    reply_str = ds_cstr(&reply);
    VLOG_INFO("%s", reply_str);
    unixctl_command_reply(conn, reply_str);
    ds_destroy(&reply);
    return;

error:
    reply_str = ds_cstr(&reply);
    VLOG_ERR("%s", reply_str);
    unixctl_command_reply_error(conn, reply_str);
    ds_destroy(&reply);
}

/* ovs-appctl dpif-netdev/pmd-rxq-rebalance 回调：
 * 手动触发 RXQ 在 PMD 线程间的重新分配。 */
static void
dpif_netdev_pmd_rebalance(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

    ovs_mutex_lock(&dp_netdev_mutex);

    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath */
        dp = shash_first(&dp_netdevs)->data;
    }

    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    dp_netdev_request_reconfigure(dp);
    ovs_mutex_unlock(&dp_netdev_mutex);
    ds_put_cstr(&reply, "pmd rxq rebalance requested.\n");
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/* 格式化输出 PMD 线程的休眠配置信息。 */
static void
pmd_info_show_sleep(struct ds *reply, unsigned core_id, int numa_id,
                    uint64_t pmd_max_sleep)
{
    if (core_id == NON_PMD_CORE_ID) {
        return;
    }
    ds_put_format(reply,
                  "pmd thread numa_id %d core_id %d:\n"
                  "  max sleep: %4"PRIu64" us\n",
                  numa_id, core_id, pmd_max_sleep);
}

/* PMD 信息统一入口函数（被多个 appctl 命令共用）。
 * 根据 aux 参数中的 pmd_info_type 分发到不同的处理分支：
 * stats-show / stats-clear / rxq-show / perf-show / sleep-show。
 * 支持 -pmd 过滤指定核心、-secs 指定统计时间窗口。 */
static void
dpif_netdev_pmd_info(struct unixctl_conn *conn, int argc, const char *argv[],
                     void *aux)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev_pmd_thread **pmd_list;
    struct dp_netdev *dp = NULL;
    enum pmd_info_type type = *(enum pmd_info_type *) aux;
    unsigned int core_id;
    bool filter_on_pmd = false;
    size_t n;
    unsigned int secs = 0;
    unsigned long long max_secs = (PMD_INTERVAL_LEN * PMD_INTERVAL_MAX)
                                      / INTERVAL_USEC_TO_SEC;
    bool show_header = true;
    uint64_t max_sleep;

    ovs_mutex_lock(&dp_netdev_mutex);

    while (argc > 1) {
        if (!strcmp(argv[1], "-pmd") && argc > 2) {
            if (str_to_uint(argv[2], 10, &core_id)) {
                filter_on_pmd = true;
            }
            argc -= 2;
            argv += 2;
        } else if (type == PMD_INFO_SHOW_RXQ &&
                       !strcmp(argv[1], "-secs") &&
                       argc > 2) {
            if (!str_to_uint(argv[2], 10, &secs)) {
                secs = max_secs;
            }
            argc -= 2;
            argv += 2;
        } else {
            dp = shash_find_data(&dp_netdevs, argv[1]);
            argc -= 1;
            argv += 1;
        }
    }

    if (!dp) {
        if (shash_count(&dp_netdevs) == 1) {
            /* There's only one datapath */
            dp = shash_first(&dp_netdevs)->data;
        } else {
            ovs_mutex_unlock(&dp_netdev_mutex);
            unixctl_command_reply_error(conn,
                                        "please specify an existing datapath");
            return;
        }
    }

    sorted_poll_thread_list(dp, &pmd_list, &n);
    for (size_t i = 0; i < n; i++) {
        struct dp_netdev_pmd_thread *pmd = pmd_list[i];
        if (!pmd) {
            break;
        }
        if (filter_on_pmd && pmd->core_id != core_id) {
            continue;
        }
        if (type == PMD_INFO_SHOW_RXQ) {
            if (show_header) {
                if (!secs || secs > max_secs) {
                    secs = max_secs;
                } else {
                    secs = ROUND_UP(secs,
                                    PMD_INTERVAL_LEN / INTERVAL_USEC_TO_SEC);
                }
                ds_put_format(&reply, "Displaying last %u seconds "
                              "pmd usage %%\n", secs);
                show_header = false;
            }
            pmd_info_show_rxq(&reply, pmd, secs);
        } else if (type == PMD_INFO_CLEAR_STATS) {
            pmd_perf_stats_clear(&pmd->perf_stats);
        } else if (type == PMD_INFO_SHOW_STATS) {
            pmd_info_show_stats(&reply, pmd);
        } else if (type == PMD_INFO_PERF_SHOW) {
            pmd_info_show_perf(&reply, pmd, (struct pmd_perf_params *)aux);
        } else if (type == PMD_INFO_SLEEP_SHOW) {
            if (show_header) {
                ds_put_format(&reply, "Default max sleep: %4"PRIu64" us\n",
                              dp->pmd_max_sleep_default);
                show_header = false;
            }
            atomic_read_relaxed(&pmd->max_sleep, &max_sleep);
            pmd_info_show_sleep(&reply, pmd->core_id, pmd->numa_id,
                                max_sleep);
        }
    }
    free(pmd_list);

    ovs_mutex_unlock(&dp_netdev_mutex);

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/* ovs-appctl dpif-netdev/pmd-perf-show 命令解析。
 * 解析 -nh（不显示直方图）、-it（迭代历史长度）、-ms（毫秒历史长度）参数。 */
static void
pmd_perf_show_cmd(struct unixctl_conn *conn, int argc,
                          const char *argv[],
                          void *aux OVS_UNUSED)
{
    struct pmd_perf_params par;
    long int it_hist = 0, ms_hist = 0;
    par.histograms = true;

    while (argc > 1) {
        if (!strcmp(argv[1], "-nh")) {
            par.histograms = false;
            argc -= 1;
            argv += 1;
        } else if (!strcmp(argv[1], "-it") && argc > 2) {
            it_hist = strtol(argv[2], NULL, 10);
            if (it_hist < 0) {
                it_hist = 0;
            } else if (it_hist > HISTORY_LEN) {
                it_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-ms") && argc > 2) {
            ms_hist = strtol(argv[2], NULL, 10);
            if (ms_hist < 0) {
                ms_hist = 0;
            } else if (ms_hist > HISTORY_LEN) {
                ms_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else {
            break;
        }
    }
    par.iter_hist_len = it_hist;
    par.ms_hist_len = ms_hist;
    par.command_type = PMD_INFO_PERF_SHOW;
    dpif_netdev_pmd_info(conn, argc, argv, &par);
}

/* ovs-appctl dpif-netdev/bond-show 回调：
 * 显示数据路径中所有 bond 的哈希桶到成员端口的映射关系。 */
static void
dpif_netdev_bond_show(struct unixctl_conn *conn, int argc,
                      const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

    ovs_mutex_lock(&dp_netdev_mutex);
    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath. */
        dp = shash_first(&dp_netdevs)->data;
    }
    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    if (cmap_count(&dp->tx_bonds) > 0) {
        struct tx_bond *dp_bond_entry;

        ds_put_cstr(&reply, "Bonds:\n");
        CMAP_FOR_EACH (dp_bond_entry, node, &dp->tx_bonds) {
            ds_put_format(&reply, "  bond-id %"PRIu32":\n",
                          dp_bond_entry->bond_id);
            for (int bucket = 0; bucket < BOND_BUCKETS; bucket++) {
                uint32_t member_id = odp_to_u32(
                    dp_bond_entry->member_buckets[bucket].member_id);
                ds_put_format(&reply,
                              "    bucket %d - member %"PRIu32"\n",
                              bucket, member_id);
            }
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

/* @veencn_260223: Latency appctl command callbacks. */

static const char *latency_hist_labels[LATENCY_HIST_BUCKETS] = {
    "<100ns", "100-200ns", "200-500ns", "500ns-1us",
    "1-10us", "10-100us", ">=100us"
};

static void
latency_stage_format(struct ds *reply, const char *name,
                     const struct latency_stage_stats *stage)
{
    if (stage->count == 0) {
        ds_put_format(reply, "  %-20s  (no data)\n", name);
        return;
    }
    uint64_t avg_ns = latency_cycles_to_ns(stage->total_cycles / stage->count);
    uint64_t min_ns = latency_cycles_to_ns(stage->min_cycles);
    uint64_t max_ns = latency_cycles_to_ns(stage->max_cycles);

    ds_put_format(reply,
                  "  %-20s  cnt: %10"PRIu64
                  "  avg: %6"PRIu64" ns"
                  "  min: %6"PRIu64" ns"
                  "  max: %6"PRIu64" ns\n",
                  name, stage->count, avg_ns, min_ns, max_ns);
}

static void
latency_hist_format(struct ds *reply, const char *name,
                    const struct latency_stage_stats *stage)
{
    if (stage->count == 0) {
        return;
    }
    ds_put_format(reply, "  %s:\n", name);
    for (int b = 0; b < LATENCY_HIST_BUCKETS; b++) {
        if (stage->histogram[b] == 0) {
            continue;
        }
        double pct = 100.0 * stage->histogram[b] / stage->count;
        int bar_len = (int)(pct / 2.0);
        if (bar_len > 50) {
            bar_len = 50;
        }
        char bar[52];
        memset(bar, '#', bar_len);
        bar[bar_len] = '\0';
        ds_put_format(reply, "    %-12s %10"PRIu64" (%5.1f%%) %s\n",
                      latency_hist_labels[b],
                      stage->histogram[b], pct, bar);
    }
}

/* Helper: find the single datapath. */
static struct dp_netdev *
latency_get_dp(struct unixctl_conn *conn, int *argc, const char **argv[])
{
    struct dp_netdev *dp = NULL;

    while (*argc > 1) {
        if (!strcmp((*argv)[1], "-pmd") && *argc > 2) {
            *argc -= 2;
            *argv += 2;
        } else {
            dp = shash_find_data(&dp_netdevs, (*argv)[1]);
            *argc -= 1;
            *argv += 1;
        }
    }
    if (!dp) {
        if (shash_count(&dp_netdevs) == 1) {
            dp = shash_first(&dp_netdevs)->data;
        } else {
            unixctl_command_reply_error(conn,
                "please specify an existing datapath");
        }
    }
    return dp;
}

static void
dpif_netdev_latency_show(struct unixctl_conn *conn,
                         int argc, const char *argv[],
                         void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    unsigned int filter_core = UINT_MAX;
    size_t n;

    /* Parse -pmd core before finding dp. */
    for (int a = 1; a + 1 < argc; a++) {
        if (!strcmp(argv[a], "-pmd")) {
            str_to_uint(argv[a + 1], 10, &filter_core);
            break;
        }
    }

    ovs_mutex_lock(&dp_netdev_mutex);
    struct dp_netdev *dp = latency_get_dp(conn, &argc, &argv);
    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        return;
    }

    struct dp_netdev_pmd_thread **pmd_list;
    sorted_poll_thread_list(dp, &pmd_list, &n);
    for (size_t i = 0; i < n; i++) {
        struct dp_netdev_pmd_thread *pmd = pmd_list[i];
        if (!pmd) {
            break;
        }
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        if (filter_core != UINT_MAX && pmd->core_id != filter_core) {
            continue;
        }

        struct pmd_latency_stats *ls = &pmd->latency_stats;
        ds_put_format(&reply,
            "pmd thread numa_id %d core_id %u (latency: %s):\n",
            pmd->numa_id, pmd->core_id,
            ls->enabled ? "enabled" : "disabled");

        if (!ls->enabled && ls->total.count == 0) {
            ds_put_format(&reply, "  (no data collected)\n\n");
            continue;
        }

        ds_put_format(&reply,
            "  Hits: EMC=%"PRIu64" SMC=%"PRIu64
            " dpcls=%"PRIu64" upcall=%"PRIu64"\n",
            ls->emc_hit_count, ls->smc_hit_count,
            ls->dpcls_hit_count, ls->upcall_count);
        ds_put_format(&reply,
            "  %-20s  %10s  %10s  %10s  %10s\n",
            "Stage", "count", "avg(ns)", "min(ns)", "max(ns)");
        ds_put_format(&reply,
            "  %-20s  %10s  %10s  %10s  %10s\n",
            "--------------------", "----------",
            "----------", "----------", "----------");
        latency_stage_format(&reply, "miniflow extract", &ls->miniflow);
        latency_stage_format(&reply, "EMC lookup", &ls->emc_lookup);
        latency_stage_format(&reply, "SMC lookup", &ls->smc_lookup);
        latency_stage_format(&reply, "dpcls lookup", &ls->dpcls_lookup);
        latency_stage_format(&reply, "upcall", &ls->upcall);
        latency_stage_format(&reply, "action exec", &ls->action_exec);
        ds_put_format(&reply,
            "  %-20s  %10s  %10s  %10s  %10s\n",
            "--------------------", "----------",
            "----------", "----------", "----------");
        latency_stage_format(&reply, "TOTAL", &ls->total);
        ds_put_cstr(&reply, "\n");
    }
    free(pmd_list);
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_latency_hist(struct unixctl_conn *conn,
                         int argc, const char *argv[],
                         void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    unsigned int filter_core = UINT_MAX;
    size_t n;

    for (int a = 1; a + 1 < argc; a++) {
        if (!strcmp(argv[a], "-pmd")) {
            str_to_uint(argv[a + 1], 10, &filter_core);
            break;
        }
    }

    ovs_mutex_lock(&dp_netdev_mutex);
    struct dp_netdev *dp = latency_get_dp(conn, &argc, &argv);
    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        return;
    }

    struct dp_netdev_pmd_thread **pmd_list;
    sorted_poll_thread_list(dp, &pmd_list, &n);
    for (size_t i = 0; i < n; i++) {
        struct dp_netdev_pmd_thread *pmd = pmd_list[i];
        if (!pmd) {
            break;
        }
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        if (filter_core != UINT_MAX && pmd->core_id != filter_core) {
            continue;
        }

        struct pmd_latency_stats *ls = &pmd->latency_stats;
        ds_put_format(&reply, "pmd thread numa_id %d core_id %u:\n",
                      pmd->numa_id, pmd->core_id);
        /* @veencn_260223: Check if any stage has data. */
        if (ls->miniflow.count == 0 && ls->emc_lookup.count == 0
            && ls->smc_lookup.count == 0 && ls->dpcls_lookup.count == 0
            && ls->upcall.count == 0 && ls->action_exec.count == 0) {
            ds_put_format(&reply, "  (no data)\n\n");
            continue;
        }
        latency_hist_format(&reply, "miniflow extract", &ls->miniflow);
        latency_hist_format(&reply, "EMC lookup", &ls->emc_lookup);
        latency_hist_format(&reply, "SMC lookup", &ls->smc_lookup);
        latency_hist_format(&reply, "dpcls lookup", &ls->dpcls_lookup);
        latency_hist_format(&reply, "upcall", &ls->upcall);
        latency_hist_format(&reply, "action exec", &ls->action_exec);
        latency_hist_format(&reply, "TOTAL", &ls->total);
        ds_put_cstr(&reply, "\n");
    }
    free(pmd_list);
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_latency_clear(struct unixctl_conn *conn,
                          int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED,
                          void *aux OVS_UNUSED)
{
    ovs_mutex_lock(&dp_netdev_mutex);
    struct shash_node *node;
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        struct dp_netdev_pmd_thread *pmd;
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            latency_stats_clear(&pmd->latency_stats);
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, "latency stats cleared\n");
}

static void
dpif_netdev_latency_set(struct unixctl_conn *conn,
                        int argc OVS_UNUSED,
                        const char *argv[],
                        void *aux OVS_UNUSED)
{
    bool enable;
    if (!strcmp(argv[1], "enabled")) {
        enable = true;
    } else if (!strcmp(argv[1], "disabled")) {
        enable = false;
    } else {
        unixctl_command_reply_error(conn,
            "usage: dpif-netdev/latency-set enabled|disabled");
        return;
    }

    ovs_mutex_lock(&dp_netdev_mutex);
    struct shash_node *node;
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        struct dp_netdev_pmd_thread *pmd;
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (enable && !pmd->latency_stats.enabled) {
                latency_stats_clear(&pmd->latency_stats);
            }
            pmd->latency_stats.enabled = enable;
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, enable
        ? "latency measurement enabled (stats cleared)\n"
        : "latency measurement disabled\n");
}
/* @veencn_260223 end: latency appctl callbacks */

/* dpif_netdev_init — 模块初始化函数。
 * 注册所有 ovs-appctl 控制命令，包括：
 * - pmd-stats-show/clear：PMD 统计查看/清零
 * - pmd-rxq-show：RXQ 分配和使用率
 * - pmd-perf-show：PMD 详细性能指标
 * - pmd-rxq-rebalance：手动触发 RXQ 重分配
 * - subtable-lookup-*：子表查找函数管理
 * - dpif-impl-*：DPIF 实现切换
 * - miniflow-parser-*：miniflow 提取函数管理
 * - latency-*：延迟测量命令
 * 在 OVS 启动时由 dpif 框架调用一次。 */
static int
dpif_netdev_init(void)
{
    static enum pmd_info_type show_aux = PMD_INFO_SHOW_STATS,
                              clear_aux = PMD_INFO_CLEAR_STATS,
                              poll_aux = PMD_INFO_SHOW_RXQ,
                              sleep_aux = PMD_INFO_SLEEP_SHOW;

    unixctl_command_register("dpif-netdev/pmd-stats-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&show_aux);
    unixctl_command_register("dpif-netdev/pmd-stats-clear", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&clear_aux);
    unixctl_command_register("dpif-netdev/pmd-rxq-show", "[-pmd core] "
                             "[-secs secs] [dp]",
                             0, 5, dpif_netdev_pmd_info,
                             (void *)&poll_aux);
    unixctl_command_register("dpif-netdev/pmd-sleep-show", "[dp]",
                             0, 1, dpif_netdev_pmd_info,
                             (void *)&sleep_aux);
    unixctl_command_register("dpif-netdev/pmd-perf-show",
                             "[-nh] [-it iter-history-len]"
                             " [-ms ms-history-len]"
                             " [-pmd core] [dp]",
                             0, 8, pmd_perf_show_cmd,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-rxq-rebalance", "[dp]",
                             0, 1, dpif_netdev_pmd_rebalance,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-perf-log-set",
                             "on|off [-b before] [-a after] [-e|-ne] "
                             "[-us usec] [-q qlen]",
                             0, 10, pmd_perf_log_set_cmd,
                             NULL);
    unixctl_command_register("dpif-netdev/bond-show", "[dp]",
                             0, 1, dpif_netdev_bond_show,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-prio-set",
                             "[lookup_func] [prio]",
                             2, 2, dpif_netdev_subtable_lookup_set,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-info-get", "",
                             0, 0, dpif_netdev_subtable_lookup_get,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-prio-get", NULL,
                             0, 0, dpif_netdev_subtable_lookup_get,
                             NULL);
    unixctl_command_register("dpif-netdev/dpif-impl-set",
                             "dpif_implementation_name",
                             1, 1, dpif_netdev_impl_set,
                             NULL);
    unixctl_command_register("dpif-netdev/dpif-impl-get", "",
                             0, 0, dpif_netdev_impl_get,
                             NULL);
    unixctl_command_register("dpif-netdev/miniflow-parser-set",
                             "[-pmd core] miniflow_implementation_name"
                             " [study_pkt_cnt]",
                             1, 5, dpif_miniflow_extract_impl_set,
                             NULL);
    unixctl_command_register("dpif-netdev/miniflow-parser-get", "",
                             0, 0, dpif_miniflow_extract_impl_get,
                             NULL);

    /* @veencn_260223: Register latency measurement commands. */
    unixctl_command_register("dpif-netdev/latency-show", "[-pmd core]",
                             0, 2, dpif_netdev_latency_show, NULL);
    unixctl_command_register("dpif-netdev/latency-hist", "[-pmd core]",
                             0, 2, dpif_netdev_latency_hist, NULL);
    unixctl_command_register("dpif-netdev/latency-clear", "",
                             0, 0, dpif_netdev_latency_clear, NULL);
    unixctl_command_register("dpif-netdev/latency-set", "enabled|disabled",
                             1, 1, dpif_netdev_latency_set, NULL);

    return 0;
}

/* 枚举所有属于给定 dpif_class 的 datapath 名称。 */
static int
dpif_netdev_enumerate(struct sset *all_dps,
                      const struct dpif_class *dpif_class)
{
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH(node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        if (dpif_class != dp->class) {
            /* 'dp_netdevs' contains both "netdev" and "dummy" dpifs.
             * If the class doesn't match, skip this dpif. */
             continue;
        }
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

/* 判断 dpif class 是否为 dummy（测试用）类型。 */
static bool
dpif_netdev_class_is_dummy(const struct dpif_class *class)
{
    return class != &dpif_netdev_class;
}

/* 将端口类型转换为底层实际类型。
 * "internal" 在真实 datapath 中映射为 "tap"，在 dummy 中映射为 "dummy-internal"。 */
static const char *
dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)
{
    return strcmp(type, "internal") ? type
                  : dpif_netdev_class_is_dummy(class) ? "dummy-internal"
                  : "tap";
}

/* 创建 dpif_netdev 接口实例并初始化。
 * 增加 dp 的引用计数，返回通用 dpif 指针供上层使用。 */
static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_netdev *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

/* Choose an unused, non-zero port number and return it on success.
 * Return ODPP_NONE on failure. */
static odp_port_t
choose_port(struct dp_netdev *dp, const char *name)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    uint32_t port_no;

    if (dp->class != &dpif_netdev_class) {
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */
        if (!strncmp(name, "br", 2)) {
            start_no = 100;
        }

        /* If the port name contains a number, try to assign that port number.
         * This can make writing unit tests easier because port numbers are
         * predictable. */
        for (p = name; *p != '\0'; p++) {
            if (isdigit((unsigned char) *p)) {
                port_no = start_no + strtol(p, NULL, 10);
                if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE)
                    && !dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
                    return u32_to_odp(port_no);
                }
                break;
            }
        }
    }

    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

/* 计算 meter ID 的哈希值。直接使用 meter_id 作为哈希值，
 * 因为 ofproto-dpif 层的 id-pool 保证了连续分配。 */
static uint32_t
dp_meter_hash(uint32_t meter_id)
{
    /* In the ofproto-dpif layer, we use the id-pool to alloc meter id
     * orderly (e.g. 1, 2, ... N.), which provides a better hash
     * distribution.  Use them directly instead of hash_xxx function for
     * achieving high-performance. */
    return meter_id;
}

/* 销毁 datapath 的所有 meter 资源。 */
static void
dp_netdev_meter_destroy(struct dp_netdev *dp)
{
    struct dp_meter *m;

    ovs_mutex_lock(&dp->meters_lock);
    CMAP_FOR_EACH (m, node, &dp->meters) {
        cmap_remove(&dp->meters, &m->node, dp_meter_hash(m->id));
        ovsrcu_postpone(free, m);
    }

    cmap_destroy(&dp->meters);
    ovs_mutex_unlock(&dp->meters_lock);
    ovs_mutex_destroy(&dp->meters_lock);
}

/* 按 meter_id 在 cmap 中查找 meter。 */
static struct dp_meter *
dp_meter_lookup(struct cmap *meters, uint32_t meter_id)
{
    uint32_t hash = dp_meter_hash(meter_id);
    struct dp_meter *m;

    CMAP_FOR_EACH_WITH_HASH (m, node, hash, meters) {
        if (m->id == meter_id) {
            return m;
        }
    }

    return NULL;
}

/* 从 cmap 中移除指定 meter 并通过 RCU 延迟释放。 */
static void
dp_meter_detach_free(struct cmap *meters, uint32_t meter_id)
{
    struct dp_meter *m = dp_meter_lookup(meters, meter_id);

    if (m) {
        cmap_remove(meters, &m->node, dp_meter_hash(meter_id));
        ovsrcu_postpone(free, m);
    }
}

/* 将 meter 插入 cmap。 */
static void
dp_meter_attach(struct cmap *meters, struct dp_meter *meter)
{
    cmap_insert(meters, &meter->node, dp_meter_hash(meter->id));
}

/* 创建并初始化一个新的 dp_netdev 数据路径实例。
 * 初始化所有子系统：端口哈希表、meter、conntrack、PMD 线程池、
 * TX 队列 ID 池、non-PMD 线程等。并添加一个 internal 类型的本地端口。
 * 首次调用时还会校准 TSC 频率（用于性能计数）。 */
static int
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    static struct ovsthread_once tsc_freq_check = OVSTHREAD_ONCE_INITIALIZER;
    struct dp_netdev *dp;
    int error;

    /* Avoid estimating TSC frequency for dummy datapath to not slow down
     * unit tests. */
    if (!dpif_netdev_class_is_dummy(class)
        && ovsthread_once_start(&tsc_freq_check)) {
        pmd_perf_estimate_tsc_frequency();
        ovsthread_once_done(&tsc_freq_check);
    }

    dp = xzalloc(sizeof *dp);
    shash_add(&dp_netdevs, name, dp);

    *CONST_CAST(const struct dpif_class **, &dp->class) = class;
    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    *CONST_CAST(const char **, &dp->full_name) = xasprintf("%s@%s",
                                                           class->type, name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_clear(&dp->destroyed);

    ovs_rwlock_init(&dp->port_rwlock);
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();
    ovs_mutex_init(&dp->bond_mutex);
    cmap_init(&dp->tx_bonds);

    fat_rwlock_init(&dp->upcall_rwlock);

    dp->reconfigure_seq = seq_create();
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Init meter resources. */
    cmap_init(&dp->meters);
    ovs_mutex_init(&dp->meters_lock);

    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

    dp->conntrack = conntrack_init();

    dpif_miniflow_extract_init();

    atomic_init(&dp->emc_insert_min, DEFAULT_EM_FLOW_INSERT_MIN);
    atomic_init(&dp->tx_flush_interval, DEFAULT_TX_FLUSH_INTERVAL);

    cmap_init(&dp->poll_threads);
    dp->pmd_rxq_assign_type = SCHED_CYCLES;

    ovs_mutex_init(&dp->tx_qid_pool_mutex);
    /* We need 1 Tx queue for each possible core + 1 for non-PMD threads. */
    dp->tx_qid_pool = id_pool_create(0, ovs_numa_get_n_cores() + 1);

    ovs_mutex_init_recursive(&dp->non_pmd_mutex);
    ovsthread_key_create(&dp->per_pmd_key, NULL);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    /* non-PMD will be created before all other threads and will
     * allocate static_tx_qid = 0. */
    dp_netdev_set_nonpmd(dp);

    error = do_add_port(dp, name, dpif_netdev_port_open_type(dp->class,
                                                             "internal"),
                        ODPP_LOCAL);
    ovs_rwlock_unlock(&dp->port_rwlock);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    dp->max_sleep_list = NULL;

    dp->last_tnl_conf_seq = seq_read(tnl_conf_seq);
    *dpp = dp;
    return 0;
}

static void
dp_netdev_request_reconfigure(struct dp_netdev *dp)
{
    seq_change(dp->reconfigure_seq);
}

/* 检查 datapath 是否需要重新配置（端口/PMD 变更后需重配）。 */
static bool
dp_netdev_is_reconf_required(struct dp_netdev *dp)
{
    return seq_read(dp->reconfigure_seq) != dp->last_reconfigure_seq;
}

/* 打开或创建一个 netdev datapath。
 * create=true 时创建新的 datapath，否则打开已有的。
 * 返回 dpif 接口指针供上层使用。 */
static int
dpif_netdev_open(const struct dpif_class *class, const char *name,
                 bool create, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) {
        error = create ? create_dp_netdev(name, class, &dp) : ENODEV;
    } else {
        error = (dp->class != class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }
    if (!error) {
        *dpifp = create_dpif_netdev(dp);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

/* 销毁 upcall 读写锁（在释放 datapath 前调用）。 */
static void
dp_netdev_destroy_upcall_lock(struct dp_netdev *dp)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* Check that upcalls are disabled, i.e. that the rwlock is taken */
    ovs_assert(fat_rwlock_tryrdlock(&dp->upcall_rwlock));

    /* Before freeing a lock we should release it */
    fat_rwlock_unlock(&dp->upcall_rwlock);
    fat_rwlock_destroy(&dp->upcall_rwlock);
}

/* 计算 bond_id 的哈希值。 */
static uint32_t
hash_bond_id(uint32_t bond_id)
{
    return hash_int(bond_id, 0);
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
/* 释放 dp_netdev 及其所有资源：删除所有端口、bond、PMD 线程、
 * conntrack、meter、TX 队列池等，最终 free(dp)。 */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port;
    struct tx_bond *bond;

    shash_find_and_delete(&dp_netdevs, dp->name);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    HMAP_FOR_EACH_SAFE (port, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    ovs_mutex_lock(&dp->bond_mutex);
    CMAP_FOR_EACH (bond, node, &dp->tx_bonds) {
        cmap_remove(&dp->tx_bonds, &bond->node, hash_bond_id(bond->bond_id));
        ovsrcu_postpone(free, bond);
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    dp_netdev_destroy_all_pmds(dp, true);
    cmap_destroy(&dp->poll_threads);

    ovs_mutex_destroy(&dp->tx_qid_pool_mutex);
    id_pool_destroy(dp->tx_qid_pool);

    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    conntrack_destroy(dp->conntrack);


    seq_destroy(dp->reconfigure_seq);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_rwlock_destroy(&dp->port_rwlock);

    cmap_destroy(&dp->tx_bonds);
    ovs_mutex_destroy(&dp->bond_mutex);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    dp_netdev_meter_destroy(dp);

    free(dp->max_sleep_list);
    free(dp->pmd_cmask);
    free(CONST_CAST(char *, dp->name));
    free(CONST_CAST(char *, dp->full_name));
    free(dp);
}

/* 减少 dp 的引用计数，降为零时释放 dp。 */
static void
dp_netdev_unref(struct dp_netdev *dp)
{
    if (dp) {
        /* Take dp_netdev_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_netdevs' shash. */
        ovs_mutex_lock(&dp_netdev_mutex);
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            dp_netdev_free(dp);
        }
        ovs_mutex_unlock(&dp_netdev_mutex);
    }
}

/* 关闭 dpif 接口：减少 dp 引用计数，释放 dpif 结构。 */
static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_unref(dp);
    free(dpif);
}

/* 销毁 datapath（标记已销毁并释放引用）。 */
static int
dpif_netdev_destroy(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'. */
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

/* Add 'n' to the atomic variable 'var' non-atomically and using relaxed
 * load/store semantics.  While the increment is not atomic, the load and
 * store operations are, making it impossible to read inconsistent values.
 *
 * This is used to update thread local stats counters. */
static void
non_atomic_ullong_add(atomic_ullong *var, unsigned long long n)
{
    unsigned long long tmp;

    atomic_read_relaxed(var, &tmp);
    tmp += n;
    atomic_store_relaxed(var, tmp);
}

/* 获取 datapath 统计信息：遍历所有 PMD 线程，
 * 汇总流表数、命中数（各级缓存之和）、miss 数、丢包数。 */
static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    uint64_t pmd_stats[PMD_N_STATS];

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        stats->n_flows += cmap_count(&pmd->flow_table);
        pmd_perf_read_counters(&pmd->perf_stats, pmd_stats);
        stats->n_hit += pmd_stats[PMD_STAT_PHWOL_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_SIMPLE_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_EXACT_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_SMC_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_MASKED_HIT];
        stats->n_missed += pmd_stats[PMD_STAT_MISS];
        stats->n_lost += pmd_stats[PMD_STAT_LOST];
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;
    stats->n_cache_hit = UINT64_MAX;

    return 0;
}

/* 触发 PMD 线程重新加载配置。
 * non-PMD 线程直接在当前上下文中重新加载端口缓存；
 * PMD 线程则通过 reload_seq 通知，等待其在主循环中完成重载。 */
static void
dp_netdev_reload_pmd__(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&pmd->dp->non_pmd_mutex);
        ovs_mutex_lock(&pmd->port_mutex);
        pmd_load_cached_ports(pmd);
        ovs_mutex_unlock(&pmd->port_mutex);
        ovs_mutex_unlock(&pmd->dp->non_pmd_mutex);
        return;
    }

    seq_change(pmd->reload_seq);
    atomic_store_explicit(&pmd->reload, true, memory_order_release);
}

/* 计算端口号的哈希值（用于端口哈希表查找）。 */
static uint32_t
hash_port_no(odp_port_t port_no)
{
    return hash_int(odp_to_u32(port_no), 0);
}

/* 创建端口：打开 netdev 设备、验证（拒绝 loopback）、分配并初始化 dp_netdev_port。 */
static int
port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dp_netdev_port **portp)
{
    struct dp_netdev_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    *portp = NULL;

    /* Open and validate network device. */
    error = netdev_open(devname, type, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR("%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = NULL;
    port->emc_enabled = true;
    port->need_reconfigure = true;
    ovs_mutex_init(&port->txq_used_mutex);

    *portp = port;

    return 0;

out:
    netdev_close(netdev);
    return error;
}

/* 向 datapath 添加端口：创建端口、插入端口哈希表、
 * 触发 datapath 重配置（分配 RXQ 到 PMD）、设置混杂模式。 */
static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    int error;

    /* Reject devices already in 'dp'. */
    if (!get_port_by_name(dp, devname, &port)) {
        return EEXIST;
    }

    error = port_create(devname, type, port_no, &port);
    if (error) {
        return error;
    }

    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

    /* Check that port was successfully configured. */
    if (!dp_netdev_lookup_port(dp, port_no)) {
        return EINVAL;
    }

    /* Updating device flags triggers an if_notifier, which triggers a bridge
     * reconfiguration and another attempt to add this port, leading to an
     * infinite loop if the device is configured incorrectly and cannot be
     * added.  Setting the promisc mode after a successful reconfiguration,
     * since we already know that the device is somehow properly configured. */
    error = netdev_turn_flags_on(port->netdev, NETDEV_PROMISC, &sf);
    if (error) {
        VLOG_ERR("%s: cannot set promisc flag", devname);
        do_del_port(dp, port);
        return error;
    }
    port->sf = sf;

    return 0;
}

/* dpif 接口：添加端口。选择端口号后调用 do_add_port。 */
static int
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev,
                     odp_port_t *port_nop)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = dp_netdev_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp, dpif_port);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (!error) {
        *port_nop = port_no;
        error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

/* dpif 接口：删除端口（不允许删除 LOCAL 端口）。 */
static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    if (port_no == ODPP_LOCAL) {
        error = EINVAL;
    } else {
        struct dp_netdev_port *port;

        error = get_port_by_number(dp, port_no, &port);
        if (!error) {
            do_del_port(dp, port);
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

/* 在端口哈希表中按端口号查找。 */
static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_netdev_lookup_port(dp, port_no);
        return *portp ? 0 : ENODEV;
    }
}

/* 销毁端口：关闭 netdev、恢复标志、关闭所有 RXQ、释放内存。 */
static void
port_destroy(struct dp_netdev_port *port)
{
    if (!port) {
        return;
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    for (unsigned i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
    }
    ovs_mutex_destroy(&port->txq_used_mutex);
    free(port->rxq_affinity_list);
    free(port->txq_used);
    free(port->rxqs);
    free(port->type);
    free(port);
}

static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }

    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

/* Returns 'true' if there is a port with pmd netdev. */
/* 检查是否有需要 PMD 轮询的端口（如 DPDK 端口）。 */
static bool
has_pmd_port(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_pmd(port->netdev)) {
            return true;
        }
    }

    return false;
}

/* 从 datapath 删除端口：从哈希表移除、触发重配置、销毁端口。 */
static void
do_del_port(struct dp_netdev *dp, struct dp_netdev_port *port)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);
    port_destroy(port);
}

/* 将内部端口信息填充到 dpif_port 结构（用于端口查询响应）。 */
static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

/* dpif 接口：按端口号查询端口信息。 */
static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                 struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

/* dpif 接口：按设备名查询端口信息。 */
static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

/* 释放流表项：释放其 action 和额外信息，然后 free 流本身。 */
static void
dp_netdev_flow_free(struct dp_netdev_flow *flow)
{
    dp_netdev_actions_free(dp_netdev_flow_get_actions(flow));
    free(flow->dp_extra_info);
    free(flow);
}

/* 减少流表项引用计数，降为零时通过 RCU 延迟释放。 */
void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

/* 按入端口号查找 PMD 线程的 dpcls 分类器实例（无锁查找）。 */
inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port)
{
    struct dpcls *cls;
    uint32_t hash = hash_port_no(in_port);
    CMAP_FOR_EACH_WITH_HASH (cls, node, hash, &pmd->classifiers) {
        if (cls->in_port == in_port) {
            /* Port classifier exists already */
            return cls;
        }
    }
    return NULL;
}

/* 查找或创建指定入端口的 dpcls 分类器（不存在时自动创建）。 */
static inline struct dpcls *
dp_netdev_pmd_find_dpcls(struct dp_netdev_pmd_thread *pmd,
                         odp_port_t in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);

    if (!cls) {
        uint32_t hash = hash_port_no(in_port);

        /* Create new classifier for in_port */
        cls = xmalloc(sizeof(*cls));
        dpcls_init(cls);
        cls->in_port = in_port;
        cmap_insert(&pmd->classifiers, &cls->node, hash);
        VLOG_DBG("Creating dpcls %p for in_port %d", cls, in_port);
    }
    return cls;
}

/* 记录流表变更日志（flow_add 或 flow_mod），包括 ufid、匹配字段、新旧 action。 */
static void
log_netdev_flow_change(const struct dp_netdev_flow *flow,
                       const struct match *match,
                       const struct dp_netdev_actions *old_actions,
                       const struct nlattr *actions,
                       size_t actions_len)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct ofpbuf key_buf, mask_buf;
    struct odp_flow_key_parms odp_parms = {
        .flow = &match->flow,
        .mask = &match->wc.masks,
        .support = dp_netdev_support,
    };

    if (OVS_LIKELY(VLOG_DROP_DBG((&upcall_rl)))) {
        return;
    }

    ofpbuf_init(&key_buf, 0);
    ofpbuf_init(&mask_buf, 0);

    odp_flow_key_from_flow(&odp_parms, &key_buf);
    odp_parms.key_buf = &key_buf;
    odp_flow_key_from_mask(&odp_parms, &mask_buf);

    if (old_actions) {
        ds_put_cstr(&ds, "flow_mod: ");
    } else {
        ds_put_cstr(&ds, "flow_add: ");
    }
    odp_format_ufid(&flow->ufid, &ds);
    ds_put_cstr(&ds, " mega_");
    odp_format_ufid(&flow->mega_ufid, &ds);
    ds_put_cstr(&ds, " ");
    odp_flow_format(key_buf.data, key_buf.size,
                    mask_buf.data, mask_buf.size,
                    NULL, &ds, false, true);
    if (old_actions) {
        ds_put_cstr(&ds, ", old_actions:");
        format_odp_actions(&ds, old_actions->actions, old_actions->size,
                           NULL);
    }
    ds_put_cstr(&ds, ", actions:");
    format_odp_actions(&ds, actions, actions_len, NULL);

    VLOG_DBG("%s", ds_cstr(&ds));

    ofpbuf_uninit(&key_buf);
    ofpbuf_uninit(&mask_buf);

    /* Add a printout of the actual match installed. */
    struct match m;
    ds_clear(&ds);
    ds_put_cstr(&ds, "flow match: ");
    miniflow_expand(&flow->cr.flow.mf, &m.flow);
    miniflow_expand(&flow->cr.mask->mf, &m.wc.masks);
    memset(&m.tun_md, 0, sizeof m.tun_md);
    match_format(&m, NULL, &ds, OFP_DEFAULT_PRIORITY);

    VLOG_DBG("%s", ds_cstr(&ds));

    ds_destroy(&ds);
}

/* =====================================================
 * 流卸载（Flow Offload）管理函数。
 *
 * 流卸载允许将流表规则下发到硬件（如智能网卡），由硬件直接转发报文。
 * 由于卸载操作是异步的，需要用队列深度计数器跟踪待处理的卸载操作数量，
 * 确保在流销毁时所有操作都已完成。
 * ===================================================== */

/* Offloaded flows can be handled asynchronously, so we do not always know
 * whether a specific flow is offloaded or not.  It might still be pending;
 * in fact, multiple modifications can be pending, and the actual offload
 * state depends on the completion of each modification.
 *
 * To correctly determine whether a flow is offloaded when it is being
 * destroyed (and therefore requires cleanup), we must ensure that all
 * operations have completed.  To achieve this, we track the number of
 * outstanding offloaded flow modifications. */
/* 原子递增卸载队列深度。若已为负（正在清理），则拒绝入队返回 false。 */
static bool
offload_queue_inc(struct dp_netdev_flow *flow)
{
    int current;

    while (true) {
        atomic_read(&flow->offload_queue_depth, &current);
        if (current < 0) {
            /* We are cleaning up, so no longer enqueue operations. */
            return false;
        }

        /* Here we try to atomically increase the value.  If we do not succeed,
         * someone else has modified it, and we need to check again for a
         * current negative value. */
        if (atomic_compare_exchange_strong(&flow->offload_queue_depth,
                                           &current, current + 1)) {
            return true;
        }
    }
}

/* 原子递减卸载队列深度。返回 true 表示队列可能已空（深度从1降到0）。 */
static bool
offload_queue_dec(struct dp_netdev_flow *flow)
{
    int old;

    atomic_sub(&flow->offload_queue_depth, 1, &old);
    ovs_assert(old >= 1);

    if (old == 1) {
        /* Note that this only indicates that the queue might be empty. */
        return true;
    }
    return false;
}

/* 尝试标记卸载队列为"已完成"：用 CAS 将深度从0设为-1，
 * 阻止后续操作入队。成功返回 true。 */
static bool
offload_queue_complete(struct dp_netdev_flow *flow)
{
    /* This function returns false if the queue is still in use.
     * If the queue is empty, it will attempt to atomically mark it as
     * 'not in use' by making the queue depth negative.  This prevents
     * other flow operations from being added.  If successful, it returns
     * true. */
     int expected_val = 0;

    return atomic_compare_exchange_strong(&flow->offload_queue_depth,
                                          &expected_val, -1);
}

/* 卸载流引用释放回调：清除 offloaded 标记并减引用。 */
static void
offload_flow_reference_unreference_cb(unsigned pmd_id OVS_UNUSED,
                                      void *flow_reference_)
{
    struct dp_netdev_flow *flow_reference = flow_reference_;

    if (flow_reference) {
        flow_reference->offloaded = false;
        dp_netdev_flow_unref(flow_reference);
    }
}

/* 卸载流删除完成后的后续处理：
 * EINPROGRESS 表示异步进行中（什么都不做）；
 * 其他错误记日志；成功则释放硬件引用。 */
static void
offload_flow_del_resume(struct dp_netdev_flow *flow_reference,
                        int error)
{
    if (error == EINPROGRESS) {
        return;
    }

    if (error) {
        odp_port_t in_port = flow_reference->flow.in_port.odp_port;

        VLOG_DBG(
            "Failed removing offload flow ufid " UUID_FMT " from port %d: %d",
            UUID_ARGS((struct uuid *)&flow_reference->mega_ufid), in_port,
            error);
    } else {
        /* Release because we successfully removed the reference. */
        dp_netdev_flow_unref(flow_reference);
    }

    /* Release as we took a reference in offload_flow_del(). */
    dp_netdev_flow_unref(flow_reference);
}

/* 异步卸载删除操作完成后的回调入口。 */
static void
offload_flow_del_resume_cb(void *aux OVS_UNUSED,
                           struct dpif_flow_stats *stats OVS_UNUSED,
                           unsigned pmd_id OVS_UNUSED,
                           void *flow_reference,
                           void *previous_flow_reference OVS_UNUSED, int error)
{
    offload_flow_del_resume(flow_reference, error);
}

/* 请求硬件删除已卸载的流。仅在流被标记为 dead 后调用。
 * 先检查卸载队列是否已完成，再判断 flow->offloaded 标志。 */
static void
offload_flow_del(struct dp_netdev *dp, unsigned pmd_id,
                 struct dp_netdev_flow *flow)
{
    odp_port_t in_port = flow->flow.in_port.odp_port;
    struct dpif_offload_flow_del del = {
        .in_port = in_port,
        .pmd_id = pmd_id,
        .ufid = CONST_CAST(ovs_u128 *, &flow->mega_ufid),
        .flow_reference = flow,
        .stats = NULL,
        .cb_data = { .callback = offload_flow_del_resume_cb },
    };
    int error;

    if (!dpif_offload_enabled()) {
        return;
    }

    /* This offload flow delete is only called when the actual flow is
     * destructed.  However, we can only trust the state of flow->offloaded
     * if no more flow_put operations are pending.  Below, we check whether
     * the queue can be marked as complete, and then determine if we need
     * to schedule a removal.  If not, the delete will be rescheduled later
     * in the last offload_flow_put_resume_cb() callback. */
    ovs_assert(flow->dead);
    if (!offload_queue_complete(flow) || !flow->offloaded) {
        return;
    }

    flow->offloaded = false;
    dp_netdev_flow_ref(flow);

    /* It's the responsibility of the offload provider to remove the
     * actual rule from hardware only if none of the other PMD threads
     * have the rule installed in hardware. */
    error = dpif_offload_datapath_flow_del(dp->full_name, &del);
    offload_flow_del_resume(flow, error);
}

/* 从 PMD 线程中移除一条流：
 * 1) 从 dpcls 分类器中删除规则
 * 2) 清除 simple_match 优化
 * 3) 从 flow_table cmap 中移除
 * 4) 递减该入端口的流计数
 * 5) 标记 dead 并触发硬件卸载删除
 * 6) 减引用（可能触发 RCU 延迟释放） */
static void
dp_netdev_pmd_remove_flow(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);
    struct dpcls *cls;
    odp_port_t in_port = flow->flow.in_port.odp_port;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    ovs_assert(cls != NULL);
    dpcls_remove(cls, &flow->cr);
    dp_netdev_simple_match_remove(pmd, flow);
    cmap_remove(&pmd->flow_table, node, dp_netdev_flow_hash(&flow->ufid));
    ccmap_dec(&pmd->n_flows, odp_to_u32(in_port));
    flow->dead = true;
    offload_flow_del(pmd->dp, pmd->core_id, flow);

    dp_netdev_flow_unref(flow);
}

/* 清空 PMD 线程的所有流表项。 */
static void
dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_mutex_lock(&pmd->flow_mutex);
    CMAP_FOR_EACH (netdev_flow, node, &pmd->flow_table) {
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
}

/* dpif 接口的 flow_flush 实现：清空所有 PMD 线程的全部流表。 */
static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_pmd_flow_flush(pmd);
    }

    return 0;
}

/* 端口遍历状态，用于 dpif_netdev_port_dump_* 系列函数。 */
struct dp_netdev_port_state {
    struct hmap_position position;
    char *name;
};

/* 端口遍历接口：start 分配状态，next 逐个返回端口信息，done 释放资源。 */
static int
dpif_netdev_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dp_netdev_port_state));
    return 0;
}

static int
dpif_netdev_port_dump_next(const struct dpif *dpif, void *state_,
                           struct dpif_port *dpif_port)
{
    struct dp_netdev_port_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct hmap_node *node;
    int retval;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    node = hmap_at_position(&dp->ports, &state->position);
    if (node) {
        struct dp_netdev_port *port;

        port = CONTAINER_OF(node, struct dp_netdev_port, node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return retval;
}

static int
dpif_netdev_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dp_netdev_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

/* 检测端口是否有变化（通过 seq 序列号比较）。有变化返回 ENOBUFS，无变化返回 EAGAIN。 */
static int
dpif_netdev_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }

    return error;
}

/* 等待端口变化事件（poll_block 时使用）。 */
static void
dpif_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);

    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
}

/* 从 dpcls_rule 指针反推得到包含它的 dp_netdev_flow 结构。 */
static struct dp_netdev_flow *
dp_netdev_flow_cast(const struct dpcls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

/* 尝试增加流的引用计数（RCU 安全版本）。 */
static bool dp_netdev_flow_ref(struct dp_netdev_flow *flow)
{
    return ovs_refcount_try_ref_rcu(&flow->ref_cnt);
}

/* netdev_flow_key utilities.
 *
 * netdev_flow_key is basically a miniflow.  We use these functions
 * (netdev_flow_key_clone, netdev_flow_key_equal, ...) instead of the miniflow
 * functions (miniflow_clone_inline, miniflow_equal, ...), because:
 *
 * - Since we are dealing exclusively with miniflows created by
 *   miniflow_extract(), if the map is different the miniflow is different.
 *   Therefore we can be faster by comparing the map and the miniflow in a
 *   single memcmp().
 * - These functions can be inlined by the compiler. */
/* =====================================================
 * netdev_flow_key 工具函数。
 *
 * netdev_flow_key 是 miniflow 的封装，额外包含 hash 和 len。
 * 这些函数（equal, clone, init_masked, init）用于流表查找和匹配：
 * - equal: hash + memcmp 快速比较
 * - clone: 仅复制有效数据（由 len 决定）
 * - mask_init: 从 match 构建 mask key
 * - init_masked: 用 mask 过滤 flow 生成带掩码的 key
 * - init: 从完整 flow 构建 key
 * ===================================================== */

static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a,
                      const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */
    return a->hash == b->hash && !memcmp(&a->mf, &b->mf, a->len);
}

static inline void
netdev_flow_key_clone(struct netdev_flow_key *dst,
                      const struct netdev_flow_key *src)
{
    memcpy(dst, src,
           offsetof(struct netdev_flow_key, mf) + src->len);
}

/* Initialize a netdev_flow_key 'mask' from 'match'. */
static inline void
netdev_flow_mask_init(struct netdev_flow_key *mask,
                      const struct match *match)
{
    uint64_t *dst = miniflow_values(&mask->mf);
    struct flowmap fmap;
    uint32_t hash = 0;
    size_t idx;

    /* Only check masks that make sense for the flow. */
    flow_wc_map(&match->flow, &fmap);
    flowmap_init(&mask->mf.map);

    FLOWMAP_FOR_EACH_INDEX(idx, fmap) {
        uint64_t mask_u64 = flow_u64_value(&match->wc.masks, idx);

        if (mask_u64) {
            flowmap_set(&mask->mf.map, idx, 1);
            *dst++ = mask_u64;
            hash = hash_add64(hash, mask_u64);
        }
    }

    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, mask->mf.map) {
        hash = hash_add64(hash, map);
    }

    size_t n = dst - miniflow_get_values(&mask->mf);

    mask->hash = hash_finish(hash, n * 8);
    mask->len = netdev_flow_key_size(n);
}

/* Initializes 'dst' as a copy of 'flow' masked with 'mask'. */
static inline void
netdev_flow_key_init_masked(struct netdev_flow_key *dst,
                            const struct flow *flow,
                            const struct netdev_flow_key *mask)
{
    uint64_t *dst_u64 = miniflow_values(&dst->mf);
    const uint64_t *mask_u64 = miniflow_get_values(&mask->mf);
    uint32_t hash = 0;
    uint64_t value;

    dst->len = mask->len;
    dst->mf = mask->mf;   /* Copy maps. */

    FLOW_FOR_EACH_IN_MAPS(value, flow, mask->mf.map) {
        *dst_u64 = value & *mask_u64++;
        hash = hash_add64(hash, *dst_u64++);
    }
    dst->hash = hash_finish(hash,
                            (dst_u64 - miniflow_get_values(&dst->mf)) * 8);
}

/* Initializes 'key' as a copy of 'flow'. */
static inline void
netdev_flow_key_init(struct netdev_flow_key *key,
                     const struct flow *flow)
{
    uint32_t hash = 0;
    uint64_t value;

    miniflow_map_init(&key->mf, flow);
    miniflow_init(&key->mf, flow);

    size_t n = miniflow_n_values(&key->mf);

    FLOW_FOR_EACH_IN_MAPS (value, flow, key->mf.map) {
        hash = hash_add64(hash, value);
    }

    key->hash = hash_finish(hash, n * 8);
    key->len = netdev_flow_key_size(n);
}

/* =====================================================
 * EMC（Exact Match Cache）精确匹配缓存。
 *
 * EMC 是流表查找的第一级缓存，直接用报文的 miniflow key 进行精确匹配。
 * 使用开放寻址哈希表，每个哈希桶有多个候选位置。
 * 命中率最高，但容量有限，适合高频流量。
 * ===================================================== */

/* 更新 EMC 条目：替换关联的 flow 指针和/或 key。 */
static inline void
emc_change_entry(struct emc_entry *ce, struct dp_netdev_flow *flow,
                 const struct netdev_flow_key *key)
{
    if (ce->flow != flow) {
        if (ce->flow) {
            dp_netdev_flow_unref(ce->flow);
        }

        if (dp_netdev_flow_ref(flow)) {
            ce->flow = flow;
        } else {
            ce->flow = NULL;
        }
    }
    if (key) {
        netdev_flow_key_clone(&ce->key, key);
    }
}

/* 向 EMC 插入条目：
 * 1) 先查找是否已有相同 key 的条目（命中则更新 flow）
 * 2) 否则选择替换目标：优先空条目，其次 hash 最小的条目 */
static inline void
emc_insert(struct emc_cache *cache, const struct netdev_flow_key *key,
           struct dp_netdev_flow *flow)
{
    struct emc_entry *to_be_replaced = NULL;
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (netdev_flow_key_equal(&current_entry->key, key)) {
            /* We found the entry with the 'mf' miniflow */
            emc_change_entry(current_entry, flow, NULL);
            return;
        }

        /* Replacement policy: put the flow in an empty (not alive) entry, or
         * in the first entry where it can be */
        if (!to_be_replaced
            || (emc_entry_alive(to_be_replaced)
                && !emc_entry_alive(current_entry))
            || current_entry->key.hash < to_be_replaced->key.hash) {
            to_be_replaced = current_entry;
        }
    }
    /* We didn't find the miniflow in the cache.
     * The 'to_be_replaced' entry is where the new flow will be stored */

    emc_change_entry(to_be_replaced, flow, key);
}

/* 概率性 EMC 插入：以 1/100 的概率将流插入 EMC，避免低频流污染缓存。 */
static inline void
emc_probabilistic_insert(struct dp_netdev_pmd_thread *pmd,
                         const struct netdev_flow_key *key,
                         struct dp_netdev_flow *flow)
{
    /* Insert an entry into the EMC based on probability value 'min'. By
     * default the value is UINT32_MAX / 100 which yields an insertion
     * probability of 1/100 ie. 1% */

    uint32_t min = pmd->ctx.emc_insert_min;

    if (min && random_uint32() <= min) {
        emc_insert(&(pmd->flow_cache).emc_cache, key, flow);
    }
}

/* =====================================================
 * SMC（Signature Match Cache）签名匹配缓存。
 *
 * SMC 是第二级缓存，用 16 位签名（hash >> 16）快速筛选。
 * 命中后还需从 flow_table 中取出 flow 并验证。
 * 容量比 EMC 大但查找开销略高。
 * ===================================================== */

/* 通过 hash 在 SMC 中查找：匹配签名后返回 flow_table 中的 cmap_node。 */
static inline const struct cmap_node *
smc_entry_get(struct dp_netdev_pmd_thread *pmd, const uint32_t hash)
{
    struct smc_cache *cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &cache->buckets[hash & SMC_MASK];
    uint16_t sig = hash >> 16;
    uint16_t index = UINT16_MAX;

    for (int i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            index = bucket->flow_idx[i];
            break;
        }
    }
    if (index != UINT16_MAX) {
        return cmap_find_by_index(&pmd->flow_table, index);
    }
    return NULL;
}

/* Insert the flow_table index into SMC. Insertion may fail when 1) SMC is
 * turned off, 2) the flow_table index is larger than uint16_t can handle.
 * If there is already an SMC entry having same signature, the index will be
 * updated. If there is no existing entry, but an empty entry is available,
 * the empty entry will be taken. If no empty entry or existing same signature,
 * a random entry from the hashed bucket will be picked. */
/* SMC 插入策略：
 * 1) 已有相同签名 → 更新索引
 * 2) 有空槽位 → 占用空槽
 * 3) 都满了 → 随机替换一个 */
static inline void
smc_insert(struct dp_netdev_pmd_thread *pmd,
           const struct netdev_flow_key *key,
           uint32_t hash)
{
    struct smc_cache *smc_cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &smc_cache->buckets[key->hash & SMC_MASK];
    uint16_t index;
    uint32_t cmap_index;
    int i;

    if (!pmd->ctx.smc_enable_db) {
        return;
    }

    cmap_index = cmap_find_index(&pmd->flow_table, hash);
    index = (cmap_index >= UINT16_MAX) ? UINT16_MAX : (uint16_t)cmap_index;

    /* If the index is larger than SMC can handle (uint16_t), we don't
     * insert */
    if (index == UINT16_MAX) {
        return;
    }

    /* If an entry with same signature already exists, update the index */
    uint16_t sig = key->hash >> 16;
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* If there is an empty entry, occupy it. */
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->flow_idx[i] == UINT16_MAX) {
            bucket->sig[i] = sig;
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* Otherwise, pick a random entry. */
    i = random_uint32() % SMC_ENTRY_PER_BUCKET;
    bucket->sig[i] = sig;
    bucket->flow_idx[i] = index;
}

/* 批量概率性 EMC 插入：对位图中标记的每个报文执行概率性插入。 */
inline void
emc_probabilistic_insert_batch(struct dp_netdev_pmd_thread *pmd,
                               const struct netdev_flow_key *keys,
                               struct dpcls_rule **rules,
                               uint32_t emc_insert_mask)
{
    while (emc_insert_mask) {
        uint32_t i = raw_ctz(emc_insert_mask);
        emc_insert_mask &= emc_insert_mask - 1;
        /* Get the require parameters for EMC/SMC from the rule */
        struct dp_netdev_flow *flow = dp_netdev_flow_cast(rules[i]);
        /* Insert the key into EMC/SMC. */
        emc_probabilistic_insert(pmd, &keys[i], flow);
    }
}

/* 批量 SMC 插入：对位图中标记的每个报文将其 flow 索引插入 SMC。 */
inline void
smc_insert_batch(struct dp_netdev_pmd_thread *pmd,
                 const struct netdev_flow_key *keys,
                 struct dpcls_rule **rules,
                 uint32_t smc_insert_mask)
{
    while (smc_insert_mask) {
        uint32_t i = raw_ctz(smc_insert_mask);
        smc_insert_mask &= smc_insert_mask - 1;
        /* Get the require parameters for EMC/SMC from the rule */
        struct dp_netdev_flow *flow = dp_netdev_flow_cast(rules[i]);
        uint32_t hash = dp_netdev_flow_hash(&flow->ufid);
        /* Insert the key into EMC/SMC. */
        smc_insert(pmd, &keys[i], hash);
    }
}

/* 在 PMD 的 dpcls 中查找单条流（用于 flow_put/flow_get 等管理操作）。
 * 根据 key 中的 in_port 找到对应分类器，再执行 dpcls_lookup。 */
static struct dp_netdev_flow *
dp_netdev_pmd_lookup_flow(struct dp_netdev_pmd_thread *pmd,
                          const struct netdev_flow_key *key,
                          int *lookup_num_p)
{
    struct dpcls *cls;
    struct dpcls_rule *rule = NULL;
    odp_port_t in_port = u32_to_odp(MINIFLOW_GET_U32(&key->mf,
                                                     in_port.odp_port));
    struct dp_netdev_flow *netdev_flow = NULL;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        dpcls_lookup(cls, &key, &rule, 1, lookup_num_p);
        netdev_flow = dp_netdev_flow_cast(rule);
    }
    return netdev_flow;
}

/* 按 UFID 在 flow_table 中查找流。若未提供 UFID 则从 key 计算。
 * 用于 flow_get/flow_del 等需要精确定位已安装流的场景。 */
static struct dp_netdev_flow *
dp_netdev_pmd_find_flow(const struct dp_netdev_pmd_thread *pmd,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len)
{
    struct dp_netdev_flow *netdev_flow;
    struct flow flow;
    ovs_u128 ufid;

    /* If a UFID is not provided, determine one based on the key. */
    if (!ufidp && key && key_len
        && !dpif_netdev_flow_from_nlattrs(key, key_len, &flow, false)) {
        odp_flow_key_hash(&flow, sizeof flow, &ufid);
        ufidp = &ufid;
    }

    if (ufidp) {
        CMAP_FOR_EACH_WITH_HASH (netdev_flow, node, dp_netdev_flow_hash(ufidp),
                                 &pmd->flow_table) {
            if (ovs_u128_equals(netdev_flow->ufid, *ufidp)) {
                return netdev_flow;
            }
        }
    }

    return NULL;
}

/* 获取流的统计信息（包/字节/使用时间/TCP标志），并合并硬件卸载的统计。 */
static void
get_dpif_flow_status(const struct dp_netdev *dp,
                     const struct dp_netdev_flow *netdev_flow_,
                     struct dpif_flow_stats *stats,
                     struct dpif_flow_attrs *attrs)
{
    struct dpif_flow_stats offload_stats;
    struct dpif_flow_attrs offload_attrs;
    struct dp_netdev_flow *netdev_flow;
    unsigned long long n;
    long long used;
    uint16_t flags;

    netdev_flow = CONST_CAST(struct dp_netdev_flow *, netdev_flow_);

    atomic_read_relaxed(&netdev_flow->stats.packet_count, &n);
    stats->n_packets = n;
    atomic_read_relaxed(&netdev_flow->stats.byte_count, &n);
    stats->n_bytes = n;
    atomic_read_relaxed(&netdev_flow->stats.used, &used);
    stats->used = used;
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    stats->tcp_flags = flags;

    if (dpif_offload_datapath_flow_stats(dp->full_name,
                                         netdev_flow->flow.in_port.odp_port,
                                         &netdev_flow->mega_ufid,
                                         &offload_stats, &offload_attrs)) {
        stats->n_packets += offload_stats.n_packets;
        stats->n_bytes += offload_stats.n_bytes;
        stats->used = MAX(stats->used, offload_stats.used);
        stats->tcp_flags |= offload_stats.tcp_flags;
        if (attrs) {
            attrs->offloaded = offload_attrs.offloaded;
            attrs->dp_layer = offload_attrs.dp_layer;
        }
    } else if (attrs) {
        attrs->offloaded = false;
        attrs->dp_layer = "ovs";
    }
}

/* Converts to the dpif_flow format, using 'key_buf' and 'mask_buf' for
 * storing the netlink-formatted key/mask. 'key_buf' may be the same as
 * 'mask_buf'. Actions will be returned without copying, by relying on RCU to
 * protect them. */
/* 将内部流表项转换为 dpif_flow 格式（用于 ovs-dpctl dump-flows 等）。
 * terse 模式下跳过 key/mask/actions，仅返回 ufid 和统计信息。 */
static void
dp_netdev_flow_to_dpif_flow(const struct dp_netdev *dp,
                            const struct dp_netdev_flow *netdev_flow,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse)
{
    if (terse) {
        memset(flow, 0, sizeof *flow);
    } else {
        struct flow_wildcards wc;
        struct dp_netdev_actions *actions;
        size_t offset;
        struct odp_flow_key_parms odp_parms = {
            .flow = &netdev_flow->flow,
            .mask = &wc.masks,
            .support = dp_netdev_support,
        };

        miniflow_expand(&netdev_flow->cr.mask->mf, &wc.masks);
        /* in_port is exact matched, but we have left it out from the mask for
         * optimnization reasons. Add in_port back to the mask. */
        wc.masks.in_port.odp_port = ODPP_NONE;

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_parms.key_buf = key_buf;
        odp_flow_key_from_mask(&odp_parms, mask_buf);
        flow->mask_len = mask_buf->size - offset;

        /* Actions */
        actions = dp_netdev_flow_get_actions(netdev_flow);
        flow->actions = actions->actions;
        flow->actions_len = actions->size;
    }

    flow->ufid = netdev_flow->ufid;
    flow->ufid_present = true;
    flow->pmd_id = netdev_flow->pmd_id;

    get_dpif_flow_status(dp, netdev_flow, &flow->stats, &flow->attrs);
    flow->attrs.dp_extra_info = netdev_flow->dp_extra_info;
}

/* 从 netlink 属性解析流匹配的 mask。失败时记录错误日志（除非 probe 模式）。 */
static int
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow_wildcards *wc, bool probe)
{
    enum odp_key_fitness fitness;

    fitness = odp_flow_key_to_mask(mask_key, mask_key_len, wc, flow, NULL);
    if (fitness) {
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_mask() and odp_flow_key_to_mask()
             * disagree on the acceptable form of a mask.  Log the problem
             * as an error, with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, mask_key, mask_key_len, NULL, &s,
                                true, true);
                VLOG_ERR("internal error parsing flow mask %s (%s)",
                ds_cstr(&s), odp_key_fitness_to_string(fitness));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    return 0;
}

/* 从 netlink 属性解析流匹配的 key（flow 结构体）。 */
static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow, bool probe)
{
    if (odp_flow_key_to_flow(key, key_len, flow, NULL)) {
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_flow() and odp_flow_key_to_flow() disagree on
             * the acceptable form of a flow.  Log the problem as an error,
             * with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, NULL, 0, NULL, &s, true, false);
                VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    if (flow->ct_state & DP_NETDEV_CS_UNSUPPORTED_MASK) {
        return EINVAL;
    }

    return 0;
}

/* dpif 接口的 flow_get 实现：按 UFID 查找流并返回其 key/mask/actions/stats。
 * 若未指定 pmd_id，则遍历所有 PMD 线程搜索。 */
static int
dpif_netdev_flow_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct dp_netdev_pmd_thread *pmd;
    struct hmapx to_find = HMAPX_INITIALIZER(&to_find);
    struct hmapx_node *node;
    int error = EINVAL;

    if (get->pmd_id == PMD_ID_NULL) {
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dp_netdev_pmd_try_ref(pmd) && !hmapx_add(&to_find, pmd)) {
                dp_netdev_pmd_unref(pmd);
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, get->pmd_id);
        if (!pmd) {
            goto out;
        }
        hmapx_add(&to_find, pmd);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        netdev_flow = dp_netdev_pmd_find_flow(pmd, get->ufid, get->key,
                                              get->key_len);
        if (netdev_flow) {
            dp_netdev_flow_to_dpif_flow(dp, netdev_flow, get->buffer,
                                        get->buffer, get->flow, false);
            error = 0;
            break;
        } else {
            error = ENOENT;
        }
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        dp_netdev_pmd_unref(pmd);
    }
out:
    hmapx_destroy(&to_find);
    return error;
}

/* 计算 mega_ufid：对 flow 应用 mask 后再哈希，用于流卸载去重。 */
static void
dp_netdev_get_mega_ufid(const struct match *match, ovs_u128 *mega_ufid)
{
    struct flow masked_flow;
    size_t i;

    for (i = 0; i < sizeof(struct flow); i++) {
        ((uint8_t *)&masked_flow)[i] = ((uint8_t *)&match->flow)[i] &
                                       ((uint8_t *)&match->wc)[i];
    }
    odp_flow_key_hash(&masked_flow, sizeof masked_flow, mega_ufid);
}

/* =====================================================
 * Simple Match 优化：对仅匹配 in_port + dl_type + nw_frag + vlan_tci
 * 的简单流提供 O(1) 快速查找，跳过完整的 dpcls 查找流程。
 *
 * 将这4个字段编码为64位 mark 值，用独立的 cmap 表存储。
 * 仅当某入端口的所有流都是 simple_match 类型时才启用。
 * ===================================================== */

/* 将 in_port/dl_type/nw_frag/vlan_tci 编码为64位 mark 值。
 *
 * 编码原理：将 4 个字段紧凑打包到一个 uint64_t 中，
 * 使得 simple_match 查找只需一次整数比较即可完成匹配。
 * 高 32 位放 in_port，中间 16 位放 dl_type，低 16 位放 nw_frag + vlan_tci。
 * BE/LE 布局不同是为了避免字节序转换开销。 */
uint64_t
dp_netdev_simple_match_mark(odp_port_t in_port, ovs_be16 dl_type,
                            uint8_t nw_frag, ovs_be16 vlan_tci)
{
    /* Simple Match Mark:
     *
     * BE:
     * +-----------------+-------------++---------+---+-----------+
     * |     in_port     |   dl_type   || nw_frag |CFI|  VID(12)  |
     * +-----------------+-------------++---------+---+-----------+
     * 0                 32          47 49         51  52     63
     *
     * LE:
     * +-----------------+-------------+------++-------+---+------+
     * |     in_port     |   dl_type   |VID(8)||nw_frag|CFI|VID(4)|
     * +-----------------+-------------+------++-------+---+------+
     * 0                 32          47 48  55  57   59 60  61   63
     *
     *         Big Endian              Little Endian
     * in_port : 32 bits [ 0..31]  in_port : 32 bits [ 0..31]
     * dl_type : 16 bits [32..47]  dl_type : 16 bits [32..47]
     * <empty> :  1 bit  [48..48]  vlan VID:  8 bits [48..55]
     * nw_frag :  2 bits [49..50]  <empty> :  1 bit  [56..56]
     * vlan CFI:  1 bit  [51..51]  nw_frag :  2 bits [57..59]
     * vlan VID: 12 bits [52..63]  vlan CFI:  1 bit  [60..60]
     *                             vlan VID:  4 bits [61..63]
     *
     * Layout is different for LE and BE in order to save a couple of
     * network to host translations.
     * */
    return ((uint64_t) odp_to_u32(in_port) << 32)     /* 高 32 位：入端口号 */
           | ((OVS_FORCE uint32_t) dl_type << 16)      /* 中 16 位：以太网类型 */
#if WORDS_BIGENDIAN
           | (((uint16_t) nw_frag & FLOW_NW_FRAG_MASK) << VLAN_PCP_SHIFT)
#else
           | ((nw_frag & FLOW_NW_FRAG_MASK) << (VLAN_PCP_SHIFT - 8))
#endif                                                 /* nw_frag 2 位嵌入低 16 位 */
           | (OVS_FORCE uint16_t) (vlan_tci & htons(VLAN_VID_MASK | VLAN_CFI));
                                                       /* VLAN VID+CFI 嵌入低 16 位 */
}

/* 在 simple_match_table 中按 mark 值查找流。
 *
 * 查找过程：
 *   1. 将 4 个字段编码为 64 位 mark
 *   2. 对 mark 做哈希，定位 cmap 桶
 *   3. 遍历桶中节点，比较 mark 值（整数比较，极快）
 *
 * 与 dpcls 的 miniflow 匹配相比，这里只需一次 uint64_t 比较，
 * 无需位图遍历和逐字段掩码运算，因此性能更优。
 * 调用方：dfc_processing() 中的 simple_match 路径。 */
struct dp_netdev_flow *
dp_netdev_simple_match_lookup(const struct dp_netdev_pmd_thread *pmd,
                              odp_port_t in_port, ovs_be16 dl_type,
                              uint8_t nw_frag, ovs_be16 vlan_tci)
{
    /* 将 4 个匹配字段编码为 64 位 mark 值 */
    uint64_t mark = dp_netdev_simple_match_mark(in_port, dl_type,
                                                nw_frag, vlan_tci);
    uint32_t hash = hash_uint64(mark);           /* 对 mark 做哈希，定位 cmap 桶 */
    struct dp_netdev_flow *flow;
    bool found = false;

    /* 遍历哈希桶中的所有流，比较 mark 值 */
    CMAP_FOR_EACH_WITH_HASH (flow, simple_match_node,
                             hash, &pmd->simple_match_table) {
        if (flow->simple_match_mark == mark) {   /* 精确匹配：一次整数比较 */
            found = true;
            break;
        }
    }
    return found ? flow : NULL;                  /* 命中返回流指针，未命中返回 NULL */
}

/* 检查指定入端口是否启用了 simple_match 优化：
 * 当该端口的总流数 == simple 流数时启用。
 *
 * 原理：只有当某入端口上的所有流都满足 simple_match 条件时，
 * 才能安全地使用 simple_match 快速路径（否则会漏匹配非 simple 的流）。
 * n_flows 和 n_simple_flows 都是按入端口索引的 ccmap 计数器。 */
bool
dp_netdev_simple_match_enabled(const struct dp_netdev_pmd_thread *pmd,
                               odp_port_t in_port)
{
    /* 总流数 == simple 流数 → 该端口所有流都是 simple，可启用优化 */
    return ccmap_find(&pmd->n_flows, odp_to_u32(in_port))
           == ccmap_find(&pmd->n_simple_flows, odp_to_u32(in_port));
}

/* 将流插入 simple_match_table（需持有 flow_mutex）。
 *
 * 在 dp_netdev_flow_add() 中，若新流满足 simple_match 条件，调用此函数。
 * 步骤：增引用 → 防重复移除 → 编码 mark → 插入 cmap → 递增计数。 */
static void
dp_netdev_simple_match_insert(struct dp_netdev_pmd_thread *pmd,
                              struct dp_netdev_flow *dp_flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    /* 从流的 unmasked key 中提取 4 个匹配字段 */
    odp_port_t in_port = dp_flow->flow.in_port.odp_port;  /* 入端口 */
    ovs_be16 vlan_tci = dp_flow->flow.vlans[0].tci;       /* 第一层 VLAN TCI */
    ovs_be16 dl_type = dp_flow->flow.dl_type;             /* 以太网类型 */
    uint8_t nw_frag = dp_flow->flow.nw_frag;              /* IP 分片标志 */

    /* 增加引用计数，防止流在操作过程中被释放 */
    if (!dp_netdev_flow_ref(dp_flow)) {
        return;                                /* 流已死亡（ref_cnt=0），放弃插入 */
    }

    /* Avoid double insertion.  Should not happen in practice. */
    dp_netdev_simple_match_remove(pmd, dp_flow);  /* 防御性移除：避免重复插入 */

    /* 编码 4 个字段为 64 位 mark，计算哈希 */
    uint64_t mark = dp_netdev_simple_match_mark(in_port, dl_type,
                                                nw_frag, vlan_tci);
    uint32_t hash = hash_uint64(mark);

    dp_flow->simple_match_mark = mark;         /* 将 mark 存入流结构体 */
    cmap_insert(&pmd->simple_match_table,      /* 插入 simple_match cmap 表 */
                CONST_CAST(struct cmap_node *, &dp_flow->simple_match_node),
                hash);
    ccmap_inc(&pmd->n_simple_flows, odp_to_u32(in_port)); /* 该端口的 simple 流计数 +1 */

    VLOG_DBG("Simple match insert: "
             "core_id(%d),in_port(%"PRIu32"),mark(0x%016"PRIx64").",
             pmd->core_id, in_port, mark);
}

/* 从 simple_match_table 中移除流。
 *
 * 在流删除（dp_netdev_flow_del__）时调用。
 * 先 lookup 确认表中确实存在该流（防止误删），再执行移除。 */
static void
dp_netdev_simple_match_remove(struct dp_netdev_pmd_thread *pmd,
                               struct dp_netdev_flow *dp_flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    /* 提取 4 个匹配字段 */
    odp_port_t in_port = dp_flow->flow.in_port.odp_port;
    ovs_be16 vlan_tci = dp_flow->flow.vlans[0].tci;
    ovs_be16 dl_type = dp_flow->flow.dl_type;
    uint8_t nw_frag = dp_flow->flow.nw_frag;
    struct dp_netdev_flow *flow;
    /* 编码 mark 并计算哈希（移除时也需要哈希来定位 cmap 桶） */
    uint64_t mark = dp_netdev_simple_match_mark(in_port, dl_type,
                                                nw_frag, vlan_tci);
    uint32_t hash = hash_uint64(mark);

    /* 先查找确认：表中存在且确实是同一个流对象 */
    flow = dp_netdev_simple_match_lookup(pmd, in_port, dl_type,
                                         nw_frag, vlan_tci);
    if (flow == dp_flow) {
        VLOG_DBG("Simple match remove: "
                 "core_id(%d),in_port(%"PRIu32"),mark(0x%016"PRIx64").",
                 pmd->core_id, in_port, mark);
        cmap_remove(&pmd->simple_match_table,  /* 从 cmap 中移除节点 */
                    CONST_CAST(struct cmap_node *, &flow->simple_match_node),
                    hash);
        ccmap_dec(&pmd->n_simple_flows, odp_to_u32(in_port)); /* simple 流计数 -1 */
        dp_netdev_flow_unref(flow);            /* 释放插入时增加的引用 */
    }
}

/* 判断流是否为 simple_match：仅匹配 in_port/dl_type/nw_frag/vlan_tci
 * 且 recirc_id=0, packet_type=PT_ETH。
 *
 * 判断逻辑：构造一个"最小通配符集"（miniflow_extract 一定会设置的字段），
 * 然后检查该流的实际通配符是否与最小集完全一致。
 * 如果流只匹配这些最小字段，则满足 simple_match 条件。
 *
 * 为什么这 4 个字段？因为 miniflow_extract() 对每个以太网包总会设置：
 *   recirc_id, in_port, packet_type, dl_type, vlan_tci, nw_frag
 * 其中 recirc_id/in_port/packet_type 是固定值不需要编码到 mark 中，
 * 所以实际需要匹配的只有 dl_type + vlan_tci + nw_frag（加上 in_port 隐含匹配）。 */
static bool
dp_netdev_flow_is_simple_match(const struct match *match)
{
    const struct flow *flow = &match->flow;
    const struct flow_wildcards *wc = &match->wc;

    /* 前置条件：必须是首轮（recirc_id=0）且是以太网包 */
    if (flow->recirc_id || flow->packet_type != htonl(PT_ETH)) {
        return false;
    }

    /* Check that flow matches only minimal set of fields that always set.
     * Also checking that VLAN VID+CFI is an exact match, because these
     * are not mandatory and could be masked. */
    /* 构造"最小通配符集"：只包含 dpif-netdev 总会精确匹配的字段 */
    struct flow_wildcards *minimal = xmalloc(sizeof *minimal);
    ovs_be16 vlan_tci_mask = htons(VLAN_VID_MASK | VLAN_CFI); /* VID+CFI 掩码 */

    flow_wildcards_init_catchall(minimal);     /* 初始化为全通配（全 0 掩码） */
    /* 'dpif-netdev' always has following in exact match:
     *   - recirc_id                   <-- recirc_id == 0 checked on input.
     *   - in_port                     <-- Will be checked on input.
     *   - packet_type                 <-- Assuming all packets are PT_ETH.
     *   - dl_type                     <-- Need to match with.
     *   - vlan_tci                    <-- Need to match with.
     *   - and nw_frag for ip packets. <-- Need to match with.
     */
    WC_MASK_FIELD(minimal, recirc_id);         /* 设置 recirc_id 为精确匹配 */
    WC_MASK_FIELD(minimal, in_port);           /* 设置 in_port 为精确匹配 */
    WC_MASK_FIELD(minimal, packet_type);       /* 设置 packet_type 为精确匹配 */
    WC_MASK_FIELD(minimal, dl_type);           /* 设置 dl_type 为精确匹配 */
    WC_MASK_FIELD_MASK(minimal, vlans[0].tci, vlan_tci_mask); /* VID+CFI 精确匹配 */
    WC_MASK_FIELD_MASK(minimal, nw_frag, FLOW_NW_FRAG_MASK);  /* 分片标志精确匹配 */

    /* 检查：流的通配符是否比最小集有"额外"匹配字段？
     * 若有 → 该流匹配了更多字段（如 nw_src, tp_dst 等），不是 simple match。
     * 同时检查 vlan_tci 掩码必须恰好是 VID+CFI（不能只匹配部分位）。 */
    if (flow_wildcards_has_extra(minimal, wc)
        || wc->masks.vlans[0].tci != vlan_tci_mask) {
        free(minimal);
        return false;                          /* 不满足 simple_match 条件 */
    }
    free(minimal);

    return true;                               /* 满足条件：仅匹配最小字段集 */
}

/* 卸载 flow_put 操作完成后的后续处理：
 * 成功 → 标记 offloaded；失败 → 清除标记并释放引用。
 * 若这是已 dead 流的最后一个队列操作，触发 offload_flow_del。 */
static void
offload_flow_put_resume(struct dp_netdev *dp, struct dp_netdev_flow *flow,
                        struct dp_netdev_flow *previous_flow_reference,
                        unsigned pmd_id, int error)
{
    if (error == EINPROGRESS) {
        return;
    }

    if (!error) {
        flow->offloaded = true;
    } else {
        /* If the flow was already offloaded, the new action set can no
         * longer be offloaded.  In theory, we should disassociate the
         * offload from all PMDs that have this flow marked as offloaded.
         * Unfortunately, there is no mechanism to inform other PMDs, so
         * we cannot explicitly mark such flows.  This situation typically
         * occurs when the revalidator modifies the flow, so it is safe to
         * assume it will update all affected flows and that the offload
         * will subsequently fail. */
        flow->offloaded = false;

        /* On error, the flow reference was not stored by the offload provider,
         * so we should decrease the reference. */
        dp_netdev_flow_unref(flow);
    }

    if (offload_queue_dec(flow) && flow->dead) {
        /* If flows are processed asynchronously, modifications might
         * still be queued up while the flow is being removed.  If this
         * was the last flow in the queue on a dead flow, we try again
         * to see if we need to remove this flow. */
        offload_flow_del(dp, pmd_id, flow);
    }

    if (previous_flow_reference) {
        dp_netdev_flow_unref(previous_flow_reference);
        if (previous_flow_reference != flow) {
            VLOG_DBG("Updated flow reference was from outdated flow");
        }
    }
}

/* 异步卸载 put 操作完成后的回调入口。 */
static void
offload_flow_put_resume_cb(void *aux, struct dpif_flow_stats *stats OVS_UNUSED,
                           unsigned pmd_id, void *flow_reference_,
                           void *old_flow_reference_,
                           int error)
{
    struct dp_netdev *dp = aux;
    struct dp_netdev_flow *flow_reference = flow_reference_;
    struct dp_netdev_flow *old_flow_reference = old_flow_reference_;

    offload_flow_put_resume(dp, flow_reference, old_flow_reference,
                            pmd_id, error);
}

/* 请求将流卸载到硬件：构建 dpif_offload_flow_put 并提交。 */
static void
offload_flow_put(struct dp_netdev_pmd_thread *pmd, struct dp_netdev_flow *flow,
                 struct match *match, const struct nlattr *actions,
                 size_t actions_len)
{
    struct dpif_offload_flow_put put = {
        .in_port = match->flow.in_port.odp_port,
        .orig_in_port = flow->orig_in_port,
        .pmd_id = pmd->core_id,
        .ufid = CONST_CAST(ovs_u128 *, &flow->mega_ufid),
        .match = match,
        .actions = actions,
        .actions_len = actions_len,
        .stats = NULL,
        .flow_reference = flow,
        .cb_data = {
            .callback = offload_flow_put_resume_cb,
            .callback_aux = pmd->dp,
        },
    };
    void *previous_flow_reference = NULL;
    int error;

    if (!dpif_offload_enabled() || flow->dead || !offload_queue_inc(flow)) {
        return;
    }

    dp_netdev_flow_ref(flow);

    error = dpif_offload_datapath_flow_put(pmd->dp->full_name, &put,
                                           &previous_flow_reference);
    offload_flow_put_resume(pmd->dp, put.flow_reference,
                            previous_flow_reference,
                            pmd->core_id, error);
}

/* 向 PMD 线程添加一条新流：
 * 1) 构造 mask key 和 masked flow key
 * 2) 分配 dp_netdev_flow，初始化 ufid/mega_ufid/actions
 * 3) 插入 flow_table (cmap) 和 dpcls 分类器
 * 4) 尝试插入 simple_match 优化表
 * 5) 触发硬件卸载
 * 6) 记录日志 */
static struct dp_netdev_flow *
dp_netdev_flow_add(struct dp_netdev_pmd_thread *pmd,
                   struct match *match, const ovs_u128 *ufid,
                   const struct nlattr *actions, size_t actions_len,
                   odp_port_t orig_in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct ds extra_info = DS_EMPTY_INITIALIZER;
    struct dp_netdev_flow *flow;
    struct netdev_flow_key mask;
    struct dpcls *cls;
    size_t unit;

    /* Make sure in_port is exact matched before we read it. */
    ovs_assert(match->wc.masks.in_port.odp_port == ODPP_NONE);
    odp_port_t in_port = match->flow.in_port.odp_port;

    /* As we select the dpcls based on the port number, each netdev flow
     * belonging to the same dpcls will have the same odp_port value.
     * For performance reasons we wildcard odp_port here in the mask.  In the
     * typical case dp_hash is also wildcarded, and the resulting 8-byte
     * chunk {dp_hash, in_port} will be ignored by netdev_flow_mask_init() and
     * will not be part of the subtable mask.
     * This will speed up the hash computation during dpcls_lookup() because
     * there is one less call to hash_add64() in this case. */
    match->wc.masks.in_port.odp_port = 0;
    netdev_flow_mask_init(&mask, match);
    match->wc.masks.in_port.odp_port = ODPP_NONE;

    /* Make sure wc does not have metadata. */
    ovs_assert(!FLOWMAP_HAS_FIELD(&mask.mf.map, metadata)
               && !FLOWMAP_HAS_FIELD(&mask.mf.map, regs));

    /* Do not allocate extra space. */
    flow = xmalloc(sizeof *flow - sizeof flow->cr.flow.mf + mask.len);
    memset(&flow->stats, 0, sizeof flow->stats);
    flow->dead = false;
    flow->offloaded = false;
    atomic_init(&flow->offload_queue_depth, 0);
    flow->batch = NULL;
    flow->orig_in_port = orig_in_port;
    *CONST_CAST(unsigned *, &flow->pmd_id) = pmd->core_id;
    *CONST_CAST(struct flow *, &flow->flow) = match->flow;
    *CONST_CAST(ovs_u128 *, &flow->ufid) = *ufid;
    ovs_refcount_init(&flow->ref_cnt);
    ovsrcu_set(&flow->actions, dp_netdev_actions_create(actions, actions_len));

    dp_netdev_get_mega_ufid(match, CONST_CAST(ovs_u128 *, &flow->mega_ufid));
    netdev_flow_key_init_masked(&flow->cr.flow, &match->flow, &mask);

    /* Select dpcls for in_port. Relies on in_port to be exact match. */
    cls = dp_netdev_pmd_find_dpcls(pmd, in_port);
    dpcls_insert(cls, &flow->cr, &mask);

    ds_put_cstr(&extra_info, "miniflow_bits(");
    FLOWMAP_FOR_EACH_UNIT (unit) {
        if (unit) {
            ds_put_char(&extra_info, ',');
        }
        ds_put_format(&extra_info, "%d",
                      count_1bits(flow->cr.mask->mf.map.bits[unit]));
    }
    ds_put_char(&extra_info, ')');
    flow->dp_extra_info = ds_steal_cstr(&extra_info);
    ds_destroy(&extra_info);

    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node),
                dp_netdev_flow_hash(&flow->ufid));
    ccmap_inc(&pmd->n_flows, odp_to_u32(in_port));

    if (dp_netdev_flow_is_simple_match(match)) {
        dp_netdev_simple_match_insert(pmd, flow);
    }

    offload_flow_put(pmd, flow, match, actions, actions_len);
    log_netdev_flow_change(flow, match, NULL, actions, actions_len);

    return flow;
}

/* 在单个 PMD 线程上执行 flow_put（创建或修改流）：
 * CREATE: 若流不存在则调用 dp_netdev_flow_add 创建
 * MODIFY: 若流已存在则替换其 actions（RCU 安全替换） */
static int
flow_put_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct netdev_flow_key *key,
                struct match *match,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow *netdev_flow = NULL;
    int error = 0;

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    ovs_mutex_lock(&pmd->flow_mutex);
    if (put->ufid) {
        netdev_flow = dp_netdev_pmd_find_flow(pmd, put->ufid,
                                              put->key, put->key_len);
    } else {
        /* Use key instead of the locally generated ufid
         * to search netdev_flow. */
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
    }

    if (put->flags & DPIF_FP_CREATE) {
        if (!netdev_flow) {
            dp_netdev_flow_add(pmd, match, ufid,
                               put->actions, put->actions_len, ODPP_NONE);
        } else {
            error = EEXIST;
        }
        goto exit;
    }

    if (put->flags & DPIF_FP_MODIFY) {
        if (!netdev_flow) {
            error = ENOENT;
        } else {
            if (!put->ufid && !flow_equal(&match->flow, &netdev_flow->flow)) {
                /* Overlapping flow. */
                error = EINVAL;
                goto exit;
            }

            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

            offload_flow_put(pmd, netdev_flow, match, put->actions,
                             put->actions_len);
            log_netdev_flow_change(netdev_flow, match, old_actions,
                                   put->actions, put->actions_len);

            if (stats) {
                get_dpif_flow_status(pmd->dp, netdev_flow, stats, NULL);
            }
            if (put->flags & DPIF_FP_ZERO_STATS) {
                /* XXX: The userspace datapath uses thread local statistics
                 * (for flows), which should be updated only by the owning
                 * thread.  Since we cannot write on stats memory here,
                 * we choose not to support this flag.  Please note:
                 * - This feature is currently used only by dpctl commands with
                 *   option --clear.
                 * - Should the need arise, this operation can be implemented
                 *   by keeping a base value (to be update here) for each
                 *   counter, and subtracting it before outputting the stats */
                error = EOPNOTSUPP;
            }
            ovsrcu_postpone(dp_netdev_actions_free, old_actions);
        }
    }

exit:
    ovs_mutex_unlock(&pmd->flow_mutex);
    return error;
}

/* dpif 接口的 flow_put 实现：解析 netlink key/mask，然后在指定或所有 PMD 上执行。
 * in_port 必须为精确匹配。 */
static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct netdev_flow_key key;
    struct dp_netdev_pmd_thread *pmd;
    struct match match;
    ovs_u128 ufid;
    int error;
    bool probe = put->flags & DPIF_FP_PROBE;

    if (put->stats) {
        memset(put->stats, 0, sizeof *put->stats);
    }
    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &match.flow,
                                          probe);
    if (error) {
        return error;
    }
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &match.flow, &match.wc, probe);
    if (error) {
        return error;
    }

    if (match.wc.masks.in_port.odp_port != ODPP_NONE) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_ERR_RL(&rl, "failed to put%s flow: in_port is not an exact match",
                    (put->flags & DPIF_FP_CREATE) ? "[create]"
                    : (put->flags & DPIF_FP_MODIFY) ? "[modify]" : "[zero]");
        return EINVAL;
    }

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
        odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in handle_packet_upcall(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(VLAN_VID_MASK | VLAN_CFI);
    }

    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match.
     * We need to put in the unmasked key as flow_put_on_pmd() will first try
     * to see if an entry exists doing a packet type lookup. As masked-out
     * fields are interpreted as zeros, they could falsely match a wider IP
     * address mask. Installation of the flow will use the match variable. */
    netdev_flow_key_init(&key, &match.flow);

    if (put->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_put_on_pmd(pmd, &key, &match, &ufid, put,
                                        &pmd_stats);
            if (pmd_error) {
                error = pmd_error;
            } else if (put->stats) {
                put->stats->n_packets += pmd_stats.n_packets;
                put->stats->n_bytes += pmd_stats.n_bytes;
                put->stats->used = MAX(put->stats->used, pmd_stats.used);
                put->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, put->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, put->stats);
        dp_netdev_pmd_unref(pmd);
    }

    return error;
}

/* 在单个 PMD 线程上删除流：按 UFID 查找并移除。 */
static int
flow_del_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_find_flow(pmd, del->ufid, del->key,
                                          del->key_len);
    if (netdev_flow) {
        if (stats) {
            get_dpif_flow_status(pmd->dp, netdev_flow, stats, NULL);
        }
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&pmd->flow_mutex);

    return error;
}

/* dpif 接口的 flow_del 实现：在指定或所有 PMD 上删除流，聚合统计信息。 */
static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    int error = 0;

    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

    if (del->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_del_on_pmd(pmd, &pmd_stats, del);
            if (pmd_error) {
                error = pmd_error;
            } else if (del->stats) {
                del->stats->n_packets += pmd_stats.n_packets;
                del->stats->n_bytes += pmd_stats.n_bytes;
                del->stats->used = MAX(del->stats->used, pmd_stats.used);
                del->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, del->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_del_on_pmd(pmd, del->stats, del);
        dp_netdev_pmd_unref(pmd);
    }


    return error;
}

/* =====================================================
 * 流表遍历（Flow Dump）实现。
 *
 * 用于 ovs-dpctl dump-flows 等命令，遍历所有 PMD 线程的流表。
 * 多线程安全：使用 mutex 保护遍历位置，支持并行 dump 线程。
 * ===================================================== */

/* 流遍历状态：记录当前遍历到的 PMD 线程和 flow 位置。 */
struct dpif_netdev_flow_dump {
    struct dpif_flow_dump up;
    struct cmap_position poll_thread_pos;  /* 当前 PMD 在 poll_threads 中的位置 */
    struct cmap_position flow_pos;         /* 当前流在 flow_table 中的位置 */
    struct dp_netdev_pmd_thread *cur_pmd;  /* 当前正在遍历的 PMD */
    int status;                            /* EOF 表示遍历结束 */
    struct ovs_mutex mutex;                /* 保护多线程并发遍历 */
};

static struct dpif_netdev_flow_dump *
dpif_netdev_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netdev_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_netdev_flow_dump_create(const struct dpif *dpif_, bool terse,
                             struct dpif_flow_dump_types *types)
{
    struct dpif_netdev_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_, terse, types);
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_netdev_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}

/* 每个 dump 线程的私有状态，包含批量转换时使用的临时缓冲区。 */
struct dpif_netdev_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_netdev_flow_dump *dump;
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
};

static struct dpif_netdev_flow_dump_thread *
dpif_netdev_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netdev_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_netdev_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);
    struct dpif_netdev_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_netdev_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);

    free(thread);
}

/* 批量返回下一批流表项。遍历逻辑：
 * 1) 从当前 PMD 的 flow_table 中取最多 flow_limit 条流
 * 2) 当前 PMD 遍历完后切换到下一个 PMD
 * 3) 所有 PMD 遍历完后设 status=EOF
 * 4) 将内部流转换为 dpif_flow 格式返回 */
static int
dpif_netdev_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                           struct dpif_flow *flows, int max_flows)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);
    struct dpif_netdev_flow_dump *dump = thread->dump;
    struct dp_netdev_flow *netdev_flows[FLOW_DUMP_MAX_BATCH];
    struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dump->dpif);
    struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);
    int n_flows = 0;
    int i;

    ovs_mutex_lock(&dump->mutex);
    if (!dump->status) {
        struct dp_netdev_pmd_thread *pmd = dump->cur_pmd;
        int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

        /* First call to dump_next(), extracts the first pmd thread.
         * If there is no pmd thread, returns immediately. */
        if (!pmd) {
            pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
            if (!pmd) {
                ovs_mutex_unlock(&dump->mutex);
                return n_flows;

            }
        }

        do {
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                struct cmap_node *node;

                node = cmap_next_position(&pmd->flow_table, &dump->flow_pos);
                if (!node) {
                    break;
                }
                netdev_flows[n_flows] = CONTAINER_OF(node,
                                                     struct dp_netdev_flow,
                                                     node);
            }
            /* When finishing dumping the current pmd thread, moves to
             * the next. */
            if (n_flows < flow_limit) {
                memset(&dump->flow_pos, 0, sizeof dump->flow_pos);
                dp_netdev_pmd_unref(pmd);
                pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
                if (!pmd) {
                    dump->status = EOF;
                    break;
                }
            }
            /* Keeps the reference to next caller. */
            dump->cur_pmd = pmd;

            /* If the current dump is empty, do not exit the loop, since the
             * remaining pmds could have flows to be dumped.  Just dumps again
             * on the new 'pmd'. */
        } while (!n_flows);
    }
    ovs_mutex_unlock(&dump->mutex);

    for (i = 0; i < n_flows; i++) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];
        struct odputil_keybuf *keybuf = &thread->keybuf[i];
        struct dp_netdev_flow *netdev_flow = netdev_flows[i];
        struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask;

        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        dp_netdev_flow_to_dpif_flow(dp, netdev_flow, &key, &mask, f,
                                    dump->up.terse);
    }

    return n_flows;
}

/* dpif 接口的 execute 实现：对单个报文执行指定 actions（慢路径）。
 * 用于 packet-out、BFD 等非数据面生成的报文。
 * 非 PMD 线程调用时需加 non_pmd_mutex。 */
static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    struct dp_packet_batch pp;

    if (dp_packet_size(execute->packet) < ETH_HEADER_LEN ||
        dp_packet_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* Tries finding the 'pmd'.  If NULL is returned, that means
     * the current thread is a non-pmd thread and should use
     * dp_netdev_get_pmd(dp, NON_PMD_CORE_ID). */
    pmd = ovsthread_getspecific(dp->per_pmd_key);
    if (!pmd) {
        pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
        if (!pmd) {
            return EBUSY;
        }
    }

    if (execute->probe) {
        /* If this is part of a probe, Drop the packet, since executing
         * the action may actually cause spurious packets be sent into
         * the network. */
        if (pmd->core_id == NON_PMD_CORE_ID) {
            dp_netdev_pmd_unref(pmd);
        }
        return 0;
    }

    /* If the current thread is non-pmd thread, acquires
     * the 'non_pmd_mutex'. */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
    }

    /* Update current time in PMD context. We don't care about EMC insertion
     * probability, because we are on a slow path. */
    pmd_thread_ctx_time_update(pmd);

    /* The action processing expects the RSS hash to be valid, because
     * it's always initialized at the beginning of datapath processing.
     * In this case, though, 'execute->packet' may not have gone through
     * the datapath at all, it may have been generated by the upper layer
     * (OpenFlow packet-out, BFD frame, ...). */
    if (!dp_packet_rss_valid(execute->packet)) {
        dp_packet_set_rss_hash(execute->packet,
                               flow_hash_5tuple(execute->flow, 0));
    }

    /* Making a copy because the packet might be stolen during the execution
     * and caller might still need it.  */
    struct dp_packet *packet_clone = dp_packet_clone(execute->packet);
    dp_packet_batch_init_packet(&pp, packet_clone);
    dp_netdev_execute_actions(pmd, &pp, false, execute->flow,
                              execute->actions, execute->actions_len);
    dp_netdev_pmd_flush_output_packets(pmd, true);

    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_unlock(&dp->non_pmd_mutex);
        dp_netdev_pmd_unref(pmd);
    }

    if (dp_packet_batch_size(&pp) == 1) {
        /* Packet wasn't dropped during the execution.  Swapping content with
         * the original packet, because the caller might expect actions to
         * modify it.  Uisng the packet from a batch instead of 'packet_clone'
         * because it maybe stolen and replaced by other packet, e.g. by
         * the fragmentation engine. */
        dp_packet_swap(execute->packet, pp.packets[0]);
        dp_packet_delete_batch(&pp, true);
    } else if (dp_packet_batch_size(&pp)) {
        /* FIXME: We have more packets than expected.  Likely, we got IP
         * fragments of the reassembled packet.  Dropping them here as we have
         * no way to get them to the caller.  It might be that all the required
         * actions with them are already executed, but it also might not be a
         * case, e.g. if dpif_netdev_execute() called to execute a single
         * tunnel push. */
        dp_packet_delete_batch(&pp, true);
    }

    return 0;
}

/* dpif 接口的批量操作入口：依次执行 flow_put/flow_del/execute/flow_get。 */
static void
dpif_netdev_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    size_t i;

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            op->error = dpif_netdev_flow_put(dpif, &op->flow_put);
            break;

        case DPIF_OP_FLOW_DEL:
            op->error = dpif_netdev_flow_del(dpif, &op->flow_del);
            break;

        case DPIF_OP_EXECUTE:
            op->error = dpif_netdev_execute(dpif, &op->execute);
            break;

        case DPIF_OP_FLOW_GET:
            op->error = dpif_netdev_flow_get(dpif, &op->flow_get);
            break;
        }
    }
}

/* =====================================================
 * PMD 自动负载均衡（Auto Load Balance）配置。
 *
 * 启用后，系统定期检查各 PMD 的负载率。
 * 当负载超过阈值时标记 PMD 过载，触发 RXQ 重新分配。
 * ===================================================== */

/* Enable or Disable PMD auto load balancing. */
/* 启用/禁用 PMD 自动负载均衡，记录当前配置参数。 */
static void
set_pmd_auto_lb(struct dp_netdev *dp, bool state, bool always_log)
{
    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;

    if (pmd_alb->is_enabled != state || always_log) {
        pmd_alb->is_enabled = state;
        if (pmd_alb->is_enabled) {
            uint8_t rebalance_load_thresh;

            atomic_read_relaxed(&pmd_alb->rebalance_load_thresh,
                                &rebalance_load_thresh);
            VLOG_INFO("PMD auto load balance is enabled, "
                      "interval %"PRIu64" mins, "
                      "pmd load threshold %"PRIu8"%%, "
                      "improvement threshold %"PRIu8"%%.",
                       pmd_alb->rebalance_intvl / MIN_TO_MSEC,
                       rebalance_load_thresh,
                       pmd_alb->rebalance_improve_thresh);
        } else {
            pmd_alb->rebalance_poll_timer = 0;
            VLOG_INFO("PMD auto load balance is disabled.");
        }
    }
}

/* =====================================================
 * PMD 睡眠（Sleep）配置。
 *
 * 当 PMD 空闲时可短暂 usleep 减少 CPU 占用。
 * pmd-sleep-max 参数控制每个 PMD 的最大睡眠时间（微秒）。
 * 支持全局默认值和每个 core 的独立配置。
 * ===================================================== */

/* 解析 pmd-sleep-max 配置字符串，格式为 "core_id:max_sleep" 或 "default_sleep"。 */
static int
parse_pmd_sleep_list(const char *max_sleep_list,
                     struct pmd_sleep **pmd_sleeps)
{
    char *list, *copy, *key, *value;
    int num_vals = 0;

    if (!max_sleep_list) {
        return num_vals;
    }

    list = copy = xstrdup(max_sleep_list);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        uint64_t temp, pmd_max_sleep;
        char *error = NULL;
        unsigned core;
        int i;

        error = str_to_u64(key, &temp);
        if (error) {
            free(error);
            continue;
        }

        if (value[0] == '\0') {
            /* No value specified. key is dp default. */
            core = UINT_MAX;
            pmd_max_sleep = temp;
        } else {
            error = str_to_u64(value, &pmd_max_sleep);
            if (!error && temp < UINT_MAX) {
                /* Key is pmd core id. */
                core = (unsigned) temp;
            } else {
                free(error);
                continue;
            }
        }

        /* Detect duplicate max sleep values. */
        for (i = 0; i < num_vals; i++) {
            if ((*pmd_sleeps)[i].core_id == core) {
                break;
            }
        }
        if (i == num_vals) {
            /* Not duplicate, add a new entry. */
            *pmd_sleeps = xrealloc(*pmd_sleeps,
                                   (num_vals + 1) * sizeof **pmd_sleeps);
            num_vals++;
        }

        pmd_max_sleep = MIN(PMD_RCU_QUIESCE_INTERVAL, pmd_max_sleep);

        (*pmd_sleeps)[i].core_id = core;
        (*pmd_sleeps)[i].max_sleep = pmd_max_sleep;
    }

    free(copy);
    return num_vals;
}

static void
log_pmd_sleep(unsigned core_id, int numa_id, uint64_t pmd_max_sleep)
{
    if (core_id == NON_PMD_CORE_ID) {
        return;
    }
    VLOG_INFO("PMD thread on numa_id: %d, core id: %2d, "
              "max sleep: %4"PRIu64" us.", numa_id, core_id, pmd_max_sleep);
}

/* 初始化 PMD 的 max_sleep 值：先用全局默认值，再检查是否有针对该 core 的配置。 */
static void
pmd_init_max_sleep(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    uint64_t max_sleep = dp->pmd_max_sleep_default;
    struct pmd_sleep *pmd_sleeps = NULL;
    int num_vals;

    num_vals = parse_pmd_sleep_list(dp->max_sleep_list, &pmd_sleeps);

    /* Check if the user has set a specific value for this pmd. */
    for (int i = 0; i < num_vals; i++) {
        if (pmd_sleeps[i].core_id == pmd->core_id) {
            max_sleep = pmd_sleeps[i].max_sleep;
            break;
        }
    }
    atomic_init(&pmd->max_sleep, max_sleep);
    log_pmd_sleep(pmd->core_id, pmd->numa_id, max_sleep);
    free(pmd_sleeps);
}

/* 将解析后的 sleep 配置应用到所有 PMD 线程。返回是否有值发生变化。 */
static bool
assign_sleep_values_to_pmds(struct dp_netdev *dp, int num_vals,
                            struct pmd_sleep *pmd_sleeps)
{
    struct dp_netdev_pmd_thread *pmd;
    bool value_changed = false;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        uint64_t new_max_sleep, cur_pmd_max_sleep;

        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }

        /* Default to global value. */
        new_max_sleep = dp->pmd_max_sleep_default;

        /* Check for pmd specific value. */
        for (int i = 0;  i < num_vals; i++) {
            if (pmd->core_id == pmd_sleeps[i].core_id) {
                new_max_sleep = pmd_sleeps[i].max_sleep;
                break;
            }
        }
        atomic_read_relaxed(&pmd->max_sleep, &cur_pmd_max_sleep);
        if (new_max_sleep != cur_pmd_max_sleep) {
            atomic_store_relaxed(&pmd->max_sleep, new_max_sleep);
            value_changed = true;
        }
    }
    return value_changed;
}

/* 日志输出所有 PMD 的 sleep 配置值。 */
static void
log_all_pmd_sleeps(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread **pmd_list = NULL;
    struct dp_netdev_pmd_thread *pmd;
    size_t n;

    VLOG_INFO("Default PMD thread max sleep: %4"PRIu64" us.",
              dp->pmd_max_sleep_default);

    sorted_poll_thread_list(dp, &pmd_list, &n);

    for (size_t i = 0; i < n; i++) {
        uint64_t cur_pmd_max_sleep;

        pmd = pmd_list[i];
        atomic_read_relaxed(&pmd->max_sleep, &cur_pmd_max_sleep);
        log_pmd_sleep(pmd->core_id, pmd->numa_id, cur_pmd_max_sleep);
    }
    free(pmd_list);
}

/* 从 OVSDB 配置中读取并设置所有 PMD 的 max_sleep 值。 */
static bool
set_all_pmd_max_sleeps(struct dp_netdev *dp, const struct smap *config)
{
    const char *max_sleep_list = smap_get(config, "pmd-sleep-max");
    struct pmd_sleep *pmd_sleeps = NULL;
    uint64_t default_max_sleep = 0;
    bool default_changed = false;
    bool pmd_changed = false;
    uint64_t pmd_maxsleep;
    int num_vals = 0;

    /* Check for deprecated 'pmd-maxsleep' value. */
    pmd_maxsleep = smap_get_ullong(config, "pmd-maxsleep", UINT64_MAX);
    if (pmd_maxsleep != UINT64_MAX && !max_sleep_list) {
        VLOG_WARN_ONCE("pmd-maxsleep is deprecated. "
                       "Please use pmd-sleep-max instead.");
        default_max_sleep = pmd_maxsleep;
    }

    /* Check if there is no change in string or value. */
    if (!!dp->max_sleep_list == !!max_sleep_list) {
        if (max_sleep_list
            ? nullable_string_is_equal(max_sleep_list, dp->max_sleep_list)
            : default_max_sleep == dp->pmd_max_sleep_default) {
            return false;
        }
    }

    /* Free existing string and copy new one (if any). */
    free(dp->max_sleep_list);
    dp->max_sleep_list = nullable_xstrdup(max_sleep_list);

    if (max_sleep_list) {
        num_vals = parse_pmd_sleep_list(max_sleep_list, &pmd_sleeps);

        /* Check if the user has set a global value. */
        for (int i = 0; i < num_vals; i++) {
            if (pmd_sleeps[i].core_id == UINT_MAX) {
                default_max_sleep = pmd_sleeps[i].max_sleep;
                break;
            }
        }
    }

    if (dp->pmd_max_sleep_default != default_max_sleep) {
        dp->pmd_max_sleep_default = default_max_sleep;
        default_changed = true;
    }
    pmd_changed = assign_sleep_values_to_pmds(dp, num_vals, pmd_sleeps);

    free(pmd_sleeps);
    return default_changed || pmd_changed;
}

/* Applies datapath configuration from the database. Some of the changes are
 * actually applied in dpif_netdev_run(). */
/* dpif 接口的 set_config 实现：从 OVSDB other_config 读取配置并应用。
 * 主要配置项：
 * - pmd-cpu-mask: PMD 线程绑核掩码
 * - emc-insert-inv-prob: EMC 插入概率（1/N）
 * - smc-enable: SMC 缓存开关
 * - pmd-rxq-assign: RXQ 分配策略（roundrobin/cycles/group）
 * - pmd-sleep-max: PMD 空闲睡眠上限
 * - tx-flush-interval: TX 刷新间隔
 * - pmd-perf-metrics: 性能指标采集开关
 * - pmd-auto-lb*: 自动负载均衡参数 */
static int
dpif_netdev_set_config(struct dpif *dpif, const struct smap *other_config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    const char *cmask = smap_get(other_config, "pmd-cpu-mask");
    const char *pmd_rxq_assign = smap_get_def(other_config, "pmd-rxq-assign",
                                             "cycles");
    unsigned long long insert_prob =
        smap_get_ullong(other_config, "emc-insert-inv-prob",
                        DEFAULT_EM_FLOW_INSERT_INV_PROB);
    uint32_t insert_min, cur_min;
    uint32_t tx_flush_interval, cur_tx_flush_interval;
    uint64_t rebalance_intvl;
    uint8_t cur_rebalance_load;
    uint32_t rebalance_load, rebalance_improve;
    bool log_autolb = false;
    enum sched_assignment_type pmd_rxq_assign_type;
    static bool first_set_config = true;

    tx_flush_interval = smap_get_int(other_config, "tx-flush-interval",
                                     DEFAULT_TX_FLUSH_INTERVAL);
    atomic_read_relaxed(&dp->tx_flush_interval, &cur_tx_flush_interval);
    if (tx_flush_interval != cur_tx_flush_interval) {
        atomic_store_relaxed(&dp->tx_flush_interval, tx_flush_interval);
        VLOG_INFO("Flushing interval for tx queues set to %"PRIu32" us",
                  tx_flush_interval);
    }

    if (!nullable_string_is_equal(dp->pmd_cmask, cmask)) {
        free(dp->pmd_cmask);
        dp->pmd_cmask = nullable_xstrdup(cmask);
        dp_netdev_request_reconfigure(dp);
    }

    atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
    if (insert_prob <= UINT32_MAX) {
        insert_min = insert_prob == 0 ? 0 : UINT32_MAX / insert_prob;
    } else {
        insert_min = DEFAULT_EM_FLOW_INSERT_MIN;
        insert_prob = DEFAULT_EM_FLOW_INSERT_INV_PROB;
    }

    if (insert_min != cur_min) {
        atomic_store_relaxed(&dp->emc_insert_min, insert_min);
        if (insert_min == 0) {
            VLOG_INFO("EMC insertion probability changed to zero");
        } else {
            VLOG_INFO("EMC insertion probability changed to 1/%llu (~%.2f%%)",
                      insert_prob, (100 / (float)insert_prob));
        }
    }

    bool perf_enabled = smap_get_bool(other_config, "pmd-perf-metrics", false);
    bool cur_perf_enabled;
    atomic_read_relaxed(&dp->pmd_perf_metrics, &cur_perf_enabled);
    if (perf_enabled != cur_perf_enabled) {
        atomic_store_relaxed(&dp->pmd_perf_metrics, perf_enabled);
        if (perf_enabled) {
            VLOG_INFO("PMD performance metrics collection enabled");
        } else {
            VLOG_INFO("PMD performance metrics collection disabled");
        }
    }

    bool smc_enable = smap_get_bool(other_config, "smc-enable", false);
    bool cur_smc;
    atomic_read_relaxed(&dp->smc_enable_db, &cur_smc);
    if (smc_enable != cur_smc) {
        atomic_store_relaxed(&dp->smc_enable_db, smc_enable);
        if (smc_enable) {
            VLOG_INFO("SMC cache is enabled");
        } else {
            VLOG_INFO("SMC cache is disabled");
        }
    }

    if (!strcmp(pmd_rxq_assign, "roundrobin")) {
        pmd_rxq_assign_type = SCHED_ROUNDROBIN;
    } else if (!strcmp(pmd_rxq_assign, "cycles")) {
        pmd_rxq_assign_type = SCHED_CYCLES;
    } else if (!strcmp(pmd_rxq_assign, "group")) {
        pmd_rxq_assign_type = SCHED_GROUP;
    } else {
        /* Default. */
        VLOG_WARN("Unsupported rx queue to PMD assignment mode in "
                  "pmd-rxq-assign. Defaulting to 'cycles'.");
        pmd_rxq_assign_type = SCHED_CYCLES;
        pmd_rxq_assign = "cycles";
    }
    if (dp->pmd_rxq_assign_type != pmd_rxq_assign_type) {
        dp->pmd_rxq_assign_type = pmd_rxq_assign_type;
        VLOG_INFO("Rxq to PMD assignment mode changed to: \'%s\'.",
                  pmd_rxq_assign);
        dp_netdev_request_reconfigure(dp);
    }

    bool pmd_iso = smap_get_bool(other_config, "pmd-rxq-isolate", true);

    if (pmd_rxq_assign_type != SCHED_GROUP && pmd_iso == false) {
        /* Invalid combination. */
        VLOG_WARN("pmd-rxq-isolate can only be set false "
                  "when using pmd-rxq-assign=group");
        pmd_iso = true;
    }
    if (dp->pmd_iso != pmd_iso) {
        dp->pmd_iso = pmd_iso;
        if (pmd_iso) {
            VLOG_INFO("pmd-rxq-affinity isolates PMD core");
        } else {
            VLOG_INFO("pmd-rxq-affinity does not isolate PMD core");
        }
        dp_netdev_request_reconfigure(dp);
    }

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;

    rebalance_intvl = smap_get_ullong(other_config,
                                      "pmd-auto-lb-rebal-interval",
                                      ALB_REBALANCE_INTERVAL);
    if (rebalance_intvl > MAX_ALB_REBALANCE_INTERVAL) {
        rebalance_intvl = ALB_REBALANCE_INTERVAL;
    }

    /* Input is in min, convert it to msec. */
    rebalance_intvl =
        rebalance_intvl ? rebalance_intvl * MIN_TO_MSEC : MIN_TO_MSEC;

    if (pmd_alb->rebalance_intvl != rebalance_intvl) {
        pmd_alb->rebalance_intvl = rebalance_intvl;
        VLOG_INFO("PMD auto load balance interval set to "
                  "%"PRIu64" mins\n", rebalance_intvl / MIN_TO_MSEC);
        log_autolb = true;
    }

    rebalance_improve = smap_get_uint(other_config,
                                      "pmd-auto-lb-improvement-threshold",
                                      ALB_IMPROVEMENT_THRESHOLD);
    if (rebalance_improve > 100) {
        rebalance_improve = ALB_IMPROVEMENT_THRESHOLD;
    }
    if (rebalance_improve != pmd_alb->rebalance_improve_thresh) {
        pmd_alb->rebalance_improve_thresh = rebalance_improve;
        VLOG_INFO("PMD auto load balance improvement threshold set to "
                  "%"PRIu32"%%", rebalance_improve);
        log_autolb = true;
    }

    rebalance_load = smap_get_uint(other_config, "pmd-auto-lb-load-threshold",
                                   ALB_LOAD_THRESHOLD);
    if (rebalance_load > 100) {
        rebalance_load = ALB_LOAD_THRESHOLD;
    }
    atomic_read_relaxed(&pmd_alb->rebalance_load_thresh, &cur_rebalance_load);
    if (rebalance_load != cur_rebalance_load) {
        atomic_store_relaxed(&pmd_alb->rebalance_load_thresh,
                             rebalance_load);
        VLOG_INFO("PMD auto load balance load threshold set to %"PRIu32"%%",
                  rebalance_load);
        log_autolb = true;
    }

    bool autolb_state = smap_get_bool(other_config, "pmd-auto-lb", false);

    set_pmd_auto_lb(dp, autolb_state, log_autolb);

    bool sleep_changed = set_all_pmd_max_sleeps(dp, other_config);
    if (first_set_config || sleep_changed) {
        log_all_pmd_sleeps(dp);
    }

    if (first_set_config) {
        dpif_offload_datapath_register_flow_unreference_cb(
            dpif, offload_flow_reference_unreference_cb);
    }

    first_set_config = false;
    return 0;
}

static bool
dpif_netdev_number_handlers_required(struct dpif *dpif_ OVS_UNUSED,
                                     uint32_t *n_handlers)
{
    *n_handlers = 0;
    return true;
}

/* Parses affinity list and returns result in 'core_ids'. */
static int
parse_affinity_list(const char *affinity_list, unsigned *core_ids, int n_rxq)
{
    unsigned i;
    char *list, *copy, *key, *value;
    int error = 0;

    for (i = 0; i < n_rxq; i++) {
        core_ids[i] = OVS_CORE_UNSPEC;
    }

    if (!affinity_list) {
        return 0;
    }

    list = copy = xstrdup(affinity_list);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        int rxq_id, core_id;

        if (!str_to_int(key, 0, &rxq_id) || rxq_id < 0
            || !str_to_int(value, 0, &core_id) || core_id < 0) {
            error = EINVAL;
            break;
        }

        if (rxq_id < n_rxq) {
            core_ids[rxq_id] = core_id;
        }
    }

    free(copy);
    return error;
}

/* Parses 'affinity_list' and applies configuration if it is valid. */
static int
dpif_netdev_port_set_rxq_affinity(struct dp_netdev_port *port,
                                  const char *affinity_list)
{
    unsigned *core_ids, i;
    int error = 0;

    core_ids = xmalloc(port->n_rxq * sizeof *core_ids);
    if (parse_affinity_list(affinity_list, core_ids, port->n_rxq)) {
        error = EINVAL;
        goto exit;
    }

    for (i = 0; i < port->n_rxq; i++) {
        port->rxqs[i].core_id = core_ids[i];
    }

exit:
    free(core_ids);
    return error;
}

/* Returns 'true' if one of the 'port's RX queues exists in 'poll_list'
 * of given PMD thread. */
static bool
dpif_netdev_pmd_polls_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_port *port)
    OVS_EXCLUDED(pmd->port_mutex)
{
    struct rxq_poll *poll;
    bool found = false;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        if (port == poll->rxq->port) {
            found = true;
            break;
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
    return found;
}

/* Updates port configuration from the database.  The changes are actually
 * applied in dpif_netdev_run(). */
/* 端口级配置更新：
 * - emc-enable: 控制该端口是否启用 EMC
 * - pmd-rxq-affinity: RXQ 到 PMD 的亲和性绑定
 * - tx-steering: TX 队列选择模式（thread 或 hash） */
static int
dpif_netdev_port_set_config(struct dpif *dpif, odp_port_t port_no,
                            const struct smap *cfg)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error = 0;
    const char *affinity_list = smap_get(cfg, "pmd-rxq-affinity");
    bool emc_enabled = smap_get_bool(cfg, "emc-enable", true);
    const char *tx_steering_mode = smap_get(cfg, "tx-steering");
    enum txq_req_mode txq_mode;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = get_port_by_number(dp, port_no, &port);
    if (error) {
        goto unlock;
    }

    if (emc_enabled != port->emc_enabled) {
        struct dp_netdev_pmd_thread *pmd;
        struct ds ds = DS_EMPTY_INITIALIZER;
        uint32_t cur_min, insert_prob;

        port->emc_enabled = emc_enabled;
        /* Mark for reload all the threads that polls this port and request
         * for reconfiguration for the actual reloading of threads. */
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dpif_netdev_pmd_polls_port(pmd, port)) {
                pmd->need_reload = true;
            }
        }
        dp_netdev_request_reconfigure(dp);

        ds_put_format(&ds, "%s: EMC has been %s.",
                      netdev_get_name(port->netdev),
                      (emc_enabled) ? "enabled" : "disabled");
        if (emc_enabled) {
            ds_put_cstr(&ds, " Current insertion probability is ");
            atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
            if (!cur_min) {
                ds_put_cstr(&ds, "zero.");
            } else {
                insert_prob = UINT32_MAX / cur_min;
                ds_put_format(&ds, "1/%"PRIu32" (~%.2f%%).",
                              insert_prob, 100 / (float) insert_prob);
            }
        }
        VLOG_INFO("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    /* Checking for RXq affinity changes. */
    if (netdev_is_pmd(port->netdev)
        && !nullable_string_is_equal(affinity_list, port->rxq_affinity_list)) {

        error = dpif_netdev_port_set_rxq_affinity(port, affinity_list);
        if (error) {
            goto unlock;
        }
        free(port->rxq_affinity_list);
        port->rxq_affinity_list = nullable_xstrdup(affinity_list);

        dp_netdev_request_reconfigure(dp);
    }

    if (nullable_string_is_equal(tx_steering_mode, "hash")) {
        txq_mode = TXQ_REQ_MODE_HASH;
    } else {
        txq_mode = TXQ_REQ_MODE_THREAD;
    }

    if (txq_mode != port->txq_requested_mode) {
        port->txq_requested_mode = txq_mode;
        VLOG_INFO("%s: Tx packet steering mode has been set to '%s'.",
                  netdev_get_name(port->netdev),
                  (txq_mode == TXQ_REQ_MODE_THREAD) ? "thread" : "hash");
        dp_netdev_request_reconfigure(dp);
    }

unlock:
    ovs_rwlock_unlock(&dp->port_rwlock);
    return error;
}

/* 队列到优先级的映射（userspace 数据面中直接映射）。 */
static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}


/* =====================================================
 * Actions 管理和 RXQ 周期统计。
 * ===================================================== */

/* Creates and returns a new 'struct dp_netdev_actions', whose actions are
 * a copy of the 'size' bytes of 'actions' input parameters. */
/* 创建 actions 副本（用于 RCU 安全替换）。 */
struct dp_netdev_actions *
dp_netdev_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_netdev_actions *netdev_actions;

    netdev_actions = xmalloc(sizeof *netdev_actions + size);
    netdev_actions->size = size;
    if (size) {
        memcpy(netdev_actions->actions, actions, size);
    }

    return netdev_actions;
}

/* 通过 RCU 安全地读取流的当前 actions。 */
struct dp_netdev_actions *
dp_netdev_flow_get_actions(const struct dp_netdev_flow *flow)
{
    return ovsrcu_get(struct dp_netdev_actions *, &flow->actions);
}

static void
dp_netdev_actions_free(struct dp_netdev_actions *actions)
{
    free(actions);
}

/* RXQ 处理周期统计函数组：set/add/get 跟踪每个 RXQ 的 CPU 开销，
 * 作为 RXQ 到 PMD 分配的负载均衡依据。
 * intrvl (interval) 系列维护环形缓冲区记录最近几个周期的数据。 */

static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
   atomic_store_relaxed(&rx->cycles[type], cycles);
}

static void
dp_netdev_rxq_add_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
    non_atomic_ullong_add(&rx->cycles[type], cycles);
}

static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles[type], &processing_cycles);
    return processing_cycles;
}

static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                                unsigned long long cycles)
{
    unsigned int idx = atomic_count_inc(&rx->intrvl_idx) % PMD_INTERVAL_MAX;
    atomic_store_relaxed(&rx->cycles_intrvl[idx], cycles);
}

static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles_intrvl[idx], &processing_cycles);
    return processing_cycles;
}

/* PMD 性能指标开关：仅当平台支持 8 字节无锁原子操作时才可用。 */
#if ATOMIC_ALWAYS_LOCK_FREE_8B
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd)
{
    bool pmd_perf_enabled;
    atomic_read_relaxed(&pmd->dp->pmd_perf_metrics, &pmd_perf_enabled);
    return pmd_perf_enabled;
}
#else
/* If stores and reads of 64-bit integers are not atomic, the full PMD
 * performance metrics are not available as locked access to 64 bit
 * integers would be prohibitively expensive. */
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd OVS_UNUSED)
{
    return false;
}
#endif

/* =====================================================
 * TX 输出刷新。
 *
 * 报文经过 action 执行后，先缓存在 tx_port 的 output_pkts 批次中，
 * 达到批次大小或超时后统一调用 netdev_send 发送。
 * ===================================================== */

/* 刷新单个端口的待发送报文批次：
 * - XPS_HASH 模式：按报文 hash 分配到不同 TX 队列
 * - XPS 模式：动态选择 TX 队列（可能有竞争）
 * - THREAD 模式：使用 PMD 的固定 TX 队列（无竞争）
 * 发送后记录耗时并按比例分配到各报文的来源 RXQ。 */
static int
dp_netdev_pmd_flush_output_on_port(struct dp_netdev_pmd_thread *pmd,
                                   struct tx_port *p)
{
    int i;
    int tx_qid;
    int output_cnt;
    bool concurrent_txqs;
    struct cycle_timer timer;
    uint64_t cycles;
    uint32_t tx_flush_interval;

    cycle_timer_start(&pmd->perf_stats, &timer);

    output_cnt = dp_packet_batch_size(&p->output_pkts);
    ovs_assert(output_cnt > 0);

    if (p->port->txq_mode == TXQ_MODE_XPS_HASH) {
        int n_txq = netdev_n_txq(p->port->netdev);

        /* Re-batch per txq based on packet hash. */
        struct dp_packet *packet;
        DP_PACKET_BATCH_FOR_EACH (j, packet, &p->output_pkts) {
            uint32_t hash;

            if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
                hash = dp_packet_get_rss_hash(packet);
            } else {
                struct flow flow;

                flow_extract(packet, &flow);
                hash = flow_hash_5tuple(&flow, 0);
            }
            dp_packet_batch_add(&p->txq_pkts[hash % n_txq], packet);
        }

        /* Flush batches of each Tx queues. */
        for (i = 0; i < n_txq; i++) {
            if (dp_packet_batch_is_empty(&p->txq_pkts[i])) {
                continue;
            }
            netdev_send(p->port->netdev, i, &p->txq_pkts[i], true);
            dp_packet_batch_init(&p->txq_pkts[i]);
        }
    } else {
        if (p->port->txq_mode == TXQ_MODE_XPS) {
            tx_qid = dpif_netdev_xps_get_tx_qid(pmd, p);
            concurrent_txqs = true;
        } else {
            tx_qid = pmd->static_tx_qid;
            concurrent_txqs = false;
        }
        netdev_send(p->port->netdev, tx_qid, &p->output_pkts, concurrent_txqs);
    }
    dp_packet_batch_init(&p->output_pkts);

    /* Update time of the next flush. */
    atomic_read_relaxed(&pmd->dp->tx_flush_interval, &tx_flush_interval);
    p->flush_time = pmd->ctx.now + tx_flush_interval;

    ovs_assert(pmd->n_output_batches > 0);
    pmd->n_output_batches--;

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_PKTS, output_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_BATCHES, 1);

    /* Distribute send cycles evenly among transmitted packets and assign to
     * their respective rx queues. */
    cycles = cycle_timer_stop(&pmd->perf_stats, &timer) / output_cnt;
    for (i = 0; i < output_cnt; i++) {
        if (p->output_pkts_rxqs[i]) {
            dp_netdev_rxq_add_cycles(p->output_pkts_rxqs[i],
                                     RXQ_CYCLES_PROC_CURR, cycles);
        }
    }

    return output_cnt;
}

/* 遍历所有输出端口，刷新已超时或 force 模式下的待发送批次。 */
static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force)
{
    struct tx_port *p;
    int output_cnt = 0;

    if (!pmd->n_output_batches) {
        return 0;
    }

    HMAP_FOR_EACH (p, node, &pmd->send_port_cache) {
        if (!dp_packet_batch_is_empty(&p->output_pkts)
            && (force || pmd->ctx.now >= p->flush_time)) {
            output_cnt += dp_netdev_pmd_flush_output_on_port(pmd, p);
        }
    }
    return output_cnt;
}

/* 从指定 RXQ 接收一批数据包并进行处理 — PMD 收包的核心入口。
 *
 * 完整流程：
 *   netdev_rxq_recv()        收包（DPDK burst / vhost dequeue）
 *     → netdev_input_func()  MFEX 优化路径（可选）
 *       → dp_netdev_input()  流表查找 + action 执行
 *         → flush_output()   刷新输出缓冲到网卡
 *
 * 返回值：本次收到并处理的包数（0 表示无包）。 */
static int
dp_netdev_process_rxq_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_rxq *rxq,
                           odp_port_t port_no)
{
    struct pmd_perf_stats *s = &pmd->perf_stats;
    struct dp_packet_batch batch;    /* 本次 burst 收到的包批次 */
    struct cycle_timer timer;        /* 计时器：统计收包+处理的总 TSC */
    int error;
    int batch_cnt = 0;               /* 收到的包数 */
    int rem_qlen = 0, *qlen_p = NULL; /* vhost 队列剩余长度（仅 vhost 端口） */
    uint64_t cycles;

    /* 启动计时器，记录从收包到处理完成的全部 CPU 周期 */
    cycle_timer_start(&pmd->perf_stats, &timer);

    /* 设置当前正在处理的 RXQ（用于 action 执行时关联入队列） */
    pmd->ctx.last_rxq = rxq;
    dp_packet_batch_init(&batch);

    /* 仅对 vhost 端口获取队列剩余长度（用于监控队列填充率） */
    if (pmd_perf_metrics_enabled(pmd) && rxq->is_vhost) {
        qlen_p = &rem_qlen;
    }

    /* === 核心收包调用 ===
     * 对 DPDK 端口：调用 rte_eth_rx_burst() 批量收包
     * 对 vhost 端口：调用 rte_vhost_dequeue_burst() 从 VM 收包
     * 返回 0 表示成功收到包，EAGAIN 表示无包可收 */
    error = netdev_rxq_recv(rxq->rx, &batch, qlen_p);
    if (!error) {
        /* 收到至少一个包 */

        /* 重置 recirculation 深度计数器（新包从深度 0 开始） */
        *recirc_depth_get() = 0;
        /* 更新 PMD 上下文中的时间戳 */
        pmd_thread_ctx_time_update(pmd);
        batch_cnt = dp_packet_batch_size(&batch);

        /* 更新性能指标（仅在 pmd-perf-show 启用时） */
        if (pmd_perf_metrics_enabled(pmd)) {
            /* 批次计数 + 每批包数直方图 */
            s->current.batches++;
            histogram_add_sample(&s->pkts_per_batch, batch_cnt);
            /* 记录 vhost 队列最大填充水位（收到的包 + 队列中剩余的包） */
            if (rxq->is_vhost && rem_qlen >= 0) {
                uint32_t qfill = batch_cnt + rem_qlen;
                if (qfill > s->current.max_vhost_qfill) {
                    s->current.max_vhost_qfill = qfill;
                }
            }
        }

        /* @veencn_260223: 为每个包打上收包时刻的 TSC 时间戳 */
        LATENCY(pmd, STAMP_BATCH, &batch);

        /* === 核心处理调用 ===
         * 先尝试 MFEX 优化路径（netdev_input_func，如 AVX512 miniflow 提取），
         * 如果返回非零（不支持或失败），回退到通用的 dp_netdev_input()。
         * dp_netdev_input 内部完成：miniflow 提取 → EMC/SMC/dpcls 查找 → 执行 action */
        int ret = pmd->netdev_input_func(pmd, &batch, port_no);
        if (ret) {
            dp_netdev_input(pmd, &batch, port_no);
        }

        /* 停止计时器，将本次收包+处理的总 CPU 周期数累加到 RXQ 统计。
         * 这些数据被 dp_netdev_pmd_try_optimize() 采集，
         * 用于 RXQ 到 PMD 的负载均衡分配决策。 */
        cycles = cycle_timer_stop(&pmd->perf_stats, &timer);
        dp_netdev_rxq_add_cycles(rxq, RXQ_CYCLES_PROC_CURR, cycles);

        /* 刷新所有端口的输出缓冲（将 action 执行期间缓冲的包实际发送出去） */
        dp_netdev_pmd_flush_output_packets(pmd, false);
    } else {
        /* 无包可收 — 丢弃本次计时（不计入 RXQ 处理周期） */
        cycle_timer_stop(&pmd->perf_stats, &timer);
        /* EAGAIN = 队列为空（正常），EOPNOTSUPP = 不支持的操作（正常）。
         * 其他错误则限速打印日志。 */
        if (error != EAGAIN && error != EOPNOTSUPP) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                    netdev_rxq_get_name(rxq->rx), ovs_strerror(error));
        }
    }

    /* 清除当前 RXQ 关联（表示本轮处理结束） */
    pmd->ctx.last_rxq = NULL;

    return batch_cnt;
}

/* 在 hmap 中按端口号查找 tx_port（发送端口缓存）。 */
static struct tx_port *
tx_port_lookup(const struct hmap *hmap, odp_port_t port_no)
{
    struct tx_port *tx;

    HMAP_FOR_EACH_IN_BUCKET (tx, node, hash_port_no(port_no), hmap) {
        if (tx->port->port_no == port_no) {
            return tx;
        }
    }

    return NULL;
}

/* 在 cmap 中按 bond_id 查找 tx_bond（bond 发送缓存）。 */
static struct tx_bond *
tx_bond_lookup(const struct cmap *tx_bonds, uint32_t bond_id)
{
    uint32_t hash = hash_bond_id(bond_id);
    struct tx_bond *tx;

    CMAP_FOR_EACH_WITH_HASH (tx, node, hash, tx_bonds) {
        if (tx->bond_id == bond_id) {
            return tx;
        }
    }
    return NULL;
}

/* 重新配置端口的 RXQ：关闭已有队列，应用 netdev 配置变更，重新打开。
 * 在 reconfigure_datapath 中被调用。 */
static int
port_reconfigure(struct dp_netdev_port *port)
{
    struct netdev *netdev = port->netdev;
    int i, err;

    /* Closes the existing 'rxq's. */
    for (i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
        port->rxqs[i].rx = NULL;
    }
    unsigned last_nrxq = port->n_rxq;
    port->n_rxq = 0;

    /* Allows 'netdev' to apply the pending configuration changes. */
    if (netdev_is_reconf_required(netdev) || port->need_reconfigure) {
        err = netdev_reconfigure(netdev);
        if (err && (err != EOPNOTSUPP)) {
            VLOG_ERR("Failed to set interface %s new configuration",
                     netdev_get_name(netdev));
            return err;
        }
    }
    /* If the netdev_reconfigure() above succeeds, reopens the 'rxq's. */
    port->rxqs = xrealloc(port->rxqs,
                          sizeof *port->rxqs * netdev_n_rxq(netdev));
    /* Realloc 'used' counters for tx queues. */
    free(port->txq_used);
    port->txq_used = xcalloc(netdev_n_txq(netdev), sizeof *port->txq_used);

    for (i = 0; i < netdev_n_rxq(netdev); i++) {
        bool new_queue = i >= last_nrxq;
        if (new_queue) {
            memset(&port->rxqs[i], 0, sizeof port->rxqs[i]);
        }

        port->rxqs[i].port = port;
        port->rxqs[i].is_vhost = !strncmp(port->type, "dpdkvhost", 9);

        err = netdev_rxq_open(netdev, &port->rxqs[i].rx, i);
        if (err) {
            return err;
        }
        port->n_rxq++;
    }

    /* Parse affinity list to apply configuration for new queues. */
    dpif_netdev_port_set_rxq_affinity(port, port->rxq_affinity_list);

    /* If reconfiguration was successful mark it as such, so we can use it */
    port->need_reconfigure = false;

    return 0;
}

/* =====================================================
 * RXQ 调度器（Scheduler）数据结构和算法。
 *
 * 负责将各端口的 RXQ 分配到不同 PMD 线程，目标是负载均衡。
 * 支持三种策略：
 * - roundrobin: 轮询分配
 * - cycles: 按处理周期数排序，贪心分配给最空闲的 PMD
 * - group: 分组优化
 * ===================================================== */

/* NUMA 节点级别的调度信息列表。 */
struct sched_numa_list {
    struct hmap numas;  /* Contains 'struct sched_numa'. */
};

/* 调度器中每个 PMD 的状态：记录已分配的 RXQ 列表和累计处理周期。 */
struct sched_pmd {
    struct sched_numa *numa;
    /* Associated PMD thread. */
    struct dp_netdev_pmd_thread *pmd;
    uint64_t pmd_proc_cycles;
    struct dp_netdev_rxq **rxqs;
    unsigned n_rxq;
    bool isolated;
};

/* 调度器中每个 NUMA 节点的状态：包含该节点上所有 PMD 的信息。 */
struct sched_numa {
    struct hmap_node node;
    int numa_id;
    struct sched_pmd *pmds;     /* 该 NUMA 上的 PMD 数组 */
    unsigned n_pmds;            /* PMD 总数 */
    unsigned n_isolated;        /* 隔离 PMD 数（用于固定绑定） */
    int rr_cur_index;           /* roundrobin 当前索引 */
    bool rr_idx_inc;            /* roundrobin 方向标志 */
};

static size_t
sched_numa_list_count(struct sched_numa_list *numa_list)
{
    return hmap_count(&numa_list->numas);
}

static struct sched_numa *
sched_numa_list_next(struct sched_numa_list *numa_list,
                     const struct sched_numa *numa)
{
    struct hmap_node *node = NULL;

    if (numa) {
        node = hmap_next(&numa_list->numas, &numa->node);
    }
    if (!node) {
        node = hmap_first(&numa_list->numas);
    }

    return (node) ? CONTAINER_OF(node, struct sched_numa, node) : NULL;
}

static struct sched_numa *
sched_numa_list_lookup(struct sched_numa_list *numa_list, int numa_id)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH_WITH_HASH (numa, node, hash_int(numa_id, 0),
                             &numa_list->numas) {
        if (numa->numa_id == numa_id) {
            return numa;
        }
    }
    return NULL;
}

static int
compare_sched_pmd_list(const void *a_, const void *b_)
{
    struct sched_pmd *a, *b;

    a = (struct sched_pmd *) a_;
    b = (struct sched_pmd *) b_;

    return compare_poll_thread_list(&a->pmd, &b->pmd);
}

static void
sort_numa_list_pmds(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        if (numa->n_pmds > 1) {
            qsort(numa->pmds, numa->n_pmds, sizeof *numa->pmds,
                  compare_sched_pmd_list);
        }
    }
}

/* Populate numas and pmds on those numas. */
static void
sched_numa_list_populate(struct sched_numa_list *numa_list,
                         struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    hmap_init(&numa_list->numas);

    /* For each pmd on this datapath. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct sched_numa *numa;
        struct sched_pmd *sched_pmd;
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }

        /* Get the numa of the PMD. */
        numa = sched_numa_list_lookup(numa_list, pmd->numa_id);
        /* Create a new numa node for it if not already created. */
        if (!numa) {
            numa = xzalloc(sizeof *numa);
            numa->numa_id = pmd->numa_id;
            hmap_insert(&numa_list->numas, &numa->node,
                        hash_int(pmd->numa_id, 0));
        }

        /* Create a sched_pmd on this numa for the pmd. */
        numa->n_pmds++;
        numa->pmds = xrealloc(numa->pmds, numa->n_pmds * sizeof *numa->pmds);
        sched_pmd = &numa->pmds[numa->n_pmds - 1];
        memset(sched_pmd, 0, sizeof *sched_pmd);
        sched_pmd->numa = numa;
        sched_pmd->pmd = pmd;
        /* At least one pmd is present so initialize curr_idx and idx_inc. */
        numa->rr_cur_index = 0;
        numa->rr_idx_inc = true;
    }
    sort_numa_list_pmds(numa_list);
}

static void
sched_numa_list_free_entries(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH_POP (numa, node, &numa_list->numas) {
        for (unsigned i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            sched_pmd->n_rxq = 0;
            free(sched_pmd->rxqs);
        }
        numa->n_pmds = 0;
        free(numa->pmds);
        free(numa);
    }
    hmap_destroy(&numa_list->numas);
}

static struct sched_pmd *
sched_pmd_find_by_pmd(struct sched_numa_list *numa_list,
                      struct dp_netdev_pmd_thread *pmd)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        for (unsigned i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            if (pmd == sched_pmd->pmd) {
                return sched_pmd;
            }
        }
    }
    return NULL;
}

static void
sched_pmd_add_rxq(struct sched_pmd *sched_pmd, struct dp_netdev_rxq *rxq,
                  uint64_t cycles)
{
    /* As sched_pmd is allocated outside this fn. better to not assume
     * rxqs is initialized to NULL. */
    if (sched_pmd->n_rxq == 0) {
        sched_pmd->rxqs = xmalloc(sizeof *sched_pmd->rxqs);
    } else {
        sched_pmd->rxqs = xrealloc(sched_pmd->rxqs, (sched_pmd->n_rxq + 1) *
                                                    sizeof *sched_pmd->rxqs);
    }

    sched_pmd->rxqs[sched_pmd->n_rxq++] = rxq;
    sched_pmd->pmd_proc_cycles += cycles;
}

static void
sched_numa_list_assignments(struct sched_numa_list *numa_list,
                            struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    /* For each port. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }
        /* For each rxq on the port. */
        for (unsigned qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *rxq = &port->rxqs[qid];
            struct sched_pmd *sched_pmd;
            uint64_t proc_cycles = 0;

            for (int i = 0; i < PMD_INTERVAL_MAX; i++) {
                proc_cycles  += dp_netdev_rxq_get_intrvl_cycles(rxq, i);
            }

            sched_pmd = sched_pmd_find_by_pmd(numa_list, rxq->pmd);
            if (sched_pmd) {
                if (rxq->core_id != OVS_CORE_UNSPEC && dp->pmd_iso) {
                    sched_pmd->isolated = true;
                }
                sched_pmd_add_rxq(sched_pmd, rxq, proc_cycles);
            }
        }
    }
}

static void
sched_numa_list_put_in_place(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    /* For each numa. */
    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        /* For each pmd. */
        for (int i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            sched_pmd->pmd->isolated = sched_pmd->isolated;
            /* For each rxq. */
            for (unsigned k = 0; k < sched_pmd->n_rxq; k++) {
                /* Store the new pmd from the out of place sched_numa_list
                 * struct to the dp_netdev_rxq struct */
                sched_pmd->rxqs[k]->pmd = sched_pmd->pmd;
            }
        }
    }
}

/* Returns 'true' if OVS rxq scheduling algorithm assigned any unpinned rxq to
 * a PMD thread core on a non-local numa node. */
static bool
sched_numa_list_cross_numa_polling(struct sched_numa_list *numa_list)
{
    struct sched_numa *numa;

    HMAP_FOR_EACH (numa, node, &numa_list->numas) {
        for (int i = 0; i < numa->n_pmds; i++) {
            struct sched_pmd *sched_pmd;

            sched_pmd = &numa->pmds[i];
            if (sched_pmd->isolated) {
                /* All rxqs on this PMD thread core are pinned. */
                continue;
            }
            for (unsigned k = 0; k < sched_pmd->n_rxq; k++) {
                struct dp_netdev_rxq *rxq = sched_pmd->rxqs[k];
                /* Check if the rxq is not pinned to a specific PMD thread core
                 * by the user AND the PMD thread core that OVS assigned is
                 * non-local to the rxq port. */
                if (rxq->core_id == OVS_CORE_UNSPEC &&
                    rxq->pmd->numa_id !=
                        netdev_get_numa_id(rxq->port->netdev)) {
                    return true;
                }
            }
        }
    }
    return false;
}

static unsigned
sched_numa_noniso_pmd_count(struct sched_numa *numa)
{
    if (numa->n_pmds > numa->n_isolated) {
        return numa->n_pmds - numa->n_isolated;
    }
    return 0;
}

/* Sort Rx Queues by the processing cycles they are consuming. */
static int
compare_rxq_cycles(const void *a, const void *b)
{
    struct dp_netdev_rxq *qa;
    struct dp_netdev_rxq *qb;
    uint64_t cycles_qa, cycles_qb;

    qa = *(struct dp_netdev_rxq **) a;
    qb = *(struct dp_netdev_rxq **) b;

    cycles_qa = dp_netdev_rxq_get_cycles(qa, RXQ_CYCLES_PROC_HIST);
    cycles_qb = dp_netdev_rxq_get_cycles(qb, RXQ_CYCLES_PROC_HIST);

    if (cycles_qa != cycles_qb) {
        return (cycles_qa < cycles_qb) ? 1 : -1;
    } else {
        /* Cycles are the same so tiebreak on port/queue id.
         * Tiebreaking (as opposed to return 0) ensures consistent
         * sort results across multiple OS's. */
        uint32_t port_qa = odp_to_u32(qa->port->port_no);
        uint32_t port_qb = odp_to_u32(qb->port->port_no);
        if (port_qa != port_qb) {
            return port_qa > port_qb ? 1 : -1;
        } else {
            return netdev_rxq_get_queue_id(qa->rx)
                    - netdev_rxq_get_queue_id(qb->rx);
        }
    }
}

static bool
sched_pmd_new_lowest(struct sched_pmd *current_lowest, struct sched_pmd *pmd,
                     bool has_proc)
{
    uint64_t current_num, pmd_num;

    if (current_lowest == NULL) {
        return true;
    }

    if (has_proc) {
        current_num = current_lowest->pmd_proc_cycles;
        pmd_num = pmd->pmd_proc_cycles;
    } else {
        current_num = current_lowest->n_rxq;
        pmd_num = pmd->n_rxq;
    }

    if (pmd_num < current_num) {
        return true;
    }
    return false;
}

static struct sched_pmd *
sched_pmd_get_lowest(struct sched_numa *numa, bool has_cyc)
{
    struct sched_pmd *lowest_sched_pmd = NULL;

    for (unsigned i = 0; i < numa->n_pmds; i++) {
        struct sched_pmd *sched_pmd;

        sched_pmd = &numa->pmds[i];
        if (sched_pmd->isolated) {
            continue;
        }
        if (sched_pmd_new_lowest(lowest_sched_pmd, sched_pmd, has_cyc)) {
            lowest_sched_pmd = sched_pmd;
        }
    }
    return lowest_sched_pmd;
}

/*
 * Returns the next pmd from the numa node.
 *
 * If 'updown' is 'true' it will alternate between selecting the next pmd in
 * either an up or down walk, switching between up/down when the first or last
 * core is reached. e.g. 1,2,3,3,2,1,1,2...
 *
 * If 'updown' is 'false' it will select the next pmd wrapping around when
 * last core reached. e.g. 1,2,3,1,2,3,1,2...
 */
static struct sched_pmd *
sched_pmd_next_rr(struct sched_numa *numa, bool updown)
{
    int numa_idx = numa->rr_cur_index;

    if (numa->rr_idx_inc == true) {
        /* Incrementing through list of pmds. */
        if (numa->rr_cur_index == numa->n_pmds - 1) {
            /* Reached the last pmd. */
            if (updown) {
                numa->rr_idx_inc = false;
            } else {
                numa->rr_cur_index = 0;
            }
        } else {
            numa->rr_cur_index++;
        }
    } else {
        /* Decrementing through list of pmds. */
        if (numa->rr_cur_index == 0) {
            /* Reached the first pmd. */
            numa->rr_idx_inc = true;
        } else {
            numa->rr_cur_index--;
        }
    }
    return &numa->pmds[numa_idx];
}

static struct sched_pmd *
sched_pmd_next_noniso_rr(struct sched_numa *numa, bool updown)
{
    struct sched_pmd *sched_pmd = NULL;

    /* sched_pmd_next_rr() may return duplicate PMDs before all PMDs have been
     * returned depending on updown. Call it more than n_pmds to ensure all
     * PMDs can be searched for the next non-isolated PMD. */
    for (unsigned i = 0; i < numa->n_pmds * 2; i++) {
        sched_pmd = sched_pmd_next_rr(numa, updown);
        if (!sched_pmd->isolated) {
            break;
        }
        sched_pmd = NULL;
    }
    return sched_pmd;
}

static struct sched_pmd *
sched_pmd_next(struct sched_numa *numa, enum sched_assignment_type algo,
               bool has_proc)
{
    if (algo == SCHED_GROUP) {
        return sched_pmd_get_lowest(numa, has_proc);
    }

    /* By default RR the PMDs. */
    return sched_pmd_next_noniso_rr(numa, algo == SCHED_CYCLES ? true : false);
}

static const char *
get_assignment_type_string(enum sched_assignment_type algo)
{
    switch (algo) {
    case SCHED_ROUNDROBIN: return "roundrobin";
    case SCHED_CYCLES: return "cycles";
    case SCHED_GROUP: return "group";
    default: return "Unknown";
    }
}

#define MAX_RXQ_CYC_TEXT 40
#define MAX_RXQ_CYC_STRLEN (INT_STRLEN(uint64_t) + MAX_RXQ_CYC_TEXT)

static char *
get_rxq_cyc_log(char *a, enum sched_assignment_type algo, uint64_t cycles)
{
    int ret = 0;

    if (algo != SCHED_ROUNDROBIN) {
        ret = snprintf(a, MAX_RXQ_CYC_STRLEN,
                       " (measured processing cycles %"PRIu64")", cycles);
    }

    if (algo == SCHED_ROUNDROBIN || ret <= 0) {
        a[0] = '\0';
    }
    return a;
}

static void
sched_numa_list_schedule(struct sched_numa_list *numa_list,
                         struct dp_netdev *dp,
                         enum sched_assignment_type algo,
                         enum vlog_level level)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;
    struct dp_netdev_rxq **rxqs = NULL;
    struct sched_numa *last_cross_numa;
    unsigned n_rxqs = 0;
    bool start_logged = false;
    size_t n_numa;

    /* For each port. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        /* For each rxq on the port. */
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *rxq = &port->rxqs[qid];

            if (algo != SCHED_ROUNDROBIN) {
                uint64_t cycle_hist = 0;

                /* Sum the queue intervals and store the cycle history. */
                for (unsigned i = 0; i < PMD_INTERVAL_MAX; i++) {
                    cycle_hist += dp_netdev_rxq_get_intrvl_cycles(rxq, i);
                }
                dp_netdev_rxq_set_cycles(rxq, RXQ_CYCLES_PROC_HIST,
                                         cycle_hist);
            }

            /* Check if this rxq is pinned. */
            if (rxq->core_id != OVS_CORE_UNSPEC) {
                struct sched_pmd *sched_pmd;
                struct dp_netdev_pmd_thread *pmd;
                struct sched_numa *numa;
                bool iso = dp->pmd_iso;
                uint64_t proc_cycles;
                char rxq_cyc_log[MAX_RXQ_CYC_STRLEN];

                /* This rxq should be pinned, pin it now. */
                pmd = dp_netdev_get_pmd(dp, rxq->core_id);
                sched_pmd = sched_pmd_find_by_pmd(numa_list, pmd);
                dp_netdev_pmd_unref(pmd);
                if (!sched_pmd) {
                    /* Cannot find the PMD.  Cannot pin this rxq. */
                    VLOG(level == VLL_DBG ? VLL_DBG : VLL_WARN,
                            "Core %2u cannot be pinned with "
                            "port \'%s\' rx queue %d. Use pmd-cpu-mask to "
                            "enable a pmd on core %u. An alternative core "
                            "will be assigned.",
                            rxq->core_id,
                            netdev_rxq_get_name(rxq->rx),
                            netdev_rxq_get_queue_id(rxq->rx),
                            rxq->core_id);
                    rxqs = xrealloc(rxqs, (n_rxqs + 1) * sizeof *rxqs);
                    rxqs[n_rxqs++] = rxq;
                    continue;
                }
                if (iso) {
                    /* Mark PMD as isolated if not done already. */
                    if (sched_pmd->isolated == false) {
                        sched_pmd->isolated = true;
                        numa = sched_pmd->numa;
                        numa->n_isolated++;
                    }
                }
                proc_cycles = dp_netdev_rxq_get_cycles(rxq,
                                                       RXQ_CYCLES_PROC_HIST);
                VLOG(level, "Core %2u on numa node %d is pinned with "
                            "port \'%s\' rx queue %d%s",
                            sched_pmd->pmd->core_id, sched_pmd->pmd->numa_id,
                            netdev_rxq_get_name(rxq->rx),
                            netdev_rxq_get_queue_id(rxq->rx),
                            get_rxq_cyc_log(rxq_cyc_log, algo, proc_cycles));
                sched_pmd_add_rxq(sched_pmd, rxq, proc_cycles);
            } else {
                rxqs = xrealloc(rxqs, (n_rxqs + 1) * sizeof *rxqs);
                rxqs[n_rxqs++] = rxq;
            }
        }
    }

    if (n_rxqs > 1 && algo != SCHED_ROUNDROBIN) {
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }

    last_cross_numa = NULL;
    n_numa = sched_numa_list_count(numa_list);
    for (unsigned i = 0; i < n_rxqs; i++) {
        struct dp_netdev_rxq *rxq = rxqs[i];
        struct sched_pmd *sched_pmd = NULL;
        struct sched_numa *numa;
        int port_numa_id;
        uint64_t proc_cycles;
        char rxq_cyc_log[MAX_RXQ_CYC_STRLEN];

        if (start_logged == false && level != VLL_DBG) {
            VLOG(level, "Performing pmd to rx queue assignment using %s "
                        "algorithm.", get_assignment_type_string(algo));
            start_logged = true;
        }

        /* Store the cycles for this rxq as we will log these later. */
        proc_cycles = dp_netdev_rxq_get_cycles(rxq, RXQ_CYCLES_PROC_HIST);

        port_numa_id = netdev_get_numa_id(rxq->port->netdev);

        /* Select numa. */
        numa = sched_numa_list_lookup(numa_list, port_numa_id);

        /* Check if numa has no PMDs or no non-isolated PMDs. */
        if (!numa || !sched_numa_noniso_pmd_count(numa)) {
            /* Unable to use this numa to find a PMD. */
            numa = NULL;
            /* Find any numa with available PMDs. */
            for (int j = 0; j < n_numa; j++) {
                numa = sched_numa_list_next(numa_list, last_cross_numa);
                last_cross_numa = numa;
                if (sched_numa_noniso_pmd_count(numa)) {
                    break;
                }
                numa = NULL;
            }
        }

        if (numa) {
            /* Select the PMD that should be used for this rxq. */
            sched_pmd = sched_pmd_next(numa, algo,
                                       proc_cycles ? true : false);
        }

        /* Check that a pmd has been selected. */
        if (sched_pmd) {
            int pmd_numa_id;

            pmd_numa_id = sched_pmd->numa->numa_id;
            /* Check if selected pmd numa matches port numa. */
            if (pmd_numa_id != port_numa_id) {
                VLOG(level, "There's no available (non-isolated) pmd thread "
                            "on numa node %d. Port \'%s\' rx queue %d will "
                            "be assigned to a pmd on numa node %d. "
                            "This may lead to reduced performance.",
                            port_numa_id, netdev_rxq_get_name(rxq->rx),
                            netdev_rxq_get_queue_id(rxq->rx), pmd_numa_id);
            }
            VLOG(level, "Core %2u on numa node %d assigned port \'%s\' "
                        "rx queue %d%s.",
                        sched_pmd->pmd->core_id, sched_pmd->pmd->numa_id,
                        netdev_rxq_get_name(rxq->rx),
                        netdev_rxq_get_queue_id(rxq->rx),
                        get_rxq_cyc_log(rxq_cyc_log, algo, proc_cycles));
            sched_pmd_add_rxq(sched_pmd, rxq, proc_cycles);
        } else  {
            VLOG(level == VLL_DBG ? level : VLL_WARN,
                 "No non-isolated pmd on any numa available for "
                 "port \'%s\' rx queue %d%s. "
                 "This rx queue will not be polled.",
                 netdev_rxq_get_name(rxq->rx),
                 netdev_rxq_get_queue_id(rxq->rx),
                 get_rxq_cyc_log(rxq_cyc_log, algo, proc_cycles));
        }
    }
    free(rxqs);
}

static void
rxq_scheduling(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct sched_numa_list numa_list;
    enum sched_assignment_type algo = dp->pmd_rxq_assign_type;

    sched_numa_list_populate(&numa_list, dp);
    sched_numa_list_schedule(&numa_list, dp, algo, VLL_INFO);
    sched_numa_list_put_in_place(&numa_list);

    sched_numa_list_free_entries(&numa_list);
}

static uint64_t variance(uint64_t a[], int n);

static uint64_t
sched_numa_variance(struct sched_numa *numa)
{
    uint64_t *percent_busy = NULL;
    int n_proc = 0;
    uint64_t var;

    percent_busy = xmalloc(numa->n_pmds * sizeof *percent_busy);

    for (unsigned i = 0; i < numa->n_pmds; i++) {
        struct sched_pmd *sched_pmd;
        uint64_t total_cycles = 0;

        sched_pmd = &numa->pmds[i];
        /* Exclude isolated PMDs from variance calculations. */
        if (sched_pmd->isolated == true) {
            continue;
        }
        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&sched_pmd->pmd->intrvl_cycles, &total_cycles);

        if (total_cycles) {
            /* Estimate the cycles to cover all intervals. */
            total_cycles *= PMD_INTERVAL_MAX;
            percent_busy[n_proc++] = (sched_pmd->pmd_proc_cycles * 100)
                                            / total_cycles;
        } else {
            percent_busy[n_proc++] = 0;
        }
    }
    var = variance(percent_busy, n_proc);
    free(percent_busy);
    return var;
}

/*
 * This function checks that some basic conditions needed for a rebalance to be
 * effective are met. Such as Rxq scheduling assignment type, more than one
 * PMD, more than 2 Rxqs on a PMD. If there was no reconfiguration change
 * since the last check, it reuses the last result.
 *
 * It is not intended to be an inclusive check of every condition that may make
 * a rebalance ineffective. It is done as a quick check so a full
 * pmd_rebalance_dry_run() can be avoided when it is not needed.
 */
static bool
pmd_rebalance_dry_run_needed(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_pmd_thread *pmd;
    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    unsigned int cnt = 0;
    bool multi_rxq = false;

    /* Check if there was no reconfiguration since last check. */
    if (!pmd_alb->recheck_config) {
        if (!pmd_alb->do_dry_run) {
            VLOG_DBG("PMD auto load balance nothing to do, "
                     "no configuration changes since last check.");
            return false;
        }
        return true;
    }
    pmd_alb->recheck_config = false;

    /* Check for incompatible assignment type. */
    if (dp->pmd_rxq_assign_type == SCHED_ROUNDROBIN) {
        VLOG_DBG("PMD auto load balance nothing to do, "
                 "pmd-rxq-assign=roundrobin assignment type configured.");
        return pmd_alb->do_dry_run = false;
    }

    /* Check that there is at least 2 non-isolated PMDs and
     * one of them is polling more than one rxq. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

        if (hmap_count(&pmd->poll_list) > 1) {
            multi_rxq = true;
        }
        if (cnt && multi_rxq) {
            return pmd_alb->do_dry_run = true;
        }
        cnt++;
    }

    VLOG_DBG("PMD auto load balance nothing to do, "
             "not enough non-isolated PMDs or RxQs.");
    return pmd_alb->do_dry_run = false;
}

/* 自动负载均衡的预演（dry run）：
 * 比较当前分配和重新调度后的方差，判断是否值得重新分配。
 * 仅当方差改善达到阈值时才返回 true 触发实际重分配。 */
static bool
pmd_rebalance_dry_run(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct sched_numa_list numa_list_cur;
    struct sched_numa_list numa_list_est;
    bool thresh_met = false;

    VLOG_DBG("PMD auto load balance performing dry run.");

    /* Populate current assignments. */
    sched_numa_list_populate(&numa_list_cur, dp);
    sched_numa_list_assignments(&numa_list_cur, dp);

    /* Populate estimated assignments. */
    sched_numa_list_populate(&numa_list_est, dp);
    sched_numa_list_schedule(&numa_list_est, dp,
                             dp->pmd_rxq_assign_type, VLL_DBG);

    /* Check if cross-numa polling, there is only one numa with PMDs. */
    if (!sched_numa_list_cross_numa_polling(&numa_list_est) ||
            sched_numa_list_count(&numa_list_est) == 1) {
        struct sched_numa *numa_cur;

        /* Calculate variances. */
        HMAP_FOR_EACH (numa_cur, node, &numa_list_cur.numas) {
            uint64_t current_var, estimate_var;
            struct sched_numa *numa_est;
            uint64_t improvement = 0;

            numa_est = sched_numa_list_lookup(&numa_list_est,
                                              numa_cur->numa_id);
            if (!numa_est) {
                continue;
            }
            current_var = sched_numa_variance(numa_cur);
            estimate_var = sched_numa_variance(numa_est);
            if (estimate_var < current_var) {
                improvement = ((current_var - estimate_var) * 100)
                              / current_var;
            }
            VLOG_DBG("Numa node %d. Current variance %"PRIu64" Estimated "
                     "variance %"PRIu64". Variance improvement %"PRIu64"%%.",
                     numa_cur->numa_id, current_var,
                     estimate_var, improvement);
            if (improvement >= dp->pmd_alb.rebalance_improve_thresh) {
                thresh_met = true;
            }
        }
        VLOG_DBG("PMD load variance improvement threshold %u%% is %s.",
                 dp->pmd_alb.rebalance_improve_thresh,
                 thresh_met ? "met" : "not met");
    } else {
        VLOG_DBG("PMD auto load balance detected cross-numa polling with "
                 "multiple numa nodes. Unable to accurately estimate.");
    }

    sched_numa_list_free_entries(&numa_list_cur);
    sched_numa_list_free_entries(&numa_list_est);

    return thresh_met;
}

/* 通知所有需要重载的 PMD 线程执行重载，并等待它们完成。 */
static void
reload_affected_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            dp_netdev_reload_pmd__(pmd);
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            if (pmd->core_id != NON_PMD_CORE_ID) {
                bool reload;

                do {
                    atomic_read_explicit(&pmd->reload, &reload,
                                         memory_order_acquire);
                } while (reload);
            }
            pmd->need_reload = false;
        }
    }
}

/* 根据 pmd-cpu-mask 重新配置 PMD 线程：
 * 1) 销毁不再需要的 PMD 线程
 * 2) 创建新增的 PMD 线程（每个 core 一个）
 * 3) 必要时调整 static_tx_qid */
static void
reconfigure_pmd_threads(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_pmd_thread *pmd;
    struct ovs_numa_dump *pmd_cores;
    struct ovs_numa_info_core *core;
    struct hmapx to_delete = HMAPX_INITIALIZER(&to_delete);
    struct hmapx_node *node;
    bool changed = false;
    bool need_to_adjust_static_tx_qids = false;

    /* The pmd threads should be started only if there's a pmd port in the
     * datapath.  If the user didn't provide any "pmd-cpu-mask", we start
     * NR_PMD_THREADS per numa node. */
    if (!has_pmd_port(dp)) {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(0);
    } else if (dp->pmd_cmask && dp->pmd_cmask[0]) {
        pmd_cores = ovs_numa_dump_cores_with_cmask(dp->pmd_cmask);
    } else {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(NR_PMD_THREADS);
    }

    /* We need to adjust 'static_tx_qid's only if we're reducing number of
     * PMD threads. Otherwise, new threads will allocate all the freed ids. */
    if (ovs_numa_dump_count(pmd_cores) < cmap_count(&dp->poll_threads) - 1) {
        /* Adjustment is required to keep 'static_tx_qid's sequential and
         * avoid possible issues, for example, imbalanced tx queue usage
         * and unnecessary locking caused by remapping on netdev level. */
        need_to_adjust_static_tx_qids = true;
    }

    /* Check for unwanted pmd threads */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        if (!ovs_numa_dump_contains_core(pmd_cores, pmd->numa_id,
                                                    pmd->core_id)) {
            hmapx_add(&to_delete, pmd);
        } else if (need_to_adjust_static_tx_qids) {
            atomic_store_relaxed(&pmd->reload_tx_qid, true);
            pmd->need_reload = true;
        }
    }

    HMAPX_FOR_EACH (node, &to_delete) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        VLOG_INFO("PMD thread on numa_id: %d, core id: %2d destroyed.",
                  pmd->numa_id, pmd->core_id);
        dp_netdev_del_pmd(dp, pmd);
    }
    changed = !hmapx_is_empty(&to_delete);
    hmapx_destroy(&to_delete);

    if (need_to_adjust_static_tx_qids) {
        /* 'static_tx_qid's are not sequential now.
         * Reload remaining threads to fix this. */
        reload_affected_pmds(dp);
    }

    /* Check for required new pmd threads */
    FOR_EACH_CORE_ON_DUMP(core, pmd_cores) {
        pmd = dp_netdev_get_pmd(dp, core->core_id);
        if (!pmd) {
            struct ds name = DS_EMPTY_INITIALIZER;

            pmd = xzalloc(sizeof *pmd);
            dp_netdev_configure_pmd(pmd, dp, core->core_id, core->numa_id);

            ds_put_format(&name, "pmd-c%02d/id:", core->core_id);
            pmd->thread = ovs_thread_create(ds_cstr(&name),
                                            pmd_thread_main, pmd);
            ds_destroy(&name);

            VLOG_INFO("PMD thread on numa_id: %d, core id: %2d created.",
                      pmd->numa_id, pmd->core_id);
            changed = true;
        } else {
            dp_netdev_pmd_unref(pmd);
        }
    }

    if (changed) {
        struct ovs_numa_info_numa *numa;

        /* Log the number of pmd threads per numa node. */
        FOR_EACH_NUMA_ON_DUMP (numa, pmd_cores) {
            VLOG_INFO("There are %"PRIuSIZE" pmd threads on numa node %d",
                      numa->n_cores, numa->numa_id);
        }
    }

    ovs_numa_dump_destroy(pmd_cores);
}

/* 从 PMD 中移除已删除或需要重配置的端口的 RXQ 和 TX 缓存。 */
static void
pmd_remove_stale_ports(struct dp_netdev *dp,
                       struct dp_netdev_pmd_thread *pmd)
    OVS_EXCLUDED(pmd->port_mutex)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct rxq_poll *poll;
    struct tx_port *tx;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_SAFE (poll, node, &pmd->poll_list) {
        struct dp_netdev_port *port = poll->rxq->port;

        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_rxq_from_pmd(pmd, poll);
        }
    }
    HMAP_FOR_EACH_SAFE (tx, node, &pmd->tx_ports) {
        struct dp_netdev_port *port = tx->port;

        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_port_tx_from_pmd(pmd, tx);
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Must be called each time a port is added/removed or the cmask changes.
 * This creates and destroys pmd threads, reconfigures ports, opens their
 * rxqs and assigns all rxqs/txqs to pmd threads. */
/* 重新配置 datapath — 端口增删或 CPU 掩码变更时调用。
 * 核心流程：
 * 1. 重新配置所有端口（打开 RXQ、设置 TXQ 模式）
 * 2. 根据 pmd_cmask 创建/销毁 PMD 线程
 * 3. 将所有 RXQ 按调度策略分配到 PMD 线程
 * 4. 为每个 PMD 添加所有端口的 TX 缓存
 * 5. 触发 PMD 重新加载 */
static void
reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct hmapx busy_threads = HMAPX_INITIALIZER(&busy_threads);
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_port *port;
    int wanted_txqs;

    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Step 1: Adjust the pmd threads based on the datapath ports, the cores
     * on the system and the user configuration. */
    reconfigure_pmd_threads(dp);

    wanted_txqs = cmap_count(&dp->poll_threads);

    /* The number of pmd threads might have changed, or a port can be new:
     * adjust the txqs. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_set_tx_multiq(port->netdev, wanted_txqs);
    }

    /* Step 2: Remove from the pmd threads ports that have been removed or
     * need reconfiguration. */

    /* Check for all the ports that need reconfiguration.  We cache this in
     * 'port->need_reconfigure', because netdev_is_reconf_required() can
     * change at any time.
     * Also mark for reconfiguration all ports which will likely change their
     * 'txq_mode' parameter.  It's required to stop using them before
     * changing this setting and it's simpler to mark ports here and allow
     * 'pmd_remove_stale_ports' to remove them from threads.  There will be
     * no actual reconfiguration in 'port_reconfigure' because it's
     * unnecessary.  */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)
            || ((port->txq_mode == TXQ_MODE_XPS)
                != (netdev_n_txq(port->netdev) < wanted_txqs))
            || ((port->txq_mode == TXQ_MODE_XPS_HASH)
                != (port->txq_requested_mode == TXQ_REQ_MODE_HASH
                    && netdev_n_txq(port->netdev) > 1))) {
            port->need_reconfigure = true;
        }
    }

    /* Remove from the pmd threads all the ports that have been deleted or
     * need reconfiguration. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd_remove_stale_ports(dp, pmd);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads before
     * reconfiguring the ports, because a port cannot be reconfigured while
     * it's being used. */
    reload_affected_pmds(dp);

    /* Step 3: Reconfigure ports. */

    /* We only reconfigure the ports that we determined above, because they're
     * not being used by any pmd thread at the moment.  If a port fails to
     * reconfigure we remove it from the datapath. */
    HMAP_FOR_EACH_SAFE (port, node, &dp->ports) {
        int err;

        if (!port->need_reconfigure) {
            continue;
        }

        err = port_reconfigure(port);
        if (err) {
            hmap_remove(&dp->ports, &port->node);
            seq_change(dp->port_seq);
            port_destroy(port);
        } else {
            /* With a single queue, there is no point in using hash mode. */
            if (port->txq_requested_mode == TXQ_REQ_MODE_HASH &&
                netdev_n_txq(port->netdev) > 1) {
                port->txq_mode = TXQ_MODE_XPS_HASH;
            } else if (netdev_n_txq(port->netdev) < wanted_txqs) {
                port->txq_mode = TXQ_MODE_XPS;
            } else {
                port->txq_mode = TXQ_MODE_STATIC;
            }
        }
    }

    /* Step 4: Compute new rxq scheduling.  We don't touch the pmd threads
     * for now, we just update the 'pmd' pointer in each rxq to point to the
     * wanted thread according to the scheduling policy. */

    /* Reset all the pmd threads to non isolated. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd->isolated = false;
    }

    /* Reset all the queues to unassigned */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int i = 0; i < port->n_rxq; i++) {
            port->rxqs[i].pmd = NULL;
        }
    }
    rxq_scheduling(dp);

    /* Step 5: Remove queues not compliant with new scheduling. */

    /* Count all the threads that will have at least one queue to poll. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (q->pmd) {
                hmapx_add(&busy_threads, q->pmd);
            }
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct rxq_poll *poll;

        ovs_mutex_lock(&pmd->port_mutex);
        HMAP_FOR_EACH_SAFE (poll, node, &pmd->poll_list) {
            if (poll->rxq->pmd != pmd) {
                dp_netdev_del_rxq_from_pmd(pmd, poll);

                /* This pmd might sleep after this step if it has no rxq
                 * remaining. Tell it to busy wait for new assignment if it
                 * has at least one scheduled queue. */
                if (hmap_count(&pmd->poll_list) == 0 &&
                    hmapx_contains(&busy_threads, pmd)) {
                    atomic_store_relaxed(&pmd->wait_for_reload, true);
                }
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    hmapx_destroy(&busy_threads);

    /* Reload affected pmd threads.  We must wait for the pmd threads to remove
     * the old queues before readding them, otherwise a queue can be polled by
     * two threads at the same time. */
    reload_affected_pmds(dp);

    /* Step 6: Add queues from scheduling, if they're not there already. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (q->pmd) {
                ovs_mutex_lock(&q->pmd->port_mutex);
                dp_netdev_add_rxq_to_pmd(q->pmd, q);
                ovs_mutex_unlock(&q->pmd->port_mutex);
            }
        }
    }

    /* Add every port and bond to the tx port and bond caches of
     * every pmd thread, if it's not there already and if this pmd
     * has at least one rxq to poll.
     */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        ovs_mutex_lock(&pmd->port_mutex);
        if (hmap_count(&pmd->poll_list) || pmd->core_id == NON_PMD_CORE_ID) {
            struct tx_bond *bond;

            HMAP_FOR_EACH (port, node, &dp->ports) {
                dp_netdev_add_port_tx_to_pmd(pmd, port);
            }

            CMAP_FOR_EACH (bond, node, &dp->tx_bonds) {
                dp_netdev_add_bond_tx_to_pmd(pmd, bond, false);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads. */
    reload_affected_pmds(dp);

    /* PMD ALB will need to recheck if dry run needed. */
    dp->pmd_alb.recheck_config = true;
}

/* Returns true if one of the netdevs in 'dp' requires a reconfiguration */
static bool
ports_require_restart(const struct dp_netdev *dp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)) {
            return true;
        }
    }

    return false;
}

/* Calculates variance in the values stored in array 'a'. 'n' is the number
 * of elements in array to be considered for calculating vairance.
 * Usage example: data array 'a' contains the processing load of each pmd and
 * 'n' is the number of PMDs. It returns the variance in processing load of
 * PMDs*/
static uint64_t
variance(uint64_t a[], int n)
{
    /* Compute mean (average of elements). */
    uint64_t sum = 0;
    uint64_t mean = 0;
    uint64_t sqDiff = 0;

    if (!n) {
        return 0;
    }

    for (int i = 0; i < n; i++) {
        sum += a[i];
    }

    if (sum) {
        mean = sum / n;

        /* Compute sum squared differences with mean. */
        for (int i = 0; i < n; i++) {
            sqDiff += (a[i] - mean)*(a[i] - mean);
        }
    }
    return (sqDiff ? (sqDiff / n) : 0);
}

/* Return true if needs to revalidate datapath flows. */
/* dpif_netdev_run — 主线程的周期性调用函数。
 * 由 ofproto-dpif 在主循环中调用，处理以下任务：
 * 1. non-PMD 线程处理非 DPDK 端口（如 tap 端口）的收包
 * 2. 检查端口配置变更，按需触发 datapath 重配置
 * 3. 检查隧道配置变更，按需刷新 tnl 端口
 * 4. 自动负载均衡：检测 PMD 负载，按需重分配 RXQ
 * 返回 true 表示需要重新验证流表。 */
static bool
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *non_pmd;
    uint64_t new_tnl_seq;
    bool need_to_flush = true;
    bool pmd_rebalance = false;
    long long int now = time_msec();
    struct dp_netdev_pmd_thread *pmd;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    non_pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
    if (non_pmd) {
        ovs_mutex_lock(&dp->non_pmd_mutex);

        atomic_read_relaxed(&dp->smc_enable_db, &non_pmd->ctx.smc_enable_db);

        HMAP_FOR_EACH (port, node, &dp->ports) {
            if (!netdev_is_pmd(port->netdev)) {
                int i;

                if (port->emc_enabled) {
                    atomic_read_relaxed(&dp->emc_insert_min,
                                        &non_pmd->ctx.emc_insert_min);
                } else {
                    non_pmd->ctx.emc_insert_min = 0;
                }

                for (i = 0; i < port->n_rxq; i++) {

                    if (!netdev_rxq_enabled(port->rxqs[i].rx)) {
                        continue;
                    }

                    if (dp_netdev_process_rxq_port(non_pmd,
                                                   &port->rxqs[i],
                                                   port->port_no)) {
                        need_to_flush = false;
                    }
                }
            }
        }
        if (need_to_flush) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(non_pmd);
            dp_netdev_pmd_flush_output_packets(non_pmd, false);
        }

        dpif_netdev_xps_revalidate_pmd(non_pmd, false);
        ovs_mutex_unlock(&dp->non_pmd_mutex);

        dp_netdev_pmd_unref(non_pmd);
    }

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    if (pmd_alb->is_enabled) {
        if (!pmd_alb->rebalance_poll_timer) {
            pmd_alb->rebalance_poll_timer = now;
        } else if ((pmd_alb->rebalance_poll_timer +
                   pmd_alb->rebalance_intvl) < now) {
            pmd_alb->rebalance_poll_timer = now;
            CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
                if (atomic_count_get(&pmd->pmd_overloaded) >=
                                    PMD_INTERVAL_MAX) {
                    pmd_rebalance = true;
                    break;
                }
            }

            if (pmd_rebalance &&
                !dp_netdev_is_reconf_required(dp) &&
                !ports_require_restart(dp) &&
                pmd_rebalance_dry_run_needed(dp) &&
                pmd_rebalance_dry_run(dp)) {
                VLOG_INFO("PMD auto load balance dry run. "
                          "Requesting datapath reconfigure.");
                dp_netdev_request_reconfigure(dp);
            }
        }
    }

    if (dp_netdev_is_reconf_required(dp) || ports_require_restart(dp)) {
        reconfigure_datapath(dp);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    tnl_neigh_cache_run();
    tnl_port_map_run();
    new_tnl_seq = seq_read(tnl_conf_seq);

    if (dp->last_tnl_conf_seq != new_tnl_seq) {
        dp->last_tnl_conf_seq = new_tnl_seq;
        return true;
    }
    return false;
}

/* dpif_netdev_wait — 在 poll_block 前注册所有需要等待的事件：
 * 端口重配置需求、非 PMD 端口的 RXQ、隧道配置变更。 */
static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);
    ovs_rwlock_rdlock(&dp->port_rwlock);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_wait_reconf_required(port->netdev);
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < port->n_rxq; i++) {
                netdev_rxq_wait(port->rxqs[i].rx);
            }
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);
    ovs_mutex_unlock(&dp_netdev_mutex);
    seq_wait(tnl_conf_seq, dp->last_tnl_conf_seq);
}

/* 释放 PMD 线程的端口发送缓存：刷新未发送的报文，释放 TX 端口缓存。 */
static void
pmd_free_cached_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct tx_port *tx_port_cached;

    /* Flush all the queued packets. */
    dp_netdev_pmd_flush_output_packets(pmd, true);
    /* Free all used tx queue ids. */
    dpif_netdev_xps_revalidate_pmd(pmd, true);

    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->tnl_port_cache) {
        free(tx_port_cached->txq_pkts);
        free(tx_port_cached);
    }
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->send_port_cache) {
        free(tx_port_cached->txq_pkts);
        free(tx_port_cached);
    }
}

/* Copies ports from 'pmd->tx_ports' (shared with the main thread) to
 * thread-local copies. Copy to 'pmd->tnl_port_cache' if it is a tunnel
 * device, otherwise to 'pmd->send_port_cache' if the port has at least
 * one txq. */
/* 将共享的 tx_ports 复制到线程本地缓存：
 * 隧道端口 → tnl_port_cache，普通端口 → send_port_cache。
 * 这样 PMD 转发时无需加锁访问共享结构。 */
static void
pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx_port, *tx_port_cached;

    pmd_free_cached_ports(pmd);
    hmap_shrink(&pmd->send_port_cache);
    hmap_shrink(&pmd->tnl_port_cache);

    HMAP_FOR_EACH (tx_port, node, &pmd->tx_ports) {
        int n_txq = netdev_n_txq(tx_port->port->netdev);
        struct dp_packet_batch *txq_pkts_cached;

        if (netdev_has_tunnel_push_pop(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            if (tx_port->txq_pkts) {
                txq_pkts_cached = xmemdup(tx_port->txq_pkts,
                                          n_txq * sizeof *tx_port->txq_pkts);
                tx_port_cached->txq_pkts = txq_pkts_cached;
            }
            hmap_insert(&pmd->tnl_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }

        if (n_txq) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            if (tx_port->txq_pkts) {
                txq_pkts_cached = xmemdup(tx_port->txq_pkts,
                                          n_txq * sizeof *tx_port->txq_pkts);
                tx_port_cached->txq_pkts = txq_pkts_cached;
            }
            hmap_insert(&pmd->send_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }
    }
}

/* 从全局 TX 队列 ID 池中为 PMD 分配一个静态 TX 队列号。 */
static void
pmd_alloc_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    if (!id_pool_alloc_id(pmd->dp->tx_qid_pool, &pmd->static_tx_qid)) {
        VLOG_ABORT("static_tx_qid allocation failed for PMD on core %2d"
                   ", numa_id %d.", pmd->core_id, pmd->numa_id);
    }
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);

    VLOG_DBG("static_tx_qid = %d allocated for PMD thread on core %2d"
             ", numa_id %d.", pmd->static_tx_qid, pmd->core_id, pmd->numa_id);
}

static void
pmd_free_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    id_pool_free_id(pmd->dp->tx_qid_pool, pmd->static_tx_qid);
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);
}

/* 加载 PMD 的轮询队列列表和端口缓存。
 * 将 pmd->poll_list（hmap）中的 RXQ 信息复制到本地 poll_list 数组，
 * 同时刷新 TX 端口缓存（send_port_cache / tnl_port_cache）。
 * 返回值：本 PMD 需要轮询的 RXQ 数量。
 *
 * 此函数在 PMD 线程启动和每次 reload 时调用，
 * 确保 PMD 使用最新的端口/队列配置。 */
static int
pmd_load_queues_and_ports(struct dp_netdev_pmd_thread *pmd,
                          struct polled_queue **ppoll_list)
{
    struct polled_queue *poll_list = *ppoll_list;  /* 复用上次分配的数组（或 NULL） */
    struct rxq_poll *poll;
    int i;

    /* 加锁保护 pmd->poll_list 和端口缓存的读取。
     * 控制线程（reconfigure_pmd_threads）会修改 poll_list，
     * 因此必须在锁保护下拷贝。 */
    ovs_mutex_lock(&pmd->port_mutex);

    /* 按当前 poll_list 的大小重新分配数组。
     * xrealloc 在 poll_list 为 NULL 时等价于 xmalloc。 */
    poll_list = xrealloc(poll_list, hmap_count(&pmd->poll_list)
                                    * sizeof *poll_list);

    /* 遍历 pmd->poll_list（hmap），将每个 RXQ 的信息
     * 拷贝到本地 poll_list 数组中（避免在热路径中持锁访问 hmap）。 */
    i = 0;
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        poll_list[i].rxq = poll->rxq;               /* RXQ 指针 */
        poll_list[i].port_no = poll->rxq->port->port_no;  /* 入端口号 */
        poll_list[i].emc_enabled = poll->rxq->port->emc_enabled;  /* EMC 开关 */
        poll_list[i].rxq_enabled = netdev_rxq_enabled(poll->rxq->rx);  /* RXQ 是否可用 */
        /* 记录端口配置序列号，用于检测端口配置变更 */
        poll_list[i].change_seq =
                     netdev_get_change_seq(poll->rxq->port->netdev);
        i++;
    }

    /* 刷新本 PMD 的 TX 端口缓存：
     * 从 pmd->tx_ports（由控制线程管理）拷贝到
     * pmd->send_port_cache 和 pmd->tnl_port_cache。 */
    pmd_load_cached_ports(pmd);

    ovs_mutex_unlock(&pmd->port_mutex);

    *ppoll_list = poll_list;  /* 返回更新后的数组指针 */
    return i;                  /* 返回 RXQ 数量 */
}

/* PMD 线程主函数 — 每个 PMD 线程的入口点。
 * 核心逻辑是一个无限轮询循环：
 * 1. 绑定 CPU 核心、DPDK 线程、分配 TX 队列
 * 2. 循环遍历分配的所有 RXQ：
 *    a. dp_netdev_process_rxq_port() — 从 RXQ 收包并处理
 *    b. 定期执行优化（dpcls 子表排序、miniflow 提取函数切换）
 *    c. 定期执行 RCU 静默、刷新输出缓冲、更新统计
 * 3. 检测 reload 信号：端口变更时重新加载队列列表
 * 4. 低负载时可进入微秒级休眠以降低 CPU 使用率
 * PMD 线程是 OVS-DPDK 的性能核心。 */
static void *
pmd_thread_main(void *f_)
{
    struct dp_netdev_pmd_thread *pmd = f_;  /* 当前 PMD 线程上下文 */
    struct pmd_perf_stats *s = &pmd->perf_stats;  /* 性能统计指针（缩短引用） */
    unsigned int lc = 0;                /* 低频操作计数器，每 1024 次迭代触发一次优化 */
    struct polled_queue *poll_list;      /* 本 PMD 负责轮询的 RXQ 列表 */
    bool wait_for_reload = false;       /* 是否需要忙等 reload 信号（而非阻塞等待） */
    bool dpdk_attached;                 /* DPDK EAL 线程是否已绑定 */
    bool reload_tx_qid;                /* reload 时是否需要重新分配 TX 队列 ID */
    bool exiting;                       /* PMD 是否应退出 */
    bool reload;                        /* reload 信号标志 */
    int poll_cnt;                       /* poll_list 中的 RXQ 数量 */
    int i;
    int process_packets = 0;            /* 单次 rxq 收包处理的包数 */
    uint64_t sleep_time = 0;            /* 当前休眠时间（微秒），逐步递增直到 max_sleep */

    poll_list = NULL;

    /* 将 pmd 指针存入线程局部存储，供其他函数通过 per_pmd_key 获取当前 PMD */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);
    /* 绑定线程到指定 CPU 核心（NUMA 亲和性） */
    ovs_numa_thread_setaffinity_core(pmd->core_id);
    /* 将此线程注册到 DPDK EAL（lcore 管理） */
    dpdk_attached = dpdk_attach_thread(pmd->core_id);
    /* 加载分配给本 PMD 的 RXQ 列表和端口缓存 */
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    /* 初始化 DFC（EMC + SMC）缓存 */
    dfc_cache_init(&pmd->flow_cache);
    /* 为本 PMD 分配静态 TX 队列 ID（用于非 XPS 模式的发送） */
    pmd_alloc_static_tx_qid(pmd);
    /* 设置定时器分辨率为纳秒级（高精度计时） */
    set_timer_resolution(PMD_TIMER_RES_NS);

    /* === reload 入口 ===
     * 每次 reload（端口变更、RXQ 重分配）后跳转到这里重新初始化。 */
reload:
    /* 重置过载计数器 */
    atomic_count_init(&pmd->pmd_overloaded, 0);

    /* 重置负载统计间隔的 TSC 基准和累计周期数 */
    pmd->intrvl_tsc_prev = 0;
    atomic_store_relaxed(&pmd->intrvl_cycles, 0);

    /* 如果 DPDK 线程未绑定（可能之前 detach 过），尝试重新绑定 */
    if (!dpdk_attached) {
        dpdk_attached = dpdk_attach_thread(pmd->core_id);
    }

    /* 打印本 PMD 处理的端口/队列信息，并重置 RXQ 周期计数器 */
    for (i = 0; i < poll_cnt; i++) {
       VLOG_DBG("Core %d processing port \'%s\' with queue-id %d\n",
                pmd->core_id, netdev_rxq_get_name(poll_list[i].rxq->rx),
                netdev_rxq_get_queue_id(poll_list[i].rxq->rx));
       /* 重置当前处理周期计数（用于 RXQ 负载均衡统计） */
       dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR, 0);
       /* 清零所有间隔采样槽位 */
       for (int j = 0; j < PMD_INTERVAL_MAX; j++) {
           dp_netdev_rxq_set_intrvl_cycles(poll_list[i].rxq, 0);
       }
    }

    /* 如果没有分配到任何 RXQ，PMD 需要等待 reload 信号 */
    if (!poll_cnt) {
        if (wait_for_reload) {
            /* 控制线程马上会发送 reload，忙等即可（不阻塞） */
            do {
                atomic_read_explicit(&pmd->reload, &reload,
                                     memory_order_acquire);
            } while (!reload);
        } else {
            /* 通过 seq 机制阻塞等待，直到有新的 reload 序列号 */
            while (seq_read(pmd->reload_seq) == pmd->last_reload_seq) {
                seq_wait(pmd->reload_seq, pmd->last_reload_seq);
                poll_block();
            }
        }
    }

    /* 清零所有忙碌周期间隔槽位（用于负载均衡决策） */
    for (i = 0; i < PMD_INTERVAL_MAX; i++) {
        atomic_store_relaxed(&pmd->busy_cycles_intrvl[i], 0);
    }
    /* 重置间隔采样索引 */
    atomic_count_set(&pmd->intrvl_idx, 0);
    /* 初始化 TSC 计数器基准 */
    cycles_counter_update(s);

    /* 设置下一次 RCU 静默点的时间 */
    pmd->next_rcu_quiesce = pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;

    /* 加锁保护性能统计，防止外部（如 pmd-perf-show）在轮询时清除统计 */
    ovs_mutex_lock(&pmd->perf_stats.stats_mutex);

    /* === PMD 主轮询循环 ===
     * 每次迭代：收包 → 处理 → 发包 → 休眠(可选) → RCU → 优化 → 检查 reload */
    for (;;) {
        uint64_t rx_packets = 0, tx_packets = 0;  /* 本次迭代的收发包计数 */
        uint64_t time_slept = 0;                   /* 本次迭代的休眠周期数 */
        uint64_t max_sleep;                         /* 配置的最大休眠时间（微秒） */

        /* 记录迭代起始时间戳 */
        pmd_perf_start_iteration(s);

        /* 读取全局配置：SMC 是否启用、最大休眠时间 */
        atomic_read_relaxed(&pmd->dp->smc_enable_db, &pmd->ctx.smc_enable_db);
        atomic_read_relaxed(&pmd->max_sleep, &max_sleep);

        /* --- 第一阶段：逐个 RXQ 收包并处理 --- */
        for (i = 0; i < poll_cnt; i++) {

            /* 跳过被禁用的 RXQ（如端口被管理员 down 掉） */
            if (!poll_list[i].rxq_enabled) {
                continue;
            }

            /* 根据 per-RXQ 的 EMC 开关决定是否启用 EMC 插入 */
            if (poll_list[i].emc_enabled) {
                atomic_read_relaxed(&pmd->dp->emc_insert_min,
                                    &pmd->ctx.emc_insert_min);
            } else {
                pmd->ctx.emc_insert_min = 0;  /* EMC 禁用：不插入新条目 */
            }

            /* 核心收包+处理：从 RXQ 收包 → miniflow 提取 → 流表查找 → 执行 action */
            process_packets =
                dp_netdev_process_rxq_port(pmd, poll_list[i].rxq,
                                           poll_list[i].port_no);
            rx_packets += process_packets;
            /* 收到足够多的包时重置休眠时间（高负载不休眠） */
            if (process_packets >= PMD_SLEEP_THRESH) {
                sleep_time = 0;
            }
        }

        /* --- 第二阶段：无收包时刷新待发送队列 ---
         * 如果本轮没收到任何包，检查是否有缓冲的待发送包需要刷出。
         * 此时需要手动更新时间戳（因为收包路径未执行时间更新）。 */
        if (!rx_packets) {
            pmd_thread_ctx_time_update(pmd);
            /* 刷新输出缓冲。若配置了休眠且当前有休眠，使用惰性刷新 */
            tx_packets = dp_netdev_pmd_flush_output_packets(pmd,
                                                   max_sleep && sleep_time
                                                   ? true : false);
        }

        /* --- 第三阶段：自适应休眠（降低空闲时 CPU 使用率）---
         * 仅在 max_sleep > 0（配置了 pmd-sleep）时启用。
         * 休眠时间从 0 开始，每次迭代增加 PMD_SLEEP_INC_US 微秒，
         * 直到 max_sleep。一旦收到包（>= PMD_SLEEP_THRESH），重置为 0。 */
        if (max_sleep) {
            if (sleep_time) {
                struct cycle_timer sleep_timer;

                /* 执行纳秒级休眠（不触发 RCU 静默） */
                cycle_timer_start(&pmd->perf_stats, &sleep_timer);
                xnanosleep_no_quiesce(sleep_time * 1000);
                time_slept = cycle_timer_stop(&pmd->perf_stats, &sleep_timer);
                pmd_thread_ctx_time_update(pmd);
            }
            if (sleep_time < max_sleep) {
                /* 逐步增加休眠时间 */
                sleep_time += PMD_SLEEP_INC_US;
            } else {
                sleep_time = max_sleep;
            }
        } else {
            /* max_sleep 被清零（策略变更），重置休眠时间 */
            sleep_time = 0;
        }

        /* --- 第四阶段：RCU 定期静默 ---
         * 在固定间隔执行 RCU 静默，确保高负载下也能及时回收内存。
         * RCU 静默允许其他线程安全释放被 ovsrcu_postpone() 延迟的对象。 */
        if (pmd->ctx.now > pmd->next_rcu_quiesce) {
            if (!ovsrcu_try_quiesce()) {
                pmd->next_rcu_quiesce =
                    pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
            }
        }

        /* --- 第五阶段：低频维护操作（每 1024 次迭代一次）--- */
        if (lc++ > 1024) {
            lc = 0;

            /* 尝试清除覆盖率计数器（调试用） */
            coverage_try_clear();
            /* 优化 dpcls：按命中率对子表排序、切换 miniflow 提取函数 */
            dp_netdev_pmd_try_optimize(pmd, poll_list, poll_cnt);
            /* 再次尝试 RCU 静默，并做 EMC 慢速清扫（淘汰过期条目） */
            if (!ovsrcu_try_quiesce()) {
                emc_cache_slow_sweep(&((pmd->flow_cache).emc_cache));
                pmd->next_rcu_quiesce =
                    pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
            }

            /* 检查端口配置是否变更（change_seq），更新 RXQ 启用状态 */
            for (i = 0; i < poll_cnt; i++) {
                uint64_t current_seq =
                         netdev_get_change_seq(poll_list[i].rxq->port->netdev);
                if (poll_list[i].change_seq != current_seq) {
                    poll_list[i].change_seq = current_seq;
                    poll_list[i].rxq_enabled =
                                 netdev_rxq_enabled(poll_list[i].rxq->rx);
                }
            }
        }

        /* --- 第六阶段：检查 reload 信号 ---
         * 如果控制线程设置了 reload 标志（端口增删、RXQ 重分配等），
         * 跳出主循环去重新加载配置。 */
        atomic_read_explicit(&pmd->reload, &reload, memory_order_acquire);
        if (OVS_UNLIKELY(reload)) {
            break;
        }

        /* 记录本次迭代的统计数据（收包数、发包数、休眠时间） */
        pmd_perf_end_iteration(s, rx_packets, tx_packets, time_slept,
                               pmd_perf_metrics_enabled(pmd));
    }
    /* 释放统计锁 */
    ovs_mutex_unlock(&pmd->perf_stats.stats_mutex);

    /* === reload 处理 ===
     * 跳出主循环后，重新加载 RXQ 列表和端口缓存，
     * 读取控制线程设置的各项 reload 标志。 */
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    /* 是否需要忙等下一次 reload（两阶段 reload 时使用） */
    atomic_read_relaxed(&pmd->wait_for_reload, &wait_for_reload);
    /* 是否需要重新分配 TX 队列 ID */
    atomic_read_relaxed(&pmd->reload_tx_qid, &reload_tx_qid);
    /* 是否收到退出信号 */
    atomic_read_relaxed(&pmd->exit, &exiting);
    /* 通知控制线程本 PMD 已完成 reload 配置的加载 */
    dp_netdev_pmd_reload_done(pmd);

    /* TX 队列 ID 需要重新分配（如端口增删导致队列数变化） */
    if (reload_tx_qid) {
        pmd_free_static_tx_qid(pmd);
        pmd_alloc_static_tx_qid(pmd);
    }

    /* 未收到退出信号则跳转回 reload 标签继续轮询 */
    if (!exiting) {
        goto reload;
    }

    /* === PMD 线程退出清理 === */
    pmd_free_static_tx_qid(pmd);       /* 释放 TX 队列 ID */
    dfc_cache_uninit(&pmd->flow_cache); /* 销毁 EMC + SMC 缓存 */
    free(poll_list);                     /* 释放轮询列表 */
    pmd_free_cached_ports(pmd);          /* 释放端口缓存（send/tnl） */
    if (dpdk_attached) {
        dpdk_detach_thread();            /* 从 DPDK EAL 注销线程 */
    }
    return NULL;
}

/* 禁用 upcall（获取写锁阻止新的 upcall 处理）。 */
static void
dp_netdev_disable_upcall(struct dp_netdev *dp)
    OVS_ACQUIRES(dp->upcall_rwlock)
{
    fat_rwlock_wrlock(&dp->upcall_rwlock);
}


/* =====================================================
 * Meter（QoS 限速器）实现。
 *
 * 支持按包速率（pktps）或按位速率（kbps）限速。
 * 每个 meter 包含多个 band（限速档位），每个 band 有独立的令牌桶。
 * 超过速率的报文会被丢弃（DROP band）。
 *
 * 令牌桶使用原子操作实现，支持多 PMD 线程并发计量。
 * ===================================================== */

/* 返回 meter 能力信息（最大数量、支持的 band 类型等）。 */
static void
dpif_netdev_meter_get_features(const struct dpif * dpif OVS_UNUSED,
                               struct ofputil_meter_features *features)
{
    features->max_meters = MAX_METERS;
    features->band_types = DP_SUPPORTED_METER_BAND_TYPES;
    features->capabilities = DP_SUPPORTED_METER_FLAGS_MASK;
    features->max_bands = MAX_BANDS;
    features->max_color = 0;
}

/* Tries to atomically add 'n' to 'value' in terms of saturation arithmetic,
 * i.e., if the result will be larger than 'max_value', will store 'max_value'
 * instead. */
/* 饱和加法：加到最大值后不再增长（用于令牌桶补充）。 */
static void
atomic_sat_add(atomic_uint64_t *value, uint64_t n, uint64_t max_value)
{
    uint64_t current, new_value;

    atomic_read_relaxed(value, &current);
    do {
        new_value = current + n;
        new_value = MIN(new_value, max_value);
    } while (!atomic_compare_exchange_weak_relaxed(value, &current,
                                                   new_value));
}

/* Tries to atomically subtract 'n' from 'value'.  Does not perform the
 * operation and returns 'false' if the result will be less than 'min_value'.
 * Otherwise, stores the result and returns 'true'. */
/* 有界减法：不够减时返回 false（用于令牌桶消耗）。 */
static bool
atomic_bound_sub(atomic_uint64_t *value, uint64_t n, uint64_t min_value)
{
    uint64_t current;

    atomic_read_relaxed(value, &current);
    do {
        if (current < min_value + n) {
            return false;
        }
    } while (!atomic_compare_exchange_weak_relaxed(value, &current,
                                                   current - n));
    return true;
}

/* Applies the meter identified by 'meter_id' to 'packets_'.  Packets
 * that exceed a band are dropped in-place. */
/* 对一批报文执行 meter 计量：
 * 1) 按时间差补充令牌桶
 * 2) 对每个报文检查是否超过各 band 的速率
 * 3) 超速的报文就地丢弃（从 batch 中移除） */
static void
dp_netdev_run_meter(struct dp_netdev *dp, struct dp_packet_batch *packets_,
                    uint32_t meter_id, long long int now_ms)
{
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t exceeded_rate[NETDEV_MAX_BURST];
    uint32_t exceeded_band[NETDEV_MAX_BURST];
    uint64_t bytes, volume, meter_used, old;
    uint64_t band_packets[MAX_BANDS];
    uint64_t band_bytes[MAX_BANDS];
    struct dp_meter_band *band;
    struct dp_packet *packet;
    struct dp_meter *meter;
    bool exceeded = false;

    if (meter_id >= MAX_METERS) {
        return;
    }

    meter = dp_meter_lookup(&dp->meters, meter_id);
    if (!meter) {
        return;
    }

    /* Initialize as negative values. */
    memset(exceeded_band, 0xff, cnt * sizeof *exceeded_band);
    /* Initialize as zeroes. */
    memset(exceeded_rate, 0, cnt * sizeof *exceeded_rate);

    atomic_read_relaxed(&meter->used, &meter_used);
    do {
        if (meter_used >= now_ms) {
            /* The '>' condition means that we have several threads hitting the
             * same meter, and the other one already advanced the time. */
            meter_used = now_ms;
            break;
        }
    } while (!atomic_compare_exchange_weak_relaxed(&meter->used,
                                                   &meter_used, now_ms));

    /* Refill all buckets right away, since other threads may use them. */
    if (meter_used < now_ms) {
        /* All packets will hit the meter at the same time. */
        uint64_t delta_t = now_ms - meter_used;

        /* Make sure delta_t will not be too large, so that bucket will not
         * wrap around below. */
        delta_t = MIN(delta_t, meter->max_delta_t);

        for (int m = 0; m < meter->n_bands; m++) {
            band = &meter->bands[m];
            /* Update band's bucket.  We can't just use atomic add here,
             * because we should never add above the max capacity. */
            atomic_sat_add(&band->bucket, delta_t * band->rate,
                           band->burst_size * 1000ULL);
        }
    }

    /* Update meter stats. */
    atomic_add_relaxed(&meter->packet_count, cnt, &old);
    bytes = 0;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        bytes += dp_packet_size(packet);
    }
    atomic_add_relaxed(&meter->byte_count, bytes, &old);

    /* Meters can operate in terms of packets per second or kilobits per
     * second. */
    if (meter->flags & OFPMF13_PKTPS) {
        /* Rate in packets/second, bucket 1/1000 packets.
         * msec * packets/sec = 1/1000 packets. */
        volume = cnt * 1000; /* Take 'cnt' packets from the bucket. */
    } else {
        /* Rate in kbps, bucket in bits.
         * msec * kbps = bits */
        volume = bytes * 8;
    }

    /* Find the band hit with the highest rate for each packet (if any). */
    for (int m = 0; m < meter->n_bands; m++) {
        band = &meter->bands[m];

        /* Drain the bucket for all the packets, if possible. */
        if (atomic_bound_sub(&band->bucket, volume, 0)) {
            continue;
        }

        /* Band limit hit, must process packet-by-packet. */
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            uint64_t packet_volume = (meter->flags & OFPMF13_PKTPS)
                                     ? 1000 : (dp_packet_size(packet) * 8);

            if (!atomic_bound_sub(&band->bucket, packet_volume, 0)) {
                /* Update the exceeding band for the exceeding packet.
                 * Only one band will be fired by a packet, and that can
                 * be different for each packet. */
                if (band->rate > exceeded_rate[i]) {
                    exceeded_rate[i] = band->rate;
                    exceeded_band[i] = m;
                    exceeded = true;
                }
            }
        }
    }

    /* No need to iterate over packets if there are no drops. */
    if (!exceeded) {
        return;
    }

    /* Fire the highest rate band exceeded by each packet, and drop
     * packets if needed. */

    memset(band_packets, 0, sizeof band_packets);
    memset(band_bytes,   0, sizeof band_bytes);

    size_t j;
    DP_PACKET_BATCH_REFILL_FOR_EACH (j, cnt, packet, packets_) {
        uint32_t m = exceeded_band[j];

        if (m != UINT32_MAX) {
            /* Meter drop packet. */
            band_packets[m]++;
            band_bytes[m] += dp_packet_size(packet);
            dp_packet_delete(packet);
        } else {
            /* Meter accepts packet. */
            dp_packet_batch_refill(packets_, packet, j);
        }
    }

    for (int m = 0; m < meter->n_bands; m++) {
        if (!band_packets[m]) {
            continue;
        }
        band = &meter->bands[m];
        atomic_add_relaxed(&band->packet_count, band_packets[m], &old);
        atomic_add_relaxed(&band->byte_count,   band_bytes[m],   &old);
        COVERAGE_ADD(datapath_drop_meter, band_packets[m]);
    }
}

/* Meter set/get/del processing is still single-threaded. */
/* 设置（创建/更新）一个 meter：验证参数、分配 dp_meter、
 * 初始化 band 的速率和突发大小、插入 cmap。 */
static int
dpif_netdev_meter_set(struct dpif *dpif, ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t mid = meter_id.uint32;
    struct dp_meter *meter;
    int i;

    if (mid >= MAX_METERS) {
        return EFBIG; /* Meter_id out of range. */
    }

    if (config->flags & ~DP_SUPPORTED_METER_FLAGS_MASK) {
        return EBADF; /* Unsupported flags set */
    }

    if (config->n_bands > MAX_BANDS) {
        return EINVAL;
    }

    for (i = 0; i < config->n_bands; ++i) {
        switch (config->bands[i].type) {
        case OFPMBT13_DROP:
            break;
        default:
            return ENODEV; /* Unsupported band type */
        }
    }

    /* Allocate meter */
    meter = xzalloc(sizeof *meter
                    + config->n_bands * sizeof(struct dp_meter_band));

    meter->flags = config->flags;
    meter->n_bands = config->n_bands;
    meter->max_delta_t = 0;
    meter->id = mid;
    atomic_init(&meter->used, time_msec());

    /* set up bands */
    for (i = 0; i < config->n_bands; ++i) {
        uint32_t band_max_delta_t;
        uint64_t bucket_size;

        /* Set burst size to a workable value if none specified. */
        if (config->bands[i].burst_size == 0) {
            config->bands[i].burst_size = config->bands[i].rate;
        }

        meter->bands[i].rate = config->bands[i].rate;
        meter->bands[i].burst_size = config->bands[i].burst_size;
        /* Start with a full bucket. */
        bucket_size = meter->bands[i].burst_size * 1000ULL;
        atomic_init(&meter->bands[i].bucket, bucket_size);

        /* Figure out max delta_t that is enough to fill any bucket. */
        band_max_delta_t = bucket_size / meter->bands[i].rate;
        if (band_max_delta_t > meter->max_delta_t) {
            meter->max_delta_t = band_max_delta_t;
        }
    }

    ovs_mutex_lock(&dp->meters_lock);

    dp_meter_detach_free(&dp->meters, mid); /* Free existing meter, if any. */
    dp_meter_attach(&dp->meters, meter);

    ovs_mutex_unlock(&dp->meters_lock);

    return 0;
}

/* 获取 meter 的统计信息（总包/字节数，各 band 的丢弃包/字节数）。 */
static int
dpif_netdev_meter_get(const struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t meter_id = meter_id_.uint32;
    struct dp_meter *meter;

    if (meter_id >= MAX_METERS) {
        return EFBIG;
    }

    meter = dp_meter_lookup(&dp->meters, meter_id);
    if (!meter) {
        return ENOENT;
    }

    if (stats) {
        int i = 0;

        atomic_read_relaxed(&meter->packet_count, &stats->packet_in_count);
        atomic_read_relaxed(&meter->byte_count, &stats->byte_in_count);

        for (i = 0; i < n_bands && i < meter->n_bands; ++i) {
            atomic_read_relaxed(&meter->bands[i].packet_count,
                                &stats->bands[i].packet_count);
            atomic_read_relaxed(&meter->bands[i].byte_count,
                                &stats->bands[i].byte_count);
        }
        stats->n_bands = i;
    }

    return 0;
}

/* 删除 meter：先获取统计信息，再从哈希表中移除并释放。 */
static int
dpif_netdev_meter_del(struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    error = dpif_netdev_meter_get(dpif, meter_id_, stats, n_bands);
    if (!error) {
        uint32_t meter_id = meter_id_.uint32;

        ovs_mutex_lock(&dp->meters_lock);
        dp_meter_detach_free(&dp->meters, meter_id);
        ovs_mutex_unlock(&dp->meters_lock);
    }
    return error;
}


static void
dpif_netdev_disable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_disable_upcall(dp);
}

/* 启用 upcall（释放写锁允许新的 upcall 处理）。 */
static void
dp_netdev_enable_upcall(struct dp_netdev *dp)
    OVS_RELEASES(dp->upcall_rwlock)
{
    fat_rwlock_unlock(&dp->upcall_rwlock);
}

static void
dpif_netdev_enable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_enable_upcall(dp);
}

/* PMD 完成重载：清除 reload/wait_for_reload 标志，更新序列号。 */
static void
dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd)
{
    atomic_store_relaxed(&pmd->wait_for_reload, false);
    atomic_store_relaxed(&pmd->reload_tx_qid, false);
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_store_explicit(&pmd->reload, false, memory_order_release);
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL (it can return NULL even if
 * 'core_id' is NON_PMD_CORE_ID).
 *
 * Caller must unrefs the returned reference.  */
/* 按 core_id 查找 PMD 线程并增加引用计数。调用者负责 unref。 */
static struct dp_netdev_pmd_thread *
dp_netdev_get_pmd(struct dp_netdev *dp, unsigned core_id)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH_WITH_HASH (pmd, node, hash_int(core_id, 0),
                             &dp->poll_threads) {
        if (pmd->core_id == core_id) {
            return dp_netdev_pmd_try_ref(pmd) ? pmd : NULL;
        }
    }

    return NULL;
}

/* Sets the 'struct dp_netdev_pmd_thread' for non-pmd threads. */
/* 创建非 PMD 线程的伪 PMD 结构（用于主线程处理非 DPDK 端口）。 */
static void
dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_pmd_thread *non_pmd;

    non_pmd = xzalloc(sizeof *non_pmd);
    dp_netdev_configure_pmd(non_pmd, dp, NON_PMD_CORE_ID, OVS_NUMA_UNSPEC);
}

/* Caller must have valid pointer to 'pmd'. */
static bool
dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd)
{
    return ovs_refcount_try_ref_rcu(&pmd->ref_cnt);
}

static void
dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd && ovs_refcount_unref(&pmd->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_destroy_pmd, pmd);
    }
}

/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos)
{
    struct dp_netdev_pmd_thread *next;

    do {
        struct cmap_node *node;

        node = cmap_next_position(&dp->poll_threads, pos);
        next = node ? CONTAINER_OF(node, struct dp_netdev_pmd_thread, node)
            : NULL;
    } while (next && !dp_netdev_pmd_try_ref(next));

    return next;
}

/* Configures the 'pmd' based on the input argument. */
/* 初始化 PMD 线程结构体：设置 core_id、NUMA、flow_table、classifiers、
 * 性能统计、netdev_input 函数指针、miniflow 提取函数等。
 * 对非 PMD 线程（NON_PMD_CORE_ID）还会初始化 flow_cache 和 TX 队列。 */
static void
dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev *dp,
                        unsigned core_id, int numa_id)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    pmd->dp = dp;
    pmd->core_id = core_id;
    pmd->numa_id = numa_id;
    pmd->need_reload = false;
    pmd->n_output_batches = 0;

    ovs_refcount_init(&pmd->ref_cnt);
    atomic_init(&pmd->exit, false);
    pmd->reload_seq = seq_create();
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_init(&pmd->reload, false);
    ovs_mutex_init(&pmd->flow_mutex);
    ovs_mutex_init(&pmd->port_mutex);
    ovs_mutex_init(&pmd->bond_mutex);
    cmap_init(&pmd->flow_table);
    cmap_init(&pmd->classifiers);
    cmap_init(&pmd->simple_match_table);
    ccmap_init(&pmd->n_flows);
    ccmap_init(&pmd->n_simple_flows);
    pmd->ctx.last_rxq = NULL;
    pmd_thread_ctx_time_update(pmd);
    pmd->next_optimization = pmd->ctx.now + DPCLS_OPTIMIZATION_INTERVAL;
    pmd->next_rcu_quiesce = pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
    pmd->next_cycle_store = pmd->ctx.now + PMD_INTERVAL_LEN;
    pmd->busy_cycles_intrvl = xzalloc(PMD_INTERVAL_MAX *
                                      sizeof *pmd->busy_cycles_intrvl);
    hmap_init(&pmd->poll_list);
    hmap_init(&pmd->tx_ports);
    hmap_init(&pmd->tnl_port_cache);
    hmap_init(&pmd->send_port_cache);
    cmap_init(&pmd->tx_bonds);

    pmd_init_max_sleep(dp, pmd);

    /* Initialize DPIF function pointer to the default configured version. */
    atomic_init(&pmd->netdev_input_func, dp_netdev_impl_get_default());

    /* Init default miniflow_extract function */
    atomic_init(&pmd->miniflow_extract_opt, dp_mfex_impl_get_default());

    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */
    if (core_id == NON_PMD_CORE_ID) {
        dfc_cache_init(&pmd->flow_cache);
        pmd_alloc_static_tx_qid(pmd);
    }
    pmd_perf_stats_init(&pmd->perf_stats);
    latency_stats_init(&pmd->latency_stats); /* @veencn_260223 */
    cmap_insert(&dp->poll_threads, CONST_CAST(struct cmap_node *, &pmd->node),
                hash_int(core_id, 0));
}

/* 销毁 PMD 结构体：清空流表、销毁所有 cmap/hmap、释放内存。 */
static void
dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dpcls *cls;

    dp_netdev_pmd_flow_flush(pmd);
    hmap_destroy(&pmd->send_port_cache);
    hmap_destroy(&pmd->tnl_port_cache);
    hmap_destroy(&pmd->tx_ports);
    cmap_destroy(&pmd->tx_bonds);
    hmap_destroy(&pmd->poll_list);
    free(pmd->busy_cycles_intrvl);
    /* All flows (including their dpcls_rules) have been deleted already */
    CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
        dpcls_destroy(cls);
        ovsrcu_postpone(free, cls);
    }
    cmap_destroy(&pmd->classifiers);
    cmap_destroy(&pmd->flow_table);
    cmap_destroy(&pmd->simple_match_table);
    ccmap_destroy(&pmd->n_flows);
    ccmap_destroy(&pmd->n_simple_flows);
    ovs_mutex_destroy(&pmd->flow_mutex);
    seq_destroy(pmd->reload_seq);
    ovs_mutex_destroy(&pmd->port_mutex);
    ovs_mutex_destroy(&pmd->bond_mutex);
    free(pmd->netdev_input_func_userdata);
    free(pmd);
}

/* Stops the pmd thread, removes it from the 'dp->poll_threads',
 * and unrefs the struct. */
/* 停止并删除 PMD 线程：设 exit 标志，等待线程退出，清理端口和流。 */
static void
dp_netdev_del_pmd(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    /* NON_PMD_CORE_ID doesn't have a thread, so we don't have to synchronize,
     * but extra cleanup is necessary */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        dfc_cache_uninit(&pmd->flow_cache);
        pmd_free_cached_ports(pmd);
        pmd_free_static_tx_qid(pmd);
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    } else {
        atomic_store_relaxed(&pmd->exit, true);
        dp_netdev_reload_pmd__(pmd);
        xpthread_join(pmd->thread, NULL);
    }

    dp_netdev_pmd_clear_ports(pmd);

    /* Purges the 'pmd''s flows after stopping the thread, but before
     * destroying the flows, so that the flow stats can be collected. */
    if (dp->dp_purge_cb) {
        dp->dp_purge_cb(dp->dp_purge_aux, pmd->core_id);
    }
    cmap_remove(&pmd->dp->poll_threads, &pmd->node, hash_int(pmd->core_id, 0));
    dp_netdev_pmd_unref(pmd);
}

/* Destroys all pmd threads. If 'non_pmd' is true it also destroys the non pmd
 * thread. */
static void
dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (!non_pmd && pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        /* We cannot call dp_netdev_del_pmd(), since it alters
         * 'dp->poll_threads' (while we're iterating it) and it
         * might quiesce. */
        ovs_assert(k < n_pmds);
        pmd_list[k++] = pmd;
    }

    for (size_t i = 0; i < k; i++) {
        dp_netdev_del_pmd(dp, pmd_list[i]);
    }
    free(pmd_list);
}

/* Deletes all rx queues from pmd->poll_list and all the ports from
 * pmd->tx_ports. */
static void
dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct rxq_poll *poll;
    struct tx_port *port;
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_POP (poll, node, &pmd->poll_list) {
        free(poll);
    }
    HMAP_FOR_EACH_POP (port, node, &pmd->tx_ports) {
        free(port->txq_pkts);
        free(port);
    }
    ovs_mutex_unlock(&pmd->port_mutex);

    ovs_mutex_lock(&pmd->bond_mutex);
    CMAP_FOR_EACH (tx, node, &pmd->tx_bonds) {
        cmap_remove(&pmd->tx_bonds, &tx->node, hash_bond_id(tx->bond_id));
        ovsrcu_postpone(free, tx);
    }
    ovs_mutex_unlock(&pmd->bond_mutex);
}

/* Adds rx queue to poll_list of PMD thread, if it's not there already. */
static void
dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                         struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex)
{
    int qid = netdev_rxq_get_queue_id(rxq->rx);
    uint32_t hash = hash_2words(odp_to_u32(rxq->port->port_no), qid);
    struct rxq_poll *poll;

    HMAP_FOR_EACH_WITH_HASH (poll, node, hash, &pmd->poll_list) {
        if (poll->rxq == rxq) {
            /* 'rxq' is already polled by this thread. Do nothing. */
            return;
        }
    }

    poll = xmalloc(sizeof *poll);
    poll->rxq = rxq;
    hmap_insert(&pmd->poll_list, &poll->node, hash);

    pmd->need_reload = true;
}

/* Delete 'poll' from poll_list of PMD thread. */
static void
dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                           struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->poll_list, &poll->node);
    free(poll);

    pmd->need_reload = true;
}

/* Add 'port' to the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                             struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx;

    tx = tx_port_lookup(&pmd->tx_ports, port->port_no);
    if (tx) {
        /* 'port' is already on this thread tx cache. Do nothing. */
        return;
    }

    tx = xzalloc(sizeof *tx);

    tx->port = port;
    tx->qid = -1;
    tx->flush_time = 0LL;
    dp_packet_batch_init(&tx->output_pkts);

    if (tx->port->txq_mode == TXQ_MODE_XPS_HASH) {
        int i, n_txq = netdev_n_txq(tx->port->netdev);

        tx->txq_pkts = xzalloc(n_txq * sizeof *tx->txq_pkts);
        for (i = 0; i < n_txq; i++) {
            dp_packet_batch_init(&tx->txq_pkts[i]);
        }
    }

    hmap_insert(&pmd->tx_ports, &tx->node, hash_port_no(tx->port->port_no));
    pmd->need_reload = true;
}

/* Del 'tx' from the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                               struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->tx_ports, &tx->node);
    free(tx->txq_pkts);
    free(tx);
    pmd->need_reload = true;
}

/* Add bond to the tx bond cmap of 'pmd'. */
static void
dp_netdev_add_bond_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                             struct tx_bond *bond, bool update)
    OVS_EXCLUDED(pmd->bond_mutex)
{
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->bond_mutex);
    tx = tx_bond_lookup(&pmd->tx_bonds, bond->bond_id);

    if (tx && !update) {
        /* It's not an update and the entry already exists.  Do nothing. */
        goto unlock;
    }

    if (tx) {
        struct tx_bond *new_tx = xmemdup(bond, sizeof *bond);

        /* Copy the stats for each bucket. */
        for (int i = 0; i < BOND_BUCKETS; i++) {
            uint64_t n_packets, n_bytes;

            atomic_read_relaxed(&tx->member_buckets[i].n_packets, &n_packets);
            atomic_read_relaxed(&tx->member_buckets[i].n_bytes, &n_bytes);
            atomic_init(&new_tx->member_buckets[i].n_packets, n_packets);
            atomic_init(&new_tx->member_buckets[i].n_bytes, n_bytes);
        }
        cmap_replace(&pmd->tx_bonds, &tx->node, &new_tx->node,
                     hash_bond_id(bond->bond_id));
        ovsrcu_postpone(free, tx);
    } else {
        tx = xmemdup(bond, sizeof *bond);
        cmap_insert(&pmd->tx_bonds, &tx->node, hash_bond_id(bond->bond_id));
    }
unlock:
    ovs_mutex_unlock(&pmd->bond_mutex);
}

/* Delete bond from the tx bond cmap of 'pmd'. */
static void
dp_netdev_del_bond_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                               uint32_t bond_id)
    OVS_EXCLUDED(pmd->bond_mutex)
{
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->bond_mutex);
    tx = tx_bond_lookup(&pmd->tx_bonds, bond_id);
    if (tx) {
        cmap_remove(&pmd->tx_bonds, &tx->node, hash_bond_id(tx->bond_id));
        ovsrcu_postpone(free, tx);
    }
    ovs_mutex_unlock(&pmd->bond_mutex);
}

/* 返回数据路径版本信息（内置版本）。 */
static char *
dpif_netdev_get_datapath_version(void)
{
     return xstrdup("<built-in>");
}

/* 更新流的统计信息：包数、字节数、最后使用时间、TCP 标志。 */
static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow, int cnt, int size,
                    uint16_t tcp_flags, long long now)
{
    uint16_t flags;

    atomic_store_relaxed(&netdev_flow->stats.used, now);
    non_atomic_ullong_add(&netdev_flow->stats.packet_count, cnt);
    non_atomic_ullong_add(&netdev_flow->stats.byte_count, size);
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    flags |= tcp_flags;
    atomic_store_relaxed(&netdev_flow->stats.tcp_flags, flags);
}

/* 触发 upcall：将未匹配的报文上送到 vswitchd 的 upcall 处理器。
 * upcall 处理器会执行 OpenFlow 流表查找并返回 actions。 */
static int
dp_netdev_upcall(struct dp_netdev_pmd_thread *pmd, struct dp_packet *packet_,
                 struct flow *flow, struct flow_wildcards *wc, ovs_u128 *ufid,
                 enum dpif_upcall_type type, const struct nlattr *userdata,
                 struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct dp_netdev *dp = pmd->dp;

    if (OVS_UNLIKELY(!dp->upcall_cb)) {
        return ENODEV;
    }

    if (OVS_UNLIKELY(!VLOG_DROP_DBG(&upcall_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet_str;
        struct ofpbuf key;
        struct odp_flow_key_parms odp_parms = {
            .flow = flow,
            .mask = wc ? &wc->masks : NULL,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key, 0);
        odp_flow_key_from_flow(&odp_parms, &key);
        packet_str = ofp_dp_packet_to_string(packet_);

        odp_flow_key_format(key.data, key.size, &ds);

        VLOG_DBG("%s: %s upcall:\n%s\n%s", dp->name,
                 dpif_upcall_type_to_string(type), ds_cstr(&ds), packet_str);

        ofpbuf_uninit(&key);
        free(packet_str);

        ds_destroy(&ds);
    }

    if (type != DPIF_UC_MISS) {
        dp_packet_ol_send_prepare(packet_, 0);
    }

    return dp->upcall_cb(packet_, flow, ufid, pmd->core_id, type, userdata,
                         actions, wc, put_actions, dp->upcall_aux);
}

/* =====================================================
 * 数据面报文处理核心（dp_netdev_input 调用链）。
 *
 * 报文处理的完整流程：
 * 1. miniflow_extract: 从报文头提取字段到 miniflow key
 * 2. EMC 精确匹配缓存查找（hash + memcmp）
 * 3. SMC 签名匹配缓存查找（16位签名 + 规则验证）
 * 4. dpcls 通配符分类器查找（遍历子表批量匹配）
 * 5. upcall 慢路径（发送到 vswitchd 做 OpenFlow 匹配）
 * 6. 按流批量执行 actions
 * ===================================================== */

/* 获取或计算报文的 RSS hash，考虑 recirculation 深度。 */
static inline uint32_t
dpif_netdev_packet_get_rss_hash(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash, recirc_depth;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    /* The RSS hash must account for the recirculation depth to avoid
     * collisions in the exact match cache */
    recirc_depth = *recirc_depth_get_unsafe();
    if (OVS_UNLIKELY(recirc_depth)) {
        hash = hash_finish(hash, recirc_depth);
    }
    return hash;
}

/* 按流分组的报文批次：将匹配同一条流的报文聚合在一起，一次性执行 actions。 */
struct packet_batch_per_flow {
    unsigned int byte_count;    /* 累计字节数 */
    uint16_t tcp_flags;         /* 合并的 TCP 标志 */
    struct dp_netdev_flow *flow; /* 关联的流 */
    struct dp_packet_batch array; /* 报文数组 */
};

static inline void
packet_batch_per_flow_update(struct packet_batch_per_flow *batch,
                             struct dp_packet *packet,
                             uint16_t tcp_flags)
{
    batch->byte_count += dp_packet_size(packet);
    batch->tcp_flags |= tcp_flags;
    dp_packet_batch_add(&batch->array, packet);
}

static inline void
packet_batch_per_flow_init(struct packet_batch_per_flow *batch,
                           struct dp_netdev_flow *flow)
{
    flow->batch = batch;

    batch->flow = flow;
    dp_packet_batch_init(&batch->array);
    batch->byte_count = 0;
    batch->tcp_flags = 0;
}

/* 执行一个 per-flow 批次 — 数据包处理流水线的最后一步。
 *
 * 将同一条流的所有数据包一次性执行 action，步骤：
 * 1. 更新流的使用统计（包数、字节数、TCP 标志、最后使用时间）
 * 2. 通过 RCU 获取流的 actions（可能被 revalidator 并发更新）
 * 3. 调用 dp_netdev_execute_actions() 执行所有 action
 *
 * should_steal = true：执行完后 actions 负责释放数据包内存，
 * 调用者不再持有这些包的所有权。 */
static inline void
packet_batch_per_flow_execute(struct packet_batch_per_flow *batch,
                              struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_actions *actions;
    struct dp_netdev_flow *flow = batch->flow;

    /* 步骤 1：更新流的使用统计。
     * 这些统计可通过 ovs-appctl dpctl/dump-flows 查看：
     *   - packets: 累计包数
     *   - bytes:   累计字节数
     *   - tcp_flags: 聚合的 TCP 标志位（用于 revalidator 判断连接状态）
     *   - used:    最后使用时间戳（毫秒，用于流过期判断） */
    dp_netdev_flow_used(flow, dp_packet_batch_size(&batch->array),
                        batch->byte_count,
                        batch->tcp_flags, pmd->ctx.now / 1000);

    /* 步骤 2：获取流的 actions（RCU 保护读取）。
     * actions 可能被 revalidator 线程通过 flow_put 更新，
     * 这里用 ovsrcu_get 保证读到一致的版本。 */
    actions = dp_netdev_flow_get_actions(flow);

    /* @veencn_260223: 记录 action 执行延迟和端到端总延迟 */
    LATENCY(pmd, BEGIN, t_action_start);

    /* 步骤 3：执行 actions。
     * 内部调用 odp_execute_actions()，遍历 action 列表，
     * 对每个 action 调用 dp_execute_cb() 回调：
     *   OUTPUT → 发送到端口
     *   SET/SET_MASKED → 修改包头
     *   CT → conntrack 处理
     *   RECIRC → 重新进入 dp_netdev_input__()
     *   等等...
     * should_steal=true：action 执行后自动释放包内存 */
    dp_netdev_execute_actions(pmd, &batch->array, true, &flow->flow,
                              actions->actions, actions->size);

    LATENCY(pmd, END, t_action_start, action_exec,
            latency_batch_total(&pmd->latency_stats,
                                &batch->array, _lend));
}

/* 直接执行批量报文的 actions（SIMD 优化路径使用）。 */
void
dp_netdev_batch_execute(struct dp_netdev_pmd_thread *pmd,
                        struct dp_packet_batch *packets,
                        struct dpcls_rule *rule,
                        uint32_t bytes,
                        uint16_t tcp_flags)
{
    /* Gets action* from the rule. */
    struct dp_netdev_flow *flow = dp_netdev_flow_cast(rule);
    struct dp_netdev_actions *actions = dp_netdev_flow_get_actions(flow);

    dp_netdev_flow_used(flow, dp_packet_batch_size(packets), bytes,
                        tcp_flags, pmd->ctx.now / 1000);
    const uint32_t steal = 1;
    dp_netdev_execute_actions(pmd, packets, steal, &flow->flow,
                              actions->actions, actions->size);
}

/* 将报文加入对应流的批次。若该流还没有批次则创建新批次。 */
static inline void
dp_netdev_queue_batches(struct dp_packet *pkt,
                        struct dp_netdev_flow *flow, uint16_t tcp_flags,
                        struct packet_batch_per_flow *batches,
                        size_t *n_batches)
{
    struct packet_batch_per_flow *batch = flow->batch;

    if (OVS_UNLIKELY(!batch)) {
        batch = &batches[(*n_batches)++];
        packet_batch_per_flow_init(batch, flow);
    }

    packet_batch_per_flow_update(batch, pkt, tcp_flags);
}

/* 将报文记录到 flow_map 数组中（用于 SMC 查找后的批量处理）。 */
static inline void
packet_enqueue_to_flow_map(struct dp_packet *packet,
                           struct dp_netdev_flow *flow,
                           uint16_t tcp_flags,
                           struct dp_packet_flow_map *flow_map,
                           size_t index)
{
    struct dp_packet_flow_map *map = &flow_map[index];
    map->flow = flow;
    map->packet = packet;
    map->tcp_flags = tcp_flags;
}

/* SMC lookup function for a batch of packets.
 * By doing batching SMC lookup, we can use prefetch
 * to hide memory access latency.
 */
/* SMC 批量查找：先 prefetch 所有桶位，再逐个匹配签名和规则。
 * 命中的报文加入 flow_map，未命中的留在 packets_ 中传给 dpcls。 */
static inline void
smc_lookup_batch(struct dp_netdev_pmd_thread *pmd,
            struct netdev_flow_key *keys,
            struct netdev_flow_key **missed_keys,
            struct dp_packet_batch *packets_,
            const int cnt,
            struct dp_packet_flow_map *flow_map,
            uint8_t *index_map)
{
    int i;
    struct dp_packet *packet;
    size_t n_smc_hit = 0, n_missed = 0;
    struct dfc_cache *cache = &pmd->flow_cache;
    struct smc_cache *smc_cache = &cache->smc_cache;
    const struct cmap_node *flow_node;
    int recv_idx;
    uint16_t tcp_flags;

    /* Prefetch buckets for all packets */
    for (i = 0; i < cnt; i++) {
        OVS_PREFETCH(&smc_cache->buckets[keys[i].hash & SMC_MASK]);
    }

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow = NULL;
        flow_node = smc_entry_get(pmd, keys[i].hash);
        bool hit = false;
        /* Get the original order of this packet in received batch. */
        recv_idx = index_map[i];

        if (OVS_LIKELY(flow_node != NULL)) {
            CMAP_NODE_FOR_EACH (flow, node, flow_node) {
                /* Since we dont have per-port megaflow to check the port
                 * number, we need to  verify that the input ports match. */
                if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, &keys[i]) &&
                flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) {
                    tcp_flags = miniflow_get_tcp_flags(&keys[i].mf);

                    /* @veencn_260223: SMC hit - record lookup latency. */
                    LATENCY(pmd, MARK, packet, smc_lookup,
                            pmd->latency_stats.smc_hit_count++);

                    /* SMC hit and emc miss, we insert into EMC */
                    keys[i].len =
                        netdev_flow_key_size(miniflow_n_values(&keys[i].mf));
                    emc_probabilistic_insert(pmd, &keys[i], flow);
                    /* Add these packets into the flow map in the same order
                     * as received.
                     */
                    packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                               flow_map, recv_idx);
                    n_smc_hit++;
                    hit = true;
                    break;
                }
            }
            if (hit) {
                continue;
            }
        }

        /* SMC missed. Group missed packets together at
         * the beginning of the 'packets' array. */
        dp_packet_batch_refill(packets_, packet, i);

        /* Preserve the order of packet for flow batching. */
        index_map[n_missed] = recv_idx;

        /* Put missed keys to the pointer arrays return to the caller */
        missed_keys[n_missed++] = &keys[i];
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SMC_HIT, n_smc_hit);
}

/* 单包 SMC 查找 — 用于非批量场景。
 * 通过 key 的哈希在 SMC 中定位 flow_node，然后逐个检查
 * dpcls_rule 是否匹配 key 且入端口一致。
 * SMC 没有 per-port megaflow，因此必须额外验证入端口。 */
struct dp_netdev_flow *
smc_lookup_single(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet *packet,
                  struct netdev_flow_key *key)
{
    const struct cmap_node *flow_node = smc_entry_get(pmd, key->hash);

    if (OVS_LIKELY(flow_node != NULL)) {
        struct dp_netdev_flow *flow = NULL;

        CMAP_NODE_FOR_EACH (flow, node, flow_node) {
            /* Since we dont have per-port megaflow to check the port
             * number, we need to verify that the input ports match. */
            if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, key) &&
                flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) {

                return (void *) flow;
            }
        }
    }

    return NULL;
}

/* 硬件卸载流查找（PHWOL post-process）。
 *
 * 背景：智能网卡（如 Mellanox/NVIDIA ConnectX）可以在硬件中完成流表匹配。
 * 网卡收包时已经知道此包匹配哪条流规则，将匹配结果（flow 指针）附在包的
 * 元数据中。软件只需调用 post-process API 取出这个引用即可，跳过所有
 * 软件层面的 miniflow 提取和 EMC/SMC/dpcls 查找。
 *
 * 返回值语义：
 *   返回 0,  *flow != NULL → 硬件命中，直接使用此 flow
 *   返回 0,  *flow == NULL → 硬件未匹配（或不支持），走软件路径
 *   返回 -1              → 硬件处理出错，数据包应被丢弃 */
inline int
dp_netdev_hw_flow(const struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet *packet,
                  struct dp_netdev_flow **flow)
{
    /* 获取当前正在处理的 RXQ（由 dp_netdev_process_rxq_port 设置） */
    struct dp_netdev_rxq *rxq = pmd->ctx.last_rxq;
    bool post_process_api_supported;
    void *flow_reference = NULL;
    int err;

    /* 检查此端口的网卡是否支持 post-process API。
     * 使用 relaxed 原子读取（性能敏感的热路径，不需要内存屏障）。 */
    atomic_read_relaxed(&rxq->port->netdev->hw_info.post_process_api_supported,
                        &post_process_api_supported);

    /* 不支持 → 返回 0 + flow=NULL，调用者继续走软件查找路径 */
    if (!post_process_api_supported) {
        *flow = NULL;
        return 0;
    }

    /* 调用硬件 post-process API：
     * 从数据包元数据中提取网卡在硬件流表中匹配到的 flow 引用。
     * 成功时 flow_reference 指向已卸载的 dp_netdev_flow。 */
    err = dpif_offload_netdev_hw_post_process(rxq->port->netdev, pmd->core_id,
                                              packet, &flow_reference);
    if (err && err != EOPNOTSUPP) {
        /* 硬件处理出错 — 数据包不可用，需要丢弃 */
        if (err != ECANCELED) {
            /* 一般错误（如硬件流表过期、元数据损坏） */
            COVERAGE_INC(datapath_drop_hw_post_process);
        } else {
            /* ECANCELED：包已被硬件完全消费（如发送到硬件队列），
             * 软件不应再处理此包 */
            COVERAGE_INC(datapath_drop_hw_post_process_consumed);
        }
        return -1;
    }

    /* EOPNOTSUPP：硬件不支持此包的 post-process（flow_reference=NULL）
     * 成功：flow_reference 指向匹配的流（可能为 NULL 表示未命中） */
    *flow = flow_reference;
    return 0;
}

/* 将已分类的数据包加入 per-flow 批次或 flow_map。
 * batch_enable=true 时直接加入 batches（可以立即执行 action）；
 * batch_enable=false 时加入 flow_map 延迟处理（保持包序，
 * 因为 EMC 未命中的包还需要 fast_path_processing）。 */
/* Enqueues already classified packet into per-flow batches or the flow map,
 * depending on the fact if batching enabled. */
static inline void
dfc_processing_enqueue_classified_packet(struct dp_packet *packet,
                                         struct dp_netdev_flow *flow,
                                         uint16_t tcp_flags,
                                         bool batch_enable,
                                         struct packet_batch_per_flow *batches,
                                         size_t *n_batches,
                                         struct dp_packet_flow_map *flow_map,
                                         size_t *map_cnt)

{
    if (OVS_LIKELY(batch_enable)) {
        dp_netdev_queue_batches(packet, flow, tcp_flags, batches,
                                n_batches);
    } else {
        /* Flow batching should be performed only after fast-path
         * processing is also completed for packets with emc miss
         * or else it will result in reordering of packets with
         * same datapath flows. */
        packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                   flow_map, (*map_cnt)++);
    }

}

/* DFC（Datapath Flow Cache）处理 — 数据包的第一轮流表查找。
 *
 * 对收到的一批数据包依次尝试以下查找路径：
 * 1. 硬件卸载（PHWOL）：网卡已匹配的流，直接使用
 * 2. Simple Match：仅按 in_port/dl_type/nw_frag/vlan_tci 查找全流表
 * 3. EMC（Exact Match Cache）：通过 miniflow 提取的 key 在精确匹配缓存中查找
 * 4. SMC（Signature Match Cache）：EMC 未命中时，对未命中包做批量 SMC 查找
 *
 * 命中的包直接加入 batches 或 flow_map 等待执行 action。
 * 未命中的包被压缩到 packets 数组头部，返回给调用者进入 fast_path_processing（dpcls 查找）。
 *
 * 关键优化：
 * - Prefetch 下一个包的 data 和 metadata
 * - batch_enable 标志：一旦出现 EMC miss，后续包都进 flow_map 保序
 * - 统计计数器：PHWOL_HIT, SIMPLE_HIT, EXACT_HIT 等 */
/* Try to process all ('cnt') the 'packets' using only the datapath flow cache
 * 'pmd->flow_cache'. If a flow is not found for a packet 'packets[i]', the
 * miniflow is copied into 'keys' and the packet pointer is moved at the
 * beginning of the 'packets' array. The pointers of missed keys are put in the
 * missed_keys pointer array for future processing.
 *
 * The function returns the number of packets that needs to be processed in the
 * 'packets' array (they have been moved to the beginning of the vector).
 *
 * For performance reasons a caller may choose not to initialize the metadata
 * in 'packets_'.  If 'md_is_valid' is false, the metadata in 'packets'
 * is not valid and must be initialized by this function using 'port_no'.
 * If 'md_is_valid' is true, the metadata is already valid and 'port_no'
 * will be ignored.
 */
static inline size_t
dfc_processing(struct dp_netdev_pmd_thread *pmd,
               struct dp_packet_batch *packets_,  /* 输入/输出：未命中的包被压到头部 */
               struct netdev_flow_key *keys,       /* 输出：每个包提取的 miniflow key */
               struct netdev_flow_key **missed_keys, /* 输出：EMC+SMC 都未命中的 key 指针 */
               struct packet_batch_per_flow batches[], size_t *n_batches,
               struct dp_packet_flow_map *flow_map,  /* 输出：包→流映射（保序用） */
               size_t *n_flows, uint8_t *index_map,  /* 输出：miss 包在 flow_map 中的位置 */
               bool md_is_valid, odp_port_t port_no)
{
    const bool offload_enabled = dpif_offload_enabled();   /* 硬件卸载是否启用 */
    const uint32_t recirc_depth = *recirc_depth_get();     /* 当前 recirculation 深度 */
    const size_t cnt = dp_packet_batch_size(packets_);     /* 本批包的总数 */
    size_t n_missed = 0, n_emc_hit = 0, n_phwol_hit = 0;  /* 各路径命中计数 */
    size_t n_mfex_opt_hit = 0, n_simple_hit = 0;
    struct dfc_cache *cache = &pmd->flow_cache;   /* EMC + SMC 缓存 */
    struct netdev_flow_key *key = &keys[0];        /* 当前包使用的 key 槽位 */
    struct dp_packet *packet;
    size_t map_cnt = 0;          /* flow_map 的当前写入位置 */
    bool batch_enable = true;    /* 是否直接加入 batches（false 时进 flow_map 保序） */

    /* Simple Match 优化：仅在非 recirc 包且端口启用时可用。
     * simple_match_table 是完整流表（非缓存），未命中就必须 upcall，
     * 因此启用 simple match 时不需要 EMC/SMC。 */
    const bool simple_match_enabled =
        !md_is_valid && dp_netdev_simple_match_enabled(pmd, port_no);
    /* SMC 仅在未启用 simple match 且全局配置开启时生效 */
    const bool smc_enable_db = !simple_match_enabled && pmd->ctx.smc_enable_db;
    /* EMC 插入阈值：simple match 模式下设为 0（禁用 EMC 查找） */
    const uint32_t cur_min = simple_match_enabled
                             ? 0 : pmd->ctx.emc_insert_min;

    /* 统计本批包数：recirc 包计入 RECIRC，新收包计入 RECV */
    pmd_perf_update_counter(&pmd->perf_stats,
                            md_is_valid ? PMD_STAT_RECIRC : PMD_STAT_RECV,
                            cnt);

    /* === 主循环：逐包尝试各级查找 ===
     * 使用 DP_PACKET_BATCH_REFILL_FOR_EACH 宏：
     * 边遍历边"重填"—— 未命中的包被压缩到 packets_ 数组头部，
     * 命中的包被跳过（不放回），最终 packets_ 中只剩未命中的包。 */
    int i;
    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow = NULL;
        uint16_t tcp_flags;

        /* 丢弃过小的包（连以太网头都不够） */
        if (OVS_UNLIKELY(dp_packet_size(packet) < ETH_HEADER_LEN)) {
            dp_packet_delete(packet);
            COVERAGE_INC(datapath_drop_rx_invalid_packet);
            continue;
        }

        /* 预取下一个包的数据和 metadata 到 L1 cache。
         * 利用当前包的处理时间来隐藏下一个包的内存访问延迟。 */
        if (i != cnt - 1) {
            struct dp_packet **packets = packets_->packets;
            OVS_PREFETCH(dp_packet_data(packets[i+1]));
            pkt_metadata_prefetch_init(&packets[i+1]->md);
        }

        /* 首次从端口收包（非 recirc），需要初始化 metadata（设置 in_port） */
        if (!md_is_valid) {
            pkt_metadata_init(&packet->md, port_no);
        }

        /* --- 查找路径 1：硬件卸载（PHWOL）---
         * 仅在首次收包（recirc_depth==0）且启用卸载时尝试。
         * 网卡硬件已匹配的包直接返回 flow 引用，跳过所有软件查找。 */
        if (offload_enabled && recirc_depth == 0) {
            if (OVS_UNLIKELY(dp_netdev_hw_flow(pmd, packet, &flow))) {
                /* 硬件 post-process 失败，包已被丢弃 */
                continue;
            }
            if (OVS_LIKELY(flow)) {
                /* 硬件命中：解析 TCP 标志后直接入队 */
                tcp_flags = parse_tcp_flags(packet, NULL, NULL, NULL);
                n_phwol_hit++;
                dfc_processing_enqueue_classified_packet(
                        packet, flow, tcp_flags, batch_enable,
                        batches, n_batches, flow_map, &map_cnt);
                continue;
            }
        }

        /* --- 查找路径 2：Simple Match ---
         * 仅按 in_port + dl_type + nw_frag + vlan_tci 四个字段查找。
         * 不需要 miniflow_extract()，非常快。
         * 适用于流规则较少且匹配字段简单的场景。 */
        if (!flow && simple_match_enabled) {
            ovs_be16 dl_type = 0, vlan_tci = 0;
            uint8_t nw_frag = 0;

            tcp_flags = parse_tcp_flags(packet, &dl_type, &nw_frag, &vlan_tci);
            flow = dp_netdev_simple_match_lookup(pmd, port_no, dl_type,
                                                 nw_frag, vlan_tci);
            if (OVS_LIKELY(flow)) {
                n_simple_hit++;
                dfc_processing_enqueue_classified_packet(
                        packet, flow, tcp_flags, batch_enable,
                        batches, n_batches, flow_map, &map_cnt);
                continue;
            }
        }

        /* --- PHWOL 和 Simple Match 都未命中，进入 miniflow 路径 --- */

        /* 从数据包提取 miniflow（解析 L2/L3/L4 头部字段）。
         * 这是 CPU 密集型操作（约 50-100 个周期/包）。 */
        miniflow_extract(packet, &key->mf);
        key->len = 0; /* 长度稍后由 fast_path_processing 计算 */
        /* 计算 key 的哈希值。
         * 非 recirc 包优先使用网卡提供的 RSS hash（避免重新计算）；
         * recirc 包的 RSS hash 可能已被修改，需要重新计算。 */
        key->hash =
                (md_is_valid == false)
                ? dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf)
                : dpif_netdev_packet_get_rss_hash(packet, &key->mf);

        /* @veencn_260223: 记录 miniflow 提取延迟 */
        LATENCY(pmd, MARK, packet, miniflow);

        /* --- 查找路径 3：EMC（Exact Match Cache）---
         * cur_min > 0 时才查找（cur_min==0 表示 EMC 被禁用）。
         * EMC 是 per-PMD 的精确匹配哈希表，命中率最高时约 90%+。 */
        flow = (cur_min != 0) ? emc_lookup(&cache->emc_cache, key) : NULL;
        if (OVS_LIKELY(flow)) {
            /* EMC 命中 — 最快的软件路径 */
            /* @veencn_260223: 记录 EMC 命中延迟 */
            LATENCY(pmd, MARK, packet, emc_lookup,
                    pmd->latency_stats.emc_hit_count++);
            tcp_flags = miniflow_get_tcp_flags(&key->mf);
            n_emc_hit++;
            dfc_processing_enqueue_classified_packet(
                    packet, flow, tcp_flags, batch_enable,
                    batches, n_batches, flow_map, &map_cnt);
        } else {
            /* --- EMC 未命中 --- */

            /* 将未命中的包"重填"到 packets_ 数组头部。
             * 最终 packets_ 只包含 EMC 未命中的包，传给 fast_path_processing。 */
            dp_packet_batch_refill(packets_, packet, i);

            /* 在 flow_map 中为此包预留位置（flow=NULL 标记未分类）。
             * index_map 记录此 miss 包在 flow_map 中的原始位置，
             * 后续 fast_path_processing 命中后通过 index_map 回填。 */
            index_map[n_missed] = map_cnt;
            flow_map[map_cnt++].flow = NULL;

            /* 当前 key（keys[n_missed]）已填充了此包的 miniflow，
             * 保存到 missed_keys 指针数组供后续 SMC/dpcls 查找使用。
             * 将 key 指针前进到下一个槽位，准备给下一个包使用。 */
            missed_keys[n_missed] = key;
            key = &keys[++n_missed];

            /* 关键保序逻辑：一旦出现 EMC miss，后续所有包都进 flow_map
             * 而不是直接加入 batches。这样可以避免命中包"插队"到
             * 未命中包前面，导致同一条流的包乱序。 */
            batch_enable = false;
        }
    }

    /* flow_map 中的条目总数（包括命中和未命中的） */
    *n_flows = map_cnt;

    /* 更新各路径的命中统计 */
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_PHWOL_HIT, n_phwol_hit);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MFEX_OPT_HIT,
                            n_mfex_opt_hit);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SIMPLE_HIT,
                            n_simple_hit);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, n_emc_hit);

    /* --- 查找路径 4：SMC（Signature Match Cache）---
     * 仅在 SMC 启用且非 simple match 模式时执行。
     * 对所有 EMC 未命中的包做批量 SMC 查找。
     * SMC 命中的包会从 packets_ 中移除，剩余的继续给 dpcls。 */
    if (!smc_enable_db) {
        return dp_packet_batch_size(packets_);
    }

    smc_lookup_batch(pmd, keys, missed_keys, packets_,
                     n_missed, flow_map, index_map);

    /* 返回最终仍未命中的包数（这些包需要进入 fast_path_processing） */
    return dp_packet_batch_size(packets_);
}

/* 处理未命中流表的数据包（upcall）。
 * 流程：
 * 1. 从 miniflow 展开为 match
 * 2. 调用 upcall 回调（发送到 vswitchd 进行 OpenFlow 查表）
 * 3. 使用返回的 action 执行数据包处理
 * 4. 将新流表规则安装到 dpcls/EMC/SMC 中（避免后续包再次 upcall）
 * upcall 是慢路径，性能开销大，应尽量减少。 */
static inline int
handle_packet_upcall(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet *packet,
                     const struct netdev_flow_key *key,
                     struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct ofpbuf *add_actions;
    struct dp_packet_batch b;
    struct match match;
    ovs_u128 ufid;
    int error;
    uint64_t cycles = cycles_counter_update(&pmd->perf_stats);
    odp_port_t orig_in_port = packet->md.orig_in_port;

    match.tun_md.valid = false;
    miniflow_expand(&key->mf, &match.flow);
    memset(&match.wc, 0, sizeof match.wc);

    ofpbuf_clear(actions);
    ofpbuf_clear(put_actions);

    odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    error = dp_netdev_upcall(pmd, packet, &match.flow, &match.wc,
                             &ufid, DPIF_UC_MISS, NULL, actions,
                             put_actions);
    if (OVS_UNLIKELY(error && error != ENOSPC)) {
        dp_packet_delete(packet);
        COVERAGE_INC(datapath_drop_upcall_error);
        return error;
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in dpif_netdev_flow_put(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(VLAN_VID_MASK | VLAN_CFI);
    }

    /* We can't allow the packet batching in the next loop to execute
     * the actions.  Otherwise, if there are any slow path actions,
     * we'll send the packet up twice. */
    dp_packet_batch_init_packet(&b, packet);
    dp_netdev_execute_actions(pmd, &b, true, &match.flow,
                              actions->data, actions->size);

    add_actions = put_actions->size ? put_actions : actions;
    if (OVS_LIKELY(error != ENOSPC)) {
        struct dp_netdev_flow *netdev_flow;

        /* XXX: There's a race window where a flow covering this packet
         * could have already been installed since we last did the flow
         * lookup before upcall.  This could be solved by moving the
         * mutex lock outside the loop, but that's an awful long time
         * to be locking revalidators out of making flow modifications. */
        ovs_mutex_lock(&pmd->flow_mutex);
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
        if (OVS_LIKELY(!netdev_flow)) {
            netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid,
                                             add_actions->data,
                                             add_actions->size, orig_in_port);
        }
        ovs_mutex_unlock(&pmd->flow_mutex);
        uint32_t hash = dp_netdev_flow_hash(&netdev_flow->ufid);
        smc_insert(pmd, key, hash);
        emc_probabilistic_insert(pmd, key, netdev_flow);
    }
    if (pmd_perf_metrics_enabled(pmd)) {
        /* Update upcall stats. */
        cycles = cycles_counter_update(&pmd->perf_stats) - cycles;
        struct pmd_perf_stats *s = &pmd->perf_stats;
        s->current.upcalls++;
        s->current.upcall_cycles += cycles;
        histogram_add_sample(&s->cycles_per_upcall, cycles);
    }
    return error;
}

/* 快速路径处理 — 对 EMC/SMC 未命中的数据包进行 dpcls（megaflow）查找。
 *
 * 这是流表查找的第三级（也是最慢的软件级），前两级是 EMC 和 SMC。
 * 整体分为四个阶段：
 *
 * 阶段 1：dpcls 批量查找
 *   → 按 in_port 找到对应的 dpcls 分类器
 *   → 批量查找所有 key，结果存入 rules[] 数组
 *
 * 阶段 2：upcall 处理（仅有 miss 时）
 *   → 获取 upcall 读锁
 *   → 对每个未命中的包调用 handle_packet_upcall() 走慢路径
 *   → upcall 会安装新的 megaflow 规则到 dpcls
 *
 * 阶段 3：回填缓存 + 加入 flow_map
 *   → 命中的包回填 EMC 和 SMC（加速后续相同流的查找）
 *   → 按原始接收顺序加入 flow_map（保序）
 *
 * 阶段 4：更新统计计数器 */
static inline void
fast_path_processing(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet_batch *packets_,
                     struct netdev_flow_key **keys,
                     struct dp_packet_flow_map *flow_map,
                     uint8_t *index_map,
                     odp_port_t in_port)
{
    const size_t cnt = dp_packet_batch_size(packets_);  /* EMC/SMC 未命中的包数 */
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct dp_packet *packet;
    struct dpcls *cls;
    struct dpcls_rule *rules[PKT_ARRAY_SIZE];  /* 查找结果：每个包对应的 rule（NULL=miss） */
    struct dp_netdev *dp = pmd->dp;
    int upcall_ok_cnt = 0, upcall_fail_cnt = 0;  /* upcall 成功/失败计数 */
    int lookup_cnt = 0, add_lookup_cnt;  /* 子表查找总次数（用于统计） */
    bool any_miss;  /* 是否有包未命中 dpcls */

    /* === 阶段 1：dpcls 批量查找 === */

    /* 计算每个 key 的长度（dpcls_lookup 需要）。
     * 长度取决于 miniflow 中非零 unit 的数量。
     * hash 在 dpcls_lookup 内部按需计算。 */
    for (size_t i = 0; i < cnt; i++) {
        keys[i]->len = netdev_flow_key_size(miniflow_n_values(&keys[i]->mf));
    }

    /* 按入端口找到对应的 dpcls 分类器。
     * 每个入端口有独立的 dpcls，这样不同端口的流规则互不干扰。 */
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        /* 批量查找：将 cnt 个 key 同时在所有子表中查找。
         * rules[i] 指向命中的 dpcls_rule，未命中则为 NULL。
         * lookup_cnt 累加遍历的子表数（用于 MASKED_LOOKUP 统计）。
         * 返回 true 表示全部命中，false 表示存在 miss。 */
        any_miss = !dpcls_lookup(cls, (const struct netdev_flow_key **)keys,
                                rules, cnt, &lookup_cnt);
    } else {
        /* 该入端口没有分类器（新端口，还没有任何流规则），全部 miss */
        any_miss = true;
        memset(rules, 0, sizeof(rules));
    }

    /* @veencn_260223: 记录 dpcls 命中包的查找延迟 */
    LATENCY(pmd, MARK_BATCH, packets_, dpcls_lookup,
            dpcls_hit_count, rules);

    /* === 阶段 2：upcall 处理（慢路径）===
     * 仅在有 miss 且能获取 upcall 读锁时进入。
     * upcall_rwlock 是读写锁：
     *   - PMD 线程取读锁（允许并发 upcall）
     *   - disable_upcall() 取写锁（阻止所有 upcall，用于 datapath 重配置） */
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
        /* 使用栈上 stub 缓冲区避免 malloc（512 字节通常够用，超出会自动扩展） */
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;

        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            struct dp_netdev_flow *netdev_flow;

            /* 已命中的包跳过 */
            if (OVS_LIKELY(rules[i])) {
                continue;
            }

            /* 在执行昂贵的 upcall 之前，先再查一次流表。
             * 原因：同一批次中前面的包可能已经触发 upcall 并安装了新规则，
             * 后面的同类包就可以直接命中，避免重复 upcall。 */
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, keys[i],
                                                    &add_lookup_cnt);
            if (netdev_flow) {
                lookup_cnt += add_lookup_cnt;
                rules[i] = &netdev_flow->cr;
                continue;
            }

            /* @veencn_260223: 记录 upcall 延迟 */
            LATENCY(pmd, BEGIN, t_upcall_start);

            /* 核心 upcall 调用：
             * 1. 将包发送到 ofproto（OpenFlow 查表）
             * 2. 用返回的 action 执行数据包
             * 3. 将新的 megaflow 规则安装到 dpcls + EMC + SMC
             * 注意：upcall 会直接执行该包的 action，
             *       所以 upcall 的包不会再进入下面的 flow_map 流程 */
            int error = handle_packet_upcall(pmd, packet, keys[i],
                                             &actions, &put_actions);

            LATENCY(pmd, END, t_upcall_start, upcall,
                    pmd->latency_stats.upcall_count++);

            if (OVS_UNLIKELY(error)) {
                upcall_fail_cnt++;
            } else {
                upcall_ok_cnt++;
            }
        }

        ofpbuf_uninit(&actions);
        ofpbuf_uninit(&put_actions);
        fat_rwlock_unlock(&dp->upcall_rwlock);
    } else if (OVS_UNLIKELY(any_miss)) {
        /* upcall 读锁获取失败（说明正在 disable_upcall，即 datapath 重配置中）。
         * 无法执行 upcall，只能丢弃未命中的包。 */
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            if (OVS_UNLIKELY(!rules[i])) {
                dp_packet_delete(packet);
                COVERAGE_INC(datapath_drop_lock_error);
                upcall_fail_cnt++;
            }
        }
    }

    /* === 阶段 3：回填缓存 + 加入 flow_map ===
     * 对 dpcls 命中的包（rules[i] != NULL），做两件事：
     * 1. 回填 EMC 和 SMC — 下次相同流的包可以在更快的缓存中命中
     * 2. 按原始接收顺序（index_map）加入 flow_map — 保证包序不乱 */
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        struct dp_netdev_flow *flow;
        /* 从 index_map 获取此包在原始收包批次中的位置 */
        int recv_idx = index_map[i];
        uint16_t tcp_flags;

        /* 跳过 upcall 处理过的包（rules[i] 已被清空）和丢弃的包 */
        if (OVS_UNLIKELY(!rules[i])) {
            continue;
        }

        flow = dp_netdev_flow_cast(rules[i]);

        /* 回填 SMC：用 flow 的 ufid hash 作为 SMC 的签名 */
        uint32_t hash =  dp_netdev_flow_hash(&flow->ufid);
        smc_insert(pmd, keys[i], hash);

        /* 回填 EMC：概率性插入（不是每个包都插入，避免 EMC 抖动） */
        emc_probabilistic_insert(pmd, keys[i], flow);

        /* 将包加入 flow_map，使用原始接收顺序（recv_idx）保持包序。
         * 后续在 dp_netdev_input__ 中会将 flow_map 合并到 batches 批量执行。 */
        tcp_flags = miniflow_get_tcp_flags(&keys[i]->mf);
        packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                   flow_map, recv_idx);
    }

    /* === 阶段 4：更新性能统计 === */
    /* MASKED_HIT = dpcls 命中数（总包数 - upcall 成功 - upcall 失败） */
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_HIT,
                            cnt - upcall_ok_cnt - upcall_fail_cnt);
    /* MASKED_LOOKUP = dpcls 中遍历的子表总数（越少越好，说明热点子表排在前面） */
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_LOOKUP,
                            lookup_cnt);
    /* MISS = upcall 成功数（新流的首包） */
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MISS,
                            upcall_ok_cnt);
    /* LOST = upcall 失败数（丢弃的包） */
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_LOST,
                            upcall_fail_cnt);
}

/* 数据包进入数据路径的核心处理函数。
 * 数据包从端口接收或 recirculation 重入时都会调用此函数。
 *
 * 整体流程（三级流水线）：
 * 1. dfc_processing()   — 一级/二级缓存查找（PHWOL → Simple → EMC → SMC）
 * 2. fast_path_processing() — 三级分类器查找（dpcls），未命中则 upcall
 * 3. 合并所有 flow_map 条目到 batches，批量执行 action
 *
 * md_is_valid=false：首次从端口收包，需要用 port_no 初始化 metadata。
 * md_is_valid=true：recirculation 包，metadata 已由前一轮设置好。 */
/* Packets enter the datapath from a port (or from recirculation) here.
 *
 * When 'md_is_valid' is true the metadata in 'packets' are already valid.
 * When false the metadata in 'packets' need to be initialized. */
static void
dp_netdev_input__(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet_batch *packets,
                  bool md_is_valid, odp_port_t port_no)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = dp_packet_batch_size(packets);
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    /* keys[]：每个包的 miniflow key（cache-line 对齐以提升访问性能） */
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)
        struct netdev_flow_key keys[PKT_ARRAY_SIZE];
    /* missed_keys[]：EMC/SMC 都未命中的 key 指针，传给 fast_path_processing */
    struct netdev_flow_key *missed_keys[PKT_ARRAY_SIZE];
    /* batches[]：per-flow 的包批次，同一流的包聚合后一起执行 action */
    struct packet_batch_per_flow batches[PKT_ARRAY_SIZE];
    size_t n_batches;
    /* flow_map[]：记录包到 flow 的映射关系（保持原始接收顺序） */
    struct dp_packet_flow_map flow_map[PKT_ARRAY_SIZE];
    /* index_map[]：EMC miss 的包在 flow_map 中的原始位置索引 */
    uint8_t index_map[PKT_ARRAY_SIZE];
    size_t n_flows, i;

    odp_port_t in_port;

    /* 第一步：DFC 处理 — 尝试 EMC/SMC 缓存查找。
     * 命中的包直接加入 batches 或 flow_map；
     * 未命中的包被压缩到 packets 数组头部（返回值为未命中数）。 */
    n_batches = 0;
    dfc_processing(pmd, packets, keys, missed_keys, batches, &n_batches,
                   flow_map, &n_flows, index_map, md_is_valid, port_no);

    /* 第二步：EMC/SMC 未命中的包走 dpcls 通配符分类器查找。
     * 仍未命中则 upcall 到 vswitchd 进行 OpenFlow 查表。 */
    if (!dp_packet_batch_is_empty(packets)) {
        in_port = packets->packets[0]->md.in_port.odp_port;
        fast_path_processing(pmd, packets, missed_keys,
                             flow_map, index_map, in_port);
    }

    /* 第三步：将 flow_map 中延迟的包合并到 per-flow batches。
     * 这些包在 dfc_processing 中因为需要保序而未直接加入 batches。 */
    for (i = 0; i < n_flows; i++) {
        struct dp_packet_flow_map *map = &flow_map[i];

        if (OVS_UNLIKELY(!map->flow)) {
            continue;
        }
        dp_netdev_queue_batches(map->packet, map->flow, map->tcp_flags,
                                batches, &n_batches);
     }

    /* 第四步：清除所有 flow 的 batch 指针。
     * 必须在执行 action 前完成，因为 action 可能触发 recirculation，
     * 导致递归调用 dp_netdev_input__()。如果不清除，recirculation 中
     * 匹配到同一 flow 的包会错误地追加到外层调用的 batch 中。 */
    for (i = 0; i < n_batches; i++) {
        batches[i].flow->batch = NULL;
    }

    /* 第五步：批量执行每个 flow 的 action（发送、修改、隧道封装等）。 */
    for (i = 0; i < n_batches; i++) {
        packet_batch_per_flow_execute(&batches[i], pmd);
    }
}

/* 数据包从端口进入数据路径的公共入口函数。
 * md_is_valid=false，需要用 port_no 初始化 metadata。
 * 由 dp_netdev_process_rxq_port() 在收包后调用。 */
int32_t
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet_batch *packets,
                odp_port_t port_no)
{
    dp_netdev_input__(pmd, packets, false, port_no);
    return 0;
}

/* 将数据包重入（recirculation）到数据路径进行二次处理。
 * 常见场景：conntrack 处理后需要重新匹配流表、bond 选择后。 */
static void
dp_netdev_recirculate(struct dp_netdev_pmd_thread *pmd,
                      struct dp_packet_batch *packets)
{
    dp_netdev_input__(pmd, packets, true, 0);
}

/* dp_execute_cb 的辅助结构，携带 PMD 线程和流信息。 */
struct dp_netdev_execute_aux {
    struct dp_netdev_pmd_thread *pmd;
    const struct flow *flow;
};

/* 注册 dp 流表清除回调（PMD 删除时通知上层清理流表）。 */
static void
dpif_netdev_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb,
                                 void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->dp_purge_aux = aux;
    dp->dp_purge_cb = cb;
}

/* 注册 upcall 回调函数（流表未命中时调用此函数通知 vswitchd）。 */
static void
dpif_netdev_register_upcall_cb(struct dpif *dpif, upcall_callback *cb,
                               void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->upcall_aux = aux;
    dp->upcall_cb = cb;
}

/* XPS（Transmit Packet Steering）— PMD 发送方向的队列重验证。
 * 检查每个 TX 端口的队列分配是否过期（超过 XPS_TIMEOUT），
 * 如果过期或 purge=true，释放该 PMD 在此端口上占用的 TXQ。 */
static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge)
{
    struct tx_port *tx;
    struct dp_netdev_port *port;
    long long interval;

    HMAP_FOR_EACH (tx, node, &pmd->send_port_cache) {
        if (tx->port->txq_mode != TXQ_MODE_XPS) {
            continue;
        }
        interval = pmd->ctx.now - tx->last_used;
        if (tx->qid >= 0 && (purge || interval >= XPS_TIMEOUT)) {
            port = tx->port;
            ovs_mutex_lock(&port->txq_used_mutex);
            port->txq_used[tx->qid]--;
            ovs_mutex_unlock(&port->txq_used_mutex);
            tx->qid = -1;
        }
    }
}

/* XPS TX 队列 ID 获取 — 为 PMD 选择负载最低的 TX 队列。
 * 如果当前分配的 TXQ 未过期，直接返回；否则重新分配：
 * 遍历所有 TXQ，选择 txq_used[] 计数最小的队列。
 * 分配后还会触发一次 revalidate 清理过期的旧分配。 */
static int
dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                           struct tx_port *tx)
{
    struct dp_netdev_port *port;
    long long interval;
    int i, min_cnt, min_qid;

    interval = pmd->ctx.now - tx->last_used;
    tx->last_used = pmd->ctx.now;

    if (OVS_LIKELY(tx->qid >= 0 && interval < XPS_TIMEOUT)) {
        return tx->qid;
    }

    port = tx->port;

    ovs_mutex_lock(&port->txq_used_mutex);
    if (tx->qid >= 0) {
        port->txq_used[tx->qid]--;
        tx->qid = -1;
    }

    min_cnt = -1;
    min_qid = 0;
    for (i = 0; i < netdev_n_txq(port->netdev); i++) {
        if (port->txq_used[i] < min_cnt || min_cnt == -1) {
            min_cnt = port->txq_used[i];
            min_qid = i;
        }
    }

    port->txq_used[min_qid]++;
    tx->qid = min_qid;

    ovs_mutex_unlock(&port->txq_used_mutex);

    dpif_netdev_xps_revalidate_pmd(pmd, false);

    VLOG_DBG("Core %d: New TX queue ID %d for port \'%s\'.",
             pmd->core_id, tx->qid, netdev_get_name(tx->port->netdev));
    return min_qid;
}

/* 在隧道端口缓存中查找 TX 端口（用于隧道封装发送）。 */
static struct tx_port *
pmd_tnl_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                          odp_port_t port_no)
{
    return tx_port_lookup(&pmd->tnl_port_cache, port_no);
}

/* 在普通发送端口缓存中查找 TX 端口（用于非隧道发送）。 */
static struct tx_port *
pmd_send_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                           odp_port_t port_no)
{
    return tx_port_lookup(&pmd->send_port_cache, port_no);
}

/* 执行隧道封装（TUNNEL_PUSH）action。
 * 查找隧道端口，调用 netdev_push_header() 添加外层隧道头。
 * 失败时删除整个批次的包并返回错误。 */
static int
push_tnl_action(const struct dp_netdev_pmd_thread *pmd,
                const struct nlattr *attr,
                struct dp_packet_batch *batch)
{
    struct tx_port *tun_port;
    const struct ovs_action_push_tnl *data;
    int err;

    data = nl_attr_get(attr);

    tun_port = pmd_tnl_port_cache_lookup(pmd, data->tnl_port);
    if (!tun_port) {
        err = -EINVAL;
        goto error;
    }
    err = netdev_push_header(tun_port->port->netdev, batch, data);
    if (!err) {
        return 0;
    }
error:
    dp_packet_delete_batch(batch, true);
    return err;
}

/* 执行 USERSPACE action — 将数据包发送到用户空间处理。
 * 用于 sFlow 采样、NetFlow、packet-in 等场景。
 * 调用 dp_netdev_upcall() 通知 vswitchd，然后执行返回的 action。 */
static void
dp_execute_userspace_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet *packet, bool should_steal,
                            struct flow *flow, ovs_u128 *ufid,
                            struct ofpbuf *actions,
                            const struct nlattr *userdata)
{
    struct dp_packet_batch b;
    int error;

    ofpbuf_clear(actions);

    error = dp_netdev_upcall(pmd, packet, flow, NULL, ufid,
                             DPIF_UC_ACTION, userdata, actions,
                             NULL);
    if (!error || error == ENOSPC) {
        dp_packet_batch_init_packet(&b, packet);
        dp_netdev_execute_actions(pmd, &b, should_steal, flow,
                                  actions->data, actions->size);
    } else if (should_steal) {
        dp_packet_delete(packet);
        COVERAGE_INC(datapath_drop_userspace_action_error);
    }
}

/* 执行 OUTPUT action — 将数据包发送到指定端口。
 * 查找目标端口的 tx_port 缓存，将包添加到输出批次 output_pkts 中。
 * 如果输出批次满（超过 NETDEV_MAX_BURST）则先刷新。
 * should_steal=false 时需要克隆包（原包仍被调用者持有）。 */
static bool
dp_execute_output_action(struct dp_netdev_pmd_thread *pmd,
                         struct dp_packet_batch *packets_,
                         bool should_steal, odp_port_t port_no)
{
    struct tx_port *p = pmd_send_port_cache_lookup(pmd, port_no);
    struct dp_packet_batch out;

    if (!OVS_LIKELY(p)) {
        COVERAGE_ADD(datapath_drop_invalid_port,
                     dp_packet_batch_size(packets_));
        dp_packet_delete_batch(packets_, should_steal);
        return false;
    }
    if (!should_steal) {
        dp_packet_batch_clone(&out, packets_);
        dp_packet_batch_reset_cutlen(packets_);
        packets_ = &out;
    }
    dp_packet_batch_apply_cutlen(packets_);
#ifdef DPDK_NETDEV
    if (OVS_UNLIKELY(!dp_packet_batch_is_empty(&p->output_pkts)
                     && packets_->packets[0]->source
                        != p->output_pkts.packets[0]->source)) {
        /* XXX: netdev-dpdk assumes that all packets in a single
         *      output batch has the same source. Flush here to
         *      avoid memory access issues. */
        dp_netdev_pmd_flush_output_on_port(pmd, p);
    }
#endif
    if (dp_packet_batch_size(&p->output_pkts)
        + dp_packet_batch_size(packets_) > NETDEV_MAX_BURST) {
        /* Flush here to avoid overflow. */
        dp_netdev_pmd_flush_output_on_port(pmd, p);
    }
    if (dp_packet_batch_is_empty(&p->output_pkts)) {
        pmd->n_output_batches++;
    }

    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        p->output_pkts_rxqs[dp_packet_batch_size(&p->output_pkts)] =
            pmd->ctx.last_rxq;
        dp_packet_batch_add(&p->output_pkts, packet);
    }
    return true;
}

/* 执行 LB_OUTPUT（负载均衡输出）action — bond 场景。
 * 通过数据包的 RSS hash 选择 bond 成员端口，
 * 逐包发送到对应的成员端口，并更新成员的包/字节统计。 */
static void
dp_execute_lb_output_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet_batch *packets_,
                            bool should_steal, uint32_t bond)
{
    struct tx_bond *p_bond = tx_bond_lookup(&pmd->tx_bonds, bond);
    struct dp_packet_batch out;
    struct dp_packet *packet;

    if (!p_bond) {
        COVERAGE_ADD(datapath_drop_invalid_bond,
                     dp_packet_batch_size(packets_));
        dp_packet_delete_batch(packets_, should_steal);
        return;
    }
    if (!should_steal) {
        dp_packet_batch_clone(&out, packets_);
        dp_packet_batch_reset_cutlen(packets_);
        packets_ = &out;
    }
    dp_packet_batch_apply_cutlen(packets_);

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        /*
         * Lookup the bond-hash table using hash to get the member.
         */
        uint32_t hash = dp_packet_get_rss_hash(packet);
        struct member_entry *s_entry
            = &p_bond->member_buckets[hash & BOND_MASK];
        odp_port_t bond_member = s_entry->member_id;
        uint32_t size = dp_packet_size(packet);
        struct dp_packet_batch output_pkt;

        dp_packet_batch_init_packet(&output_pkt, packet);
        if (OVS_LIKELY(dp_execute_output_action(pmd, &output_pkt, true,
                                                bond_member))) {
            /* Update member stats. */
            non_atomic_ullong_add(&s_entry->n_packets, 1);
            non_atomic_ullong_add(&s_entry->n_bytes, size);
        }
    }
}

/* action 执行回调 — 由 odp_execute_actions() 对每个 action 调用。
 * 处理各类 ODP action：
 * - OVS_ACTION_ATTR_OUTPUT：发送到指定端口
 * - OVS_ACTION_ATTR_TUNNEL_PUSH/POP：隧道封装/解封装
 * - OVS_ACTION_ATTR_USERSPACE：发送到用户空间（sFlow/NetFlow 等）
 * - OVS_ACTION_ATTR_RECIRC：recirculation（重入处理）
 * - OVS_ACTION_ATTR_CT：连接跟踪
 * - OVS_ACTION_ATTR_METER：meter 计量
 * - OVS_ACTION_ATTR_LB_OUTPUT：bond 输出
 * 这是数据路径 action 执行的核心分发器。 */
static void
dp_execute_cb(void *aux_, struct dp_packet_batch *packets_,
              const struct nlattr *a, bool should_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    uint32_t *depth = recirc_depth_get();
    struct dp_netdev_pmd_thread *pmd = aux->pmd;
    struct dp_netdev *dp = pmd->dp;
    int type = nl_attr_type(a);
    struct tx_port *p;
    uint32_t packet_count, packets_dropped;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        dp_execute_output_action(pmd, packets_, should_steal,
                                 nl_attr_get_odp_port(a));
        return;

    case OVS_ACTION_ATTR_LB_OUTPUT:
        dp_execute_lb_output_action(pmd, packets_, should_steal,
                                    nl_attr_get_u32(a));
        return;

    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        if (should_steal) {
            /* We're requested to push tunnel header, but also we need to take
             * the ownership of these packets. Thus, we can avoid performing
             * the action, because the caller will not use the result anyway.
             * Just break to free the batch. */
            break;
        }
        dp_packet_batch_apply_cutlen(packets_);
        packet_count = dp_packet_batch_size(packets_);
        if (push_tnl_action(pmd, a, packets_)) {
            COVERAGE_ADD(datapath_drop_tunnel_push_error,
                         packet_count);
        }
        return;

    case OVS_ACTION_ATTR_TUNNEL_POP:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch *orig_packets_ = packets_;
            odp_port_t portno = nl_attr_get_odp_port(a);

            p = pmd_tnl_port_cache_lookup(pmd, portno);
            if (p) {
                struct dp_packet_batch tnl_pkt;

                if (!should_steal) {
                    dp_packet_batch_clone(&tnl_pkt, packets_);
                    packets_ = &tnl_pkt;
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                dp_packet_batch_apply_cutlen(packets_);

                packet_count = dp_packet_batch_size(packets_);
                netdev_pop_header(p->port->netdev, packets_);
                packets_dropped =
                   packet_count - dp_packet_batch_size(packets_);
                if (packets_dropped) {
                    COVERAGE_ADD(datapath_drop_tunnel_pop_error,
                                 packets_dropped);
                }
                if (dp_packet_batch_is_empty(packets_)) {
                    return;
                }

                struct dp_packet *packet;
                DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                    packet->md.in_port.odp_port = portno;
                }

                (*depth)++;
                dp_netdev_recirculate(pmd, packets_);
                (*depth)--;
                return;
            }
            COVERAGE_ADD(datapath_drop_invalid_tnl_port,
                         dp_packet_batch_size(packets_));
        } else {
            COVERAGE_ADD(datapath_drop_recirc_error,
                         dp_packet_batch_size(packets_));
        }
        break;

    case OVS_ACTION_ATTR_USERSPACE:
        if (!fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
            struct dp_packet_batch *orig_packets_ = packets_;
            const struct nlattr *userdata;
            struct dp_packet_batch usr_pkt;
            struct ofpbuf actions;
            struct flow flow;
            ovs_u128 ufid;
            bool clone = false;

            userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);
            ofpbuf_init(&actions, 0);

            if (packets_->trunc) {
                if (!should_steal) {
                    dp_packet_batch_clone(&usr_pkt, packets_);
                    packets_ = &usr_pkt;
                    clone = true;
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                dp_packet_batch_apply_cutlen(packets_);
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                flow_extract(packet, &flow);
                odp_flow_key_hash(&flow, sizeof flow, &ufid);
                dp_execute_userspace_action(pmd, packet, should_steal, &flow,
                                            &ufid, &actions, userdata);
            }

            if (clone) {
                dp_packet_delete_batch(packets_, true);
            }

            ofpbuf_uninit(&actions);
            fat_rwlock_unlock(&dp->upcall_rwlock);

            return;
        }
        COVERAGE_ADD(datapath_drop_lock_error,
                     dp_packet_batch_size(packets_));
        break;

    case OVS_ACTION_ATTR_RECIRC:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch recirc_pkts;

            if (!should_steal) {
               dp_packet_batch_clone(&recirc_pkts, packets_);
               packets_ = &recirc_pkts;
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                packet->md.recirc_id = nl_attr_get_u32(a);
            }

            (*depth)++;
            dp_netdev_recirculate(pmd, packets_);
            (*depth)--;

            return;
        }

        COVERAGE_ADD(datapath_drop_recirc_error,
                     dp_packet_batch_size(packets_));
        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
        break;

    case OVS_ACTION_ATTR_CT: {
        const struct nlattr *b;
        bool force = false;
        bool commit = false;
        unsigned int left;
        uint16_t zone = 0;
        uint32_t tp_id = 0;
        const char *helper = NULL;
        const uint32_t *setmark = NULL;
        const struct ovs_key_ct_labels *setlabel = NULL;
        struct nat_action_info_t nat_action_info;
        struct nat_action_info_t *nat_action_info_ref = NULL;
        bool nat_config = false;

        NL_ATTR_FOR_EACH_UNSAFE (b, left, nl_attr_get(a),
                                 nl_attr_get_size(a)) {
            enum ovs_ct_attr sub_type = nl_attr_type(b);

            switch(sub_type) {
            case OVS_CT_ATTR_FORCE_COMMIT:
                force = true;
                /* fall through. */
            case OVS_CT_ATTR_COMMIT:
                commit = true;
                break;
            case OVS_CT_ATTR_ZONE:
                zone = nl_attr_get_u16(b);
                break;
            case OVS_CT_ATTR_HELPER:
                helper = nl_attr_get_string(b);
                break;
            case OVS_CT_ATTR_MARK:
                setmark = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_LABELS:
                setlabel = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_EVENTMASK:
                /* Silently ignored, as userspace datapath does not generate
                 * netlink events. */
                break;
            case OVS_CT_ATTR_TIMEOUT:
                if (!str_to_uint(nl_attr_get_string(b), 10, &tp_id)) {
                    VLOG_WARN("Invalid Timeout Policy ID: %s.",
                              nl_attr_get_string(b));
                    tp_id = DEFAULT_TP_ID;
                }
                break;
            case OVS_CT_ATTR_NAT: {
                const struct nlattr *b_nest;
                unsigned int left_nest;
                bool ip_min_specified = false;
                bool proto_num_min_specified = false;
                bool ip_max_specified = false;
                bool proto_num_max_specified = false;
                memset(&nat_action_info, 0, sizeof nat_action_info);
                nat_action_info_ref = &nat_action_info;

                NL_NESTED_FOR_EACH_UNSAFE (b_nest, left_nest, b) {
                    enum ovs_nat_attr sub_type_nest = nl_attr_type(b_nest);

                    switch (sub_type_nest) {
                    case OVS_NAT_ATTR_SRC:
                    case OVS_NAT_ATTR_DST:
                        nat_config = true;
                        nat_action_info.nat_action |=
                            ((sub_type_nest == OVS_NAT_ATTR_SRC)
                                ? NAT_ACTION_SRC : NAT_ACTION_DST);
                        break;
                    case OVS_NAT_ATTR_IP_MIN:
                        memcpy(&nat_action_info.min_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));
                        ip_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_IP_MAX:
                        memcpy(&nat_action_info.max_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));
                        ip_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MIN:
                        nat_action_info.min_port =
                            nl_attr_get_u16(b_nest);
                        proto_num_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MAX:
                        nat_action_info.max_port =
                            nl_attr_get_u16(b_nest);
                        proto_num_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_RANDOM:
                        nat_action_info.nat_flags |= NAT_RANGE_RANDOM;
                        break;
                    case OVS_NAT_ATTR_PERSISTENT:
                        nat_action_info.nat_flags |= NAT_PERSISTENT;
                        break;
                    case OVS_NAT_ATTR_PROTO_HASH:
                        break;
                    case OVS_NAT_ATTR_UNSPEC:
                    case __OVS_NAT_ATTR_MAX:
                        OVS_NOT_REACHED();
                    }
                }

                if (ip_min_specified && !ip_max_specified) {
                    nat_action_info.max_addr = nat_action_info.min_addr;
                }
                if (proto_num_min_specified && !proto_num_max_specified) {
                    nat_action_info.max_port = nat_action_info.min_port;
                }
                if (proto_num_min_specified || proto_num_max_specified) {
                    if (nat_action_info.nat_action & NAT_ACTION_SRC) {
                        nat_action_info.nat_action |= NAT_ACTION_SRC_PORT;
                    } else if (nat_action_info.nat_action & NAT_ACTION_DST) {
                        nat_action_info.nat_action |= NAT_ACTION_DST_PORT;
                    }
                }
                break;
            }
            case OVS_CT_ATTR_UNSPEC:
            case __OVS_CT_ATTR_MAX:
                OVS_NOT_REACHED();
            }
        }

        /* We won't be able to function properly in this case, hence
         * complain loudly. */
        if (nat_config && !commit) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_WARN_RL(&rl, "NAT specified without commit.");
        }

        conntrack_execute(dp->conntrack, packets_, aux->flow->dl_type, force,
                          commit, zone, setmark, setlabel, helper,
                          nat_action_info_ref, pmd->ctx.now / 1000, tp_id);
        break;
    }

    case OVS_ACTION_ATTR_METER:
        dp_netdev_run_meter(pmd->dp, packets_, nl_attr_get_u32(a),
                            pmd->ctx.now / 1000);
        break;

    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_UNSPEC:
    case OVS_ACTION_ATTR_TRUNC:
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_PUSH_NSH:
    case OVS_ACTION_ATTR_POP_NSH:
    case OVS_ACTION_ATTR_CT_CLEAR:
    case OVS_ACTION_ATTR_CHECK_PKT_LEN:
    case OVS_ACTION_ATTR_DROP:
    case OVS_ACTION_ATTR_ADD_MPLS:
    case OVS_ACTION_ATTR_DEC_TTL:
    case OVS_ACTION_ATTR_PSAMPLE:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    dp_packet_delete_batch(packets_, should_steal);
}

/* 执行 action 的总入口 — 封装 odp_execute_actions 调用。
 * 将 PMD 和 flow 信息打包到 aux 结构中，传给 dp_execute_cb 回调。 */
static void
dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                          struct dp_packet_batch *packets,
                          bool should_steal, const struct flow *flow,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = { pmd, flow };

    odp_execute_actions(&aux, packets, should_steal, actions,
                        actions_len, dp_execute_cb);
}

/* =====================================================
 * 连接跟踪（Conntrack）dpif 接口实现。
 *
 * 这些函数将 dpif 层的 conntrack 操作委托给 conntrack 模块。
 * 包括：连接表 dump（遍历）、flush（清空）、
 * 最大连接数设置、TCP 序列号检查、zone 限制、
 * 超时策略管理、IP 分片（IPF）管理等。
 * ===================================================== */

/* conntrack dump 上下文，关联 conntrack 实例和 dp。 */
struct dp_netdev_ct_dump {
    struct ct_dpif_dump_state up;
    struct conntrack_dump dump;
    struct conntrack *ct;
    struct dp_netdev *dp;
};

/* 开始 conntrack 连接表 dump：分配 dump 上下文并初始化迭代器。 */
static int
dpif_netdev_ct_dump_start(struct dpif *dpif, struct ct_dpif_dump_state **dump_,
                          const uint16_t *pzone, int *ptot_bkts)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_ct_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->dp = dp;
    dump->ct = dp->conntrack;

    conntrack_dump_start(dp->conntrack, &dump->dump, pzone, ptot_bkts);

    *dump_ = &dump->up;

    return 0;
}

/* 获取下一条 conntrack 连接表条目。 */
static int
dpif_netdev_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_,
                         struct ct_dpif_entry *entry)
{
    struct dp_netdev_ct_dump *dump;

    INIT_CONTAINER(dump, dump_, up);

    return conntrack_dump_next(&dump->dump, entry);
}

/* 结束 conntrack dump 并释放资源。 */
static int
dpif_netdev_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_)
{
    struct dp_netdev_ct_dump *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = conntrack_dump_done(&dump->dump);

    free(dump);

    return err;
}

/* 开始 conntrack 期望（expectation）表 dump。 */
static int
dpif_netdev_ct_exp_dump_start(struct dpif *dpif,
                              struct ct_dpif_dump_state **dump_,
                              const uint16_t *pzone)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_ct_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->dp = dp;
    dump->ct = dp->conntrack;

    conntrack_exp_dump_start(dp->conntrack, &dump->dump, pzone);

    *dump_ = &dump->up;

    return 0;
}

/* 获取下一条 conntrack 期望表条目。 */
static int
dpif_netdev_ct_exp_dump_next(struct dpif *dpif OVS_UNUSED,
                             struct ct_dpif_dump_state *dump_,
                             struct ct_dpif_exp *entry)
{
    struct dp_netdev_ct_dump *dump;

    INIT_CONTAINER(dump, dump_, up);

    return conntrack_exp_dump_next(&dump->dump, entry);
}

/* 结束 conntrack 期望表 dump 并释放资源。 */
static int
dpif_netdev_ct_exp_dump_done(struct dpif *dpif OVS_UNUSED,
                             struct ct_dpif_dump_state *dump_)
{
    struct dp_netdev_ct_dump *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = conntrack_exp_dump_done(&dump->dump);

    free(dump);

    return err;
}

/* 清空 conntrack 表。可按 zone 过滤或按 tuple 精确删除。 */
static int
dpif_netdev_ct_flush(struct dpif *dpif, const uint16_t *zone,
                     const struct ct_dpif_tuple *tuple)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (tuple) {
        return conntrack_flush_tuple(dp->conntrack, tuple, zone ? *zone : 0);
    }
    return conntrack_flush(dp->conntrack, zone);
}

/* 设置 conntrack 最大连接数限制。 */
static int
dpif_netdev_ct_set_maxconns(struct dpif *dpif, uint32_t maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_maxconns(dp->conntrack, maxconns);
}

/* 查询 conntrack 最大连接数限制。 */
static int
dpif_netdev_ct_get_maxconns(struct dpif *dpif, uint32_t *maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_maxconns(dp->conntrack, maxconns);
}

/* 查询 conntrack 当前活跃连接数。 */
static int
dpif_netdev_ct_get_nconns(struct dpif *dpif, uint32_t *nconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_nconns(dp->conntrack, nconns);
}

/* 设置是否启用 TCP 序列号检查（安全性功能）。 */
static int
dpif_netdev_ct_set_tcp_seq_chk(struct dpif *dpif, bool enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_tcp_seq_chk(dp->conntrack, enabled);
}

/* 查询 TCP 序列号检查是否启用。 */
static int
dpif_netdev_ct_get_tcp_seq_chk(struct dpif *dpif, bool *enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    *enabled = conntrack_get_tcp_seq_chk(dp->conntrack);
    return 0;
}

/* 设置 conntrack 清扫间隔（毫秒），用于回收过期连接。 */
static int
dpif_netdev_ct_set_sweep_interval(struct dpif *dpif, uint32_t ms)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return conntrack_set_sweep_interval(dp->conntrack, ms);
}

/* 查询 conntrack 清扫间隔。 */
static int
dpif_netdev_ct_get_sweep_interval(struct dpif *dpif, uint32_t *ms)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    *ms = conntrack_get_sweep_interval(dp->conntrack);
    return 0;
}

/* 设置 conntrack zone 连接数限制。
 * 遍历 zone_limits 列表，逐个更新每个 zone 的上限。 */
static int
dpif_netdev_ct_set_limits(struct dpif *dpif,
                           const struct ovs_list *zone_limits)
{
    int err = 0;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    struct ct_dpif_zone_limit *zone_limit;
    LIST_FOR_EACH (zone_limit, node, zone_limits) {
        err = zone_limit_update(dp->conntrack, zone_limit->zone,
                                zone_limit->limit);
        if (err != 0) {
            break;
        }
    }
    return err;
}

/* 查询 conntrack zone 连接数限制。
 * 如果请求列表非空，查询指定 zone；否则返回所有已设限的 zone。 */
static int
dpif_netdev_ct_get_limits(struct dpif *dpif,
                           const struct ovs_list *zone_limits_request,
                           struct ovs_list *zone_limits_reply)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct conntrack_zone_info czl;

    if (!ovs_list_is_empty(zone_limits_request)) {
        struct ct_dpif_zone_limit *zone_limit;
        LIST_FOR_EACH (zone_limit, node, zone_limits_request) {
            czl = zone_limit_get(dp->conntrack, zone_limit->zone);
            if (czl.zone == zone_limit->zone || czl.zone == DEFAULT_ZONE) {
                ct_dpif_push_zone_limit(zone_limits_reply, zone_limit->zone,
                                        czl.limit,
                                        czl.count);
            } else {
                return EINVAL;
            }
        }
    } else {
        czl = zone_limit_get(dp->conntrack, DEFAULT_ZONE);
        if (czl.zone == DEFAULT_ZONE) {
            ct_dpif_push_zone_limit(zone_limits_reply, DEFAULT_ZONE,
                                    czl.limit, 0);
        }

        for (int z = MIN_ZONE; z <= MAX_ZONE; z++) {
            czl = zone_limit_get(dp->conntrack, z);
            if (czl.zone == z) {
                ct_dpif_push_zone_limit(zone_limits_reply, z, czl.limit,
                                        czl.count);
            }
        }
    }

    return 0;
}

/* 删除指定 zone 的连接数限制。 */
static int
dpif_netdev_ct_del_limits(struct dpif *dpif,
                           const struct ovs_list *zone_limits)
{
    int err = 0;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct ct_dpif_zone_limit *zone_limit;
    LIST_FOR_EACH (zone_limit, node, zone_limits) {
        err = zone_limit_delete(dp->conntrack, zone_limit->zone);
        if (err != 0) {
            break;
        }
    }

    return err;
}

/* 查询 conntrack 支持的特性标志（如 zero SNAT 支持）。 */
static int
dpif_netdev_ct_get_features(struct dpif *dpif OVS_UNUSED,
                            enum ct_features *features)
{
    if (features != NULL) {
        *features = CONNTRACK_F_ZERO_SNAT;
    }
    return 0;
}

/* 设置 conntrack 超时策略。 */
static int
dpif_netdev_ct_set_timeout_policy(struct dpif *dpif,
                                  const struct ct_dpif_timeout_policy *dpif_tp)
{
    struct timeout_policy tp;
    struct dp_netdev *dp;

    dp = get_dp_netdev(dpif);
    memcpy(&tp.policy, dpif_tp, sizeof tp.policy);
    return timeout_policy_update(dp->conntrack, &tp);
}

/* 查询指定 ID 的 conntrack 超时策略。 */
static int
dpif_netdev_ct_get_timeout_policy(struct dpif *dpif, uint32_t tp_id,
                                  struct ct_dpif_timeout_policy *dpif_tp)
{
    struct timeout_policy *tp;
    struct dp_netdev *dp;
    int err = 0;

    dp = get_dp_netdev(dpif);
    tp = timeout_policy_get(dp->conntrack, tp_id);
    if (!tp) {
        return ENOENT;
    }
    memcpy(dpif_tp, &tp->policy, sizeof tp->policy);
    return err;
}

/* 删除指定 ID 的 conntrack 超时策略。 */
static int
dpif_netdev_ct_del_timeout_policy(struct dpif *dpif,
                                  uint32_t tp_id)
{
    struct dp_netdev *dp;
    int err = 0;

    dp = get_dp_netdev(dpif);
    err = timeout_policy_delete(dp->conntrack, tp_id);
    return err;
}

/* 获取超时策略的名称（直接用 ID 的字符串表示）。 */
static int
dpif_netdev_ct_get_timeout_policy_name(struct dpif *dpif OVS_UNUSED,
                                       uint32_t tp_id,
                                       uint16_t dl_type OVS_UNUSED,
                                       uint8_t nw_proto OVS_UNUSED,
                                       char **tp_name, bool *is_generic)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "%"PRIu32, tp_id);
    *tp_name = ds_steal_cstr(&ds);
    *is_generic = true;
    return 0;
}

/* 启用/禁用 IP 分片重组（IPF）。v6=true 表示 IPv6，否则 IPv4。 */
static int
dpif_netdev_ipf_set_enabled(struct dpif *dpif, bool v6, bool enable)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_enabled(conntrack_ipf_ctx(dp->conntrack), v6, enable);
}

/* 设置 IP 分片的最小分片大小阈值。 */
static int
dpif_netdev_ipf_set_min_frag(struct dpif *dpif, bool v6, uint32_t min_frag)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_min_frag(conntrack_ipf_ctx(dp->conntrack), v6, min_frag);
}

/* 设置 IPF 允许缓存的最大分片数量。 */
static int
dpif_netdev_ipf_set_max_nfrags(struct dpif *dpif, uint32_t max_frags)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_max_nfrags(conntrack_ipf_ctx(dp->conntrack), max_frags);
}

/* 查询 IPF 的当前状态信息。 */
/* Adjust this function if 'dpif_ipf_status' and 'ipf_status' were to
 * diverge. */
static int
dpif_netdev_ipf_get_status(struct dpif *dpif,
                           struct dpif_ipf_status *dpif_ipf_status)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    ipf_get_status(conntrack_ipf_ctx(dp->conntrack),
                   (struct ipf_status *) dpif_ipf_status);
    return 0;
}

/* 开始 IPF 分片信息 dump。 */
static int
dpif_netdev_ipf_dump_start(struct dpif *dpif OVS_UNUSED,
                           struct ipf_dump_ctx **ipf_dump_ctx)
{
    return ipf_dump_start(ipf_dump_ctx);
}

/* 获取下一条 IPF 分片 dump 条目。 */
static int
dpif_netdev_ipf_dump_next(struct dpif *dpif, void *ipf_dump_ctx, char **dump)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_dump_next(conntrack_ipf_ctx(dp->conntrack), ipf_dump_ctx,
                         dump);
}

/* 结束 IPF 分片 dump。 */
static int
dpif_netdev_ipf_dump_done(struct dpif *dpif OVS_UNUSED, void *ipf_dump_ctx)
{
    return ipf_dump_done(ipf_dump_ctx);

}

/* 添加/更新 bond：设置哈希桶到成员端口的映射，并更新所有 PMD。 */
static int
dpif_netdev_bond_add(struct dpif *dpif, uint32_t bond_id,
                     odp_port_t *member_map)
{
    struct tx_bond *new_tx = xzalloc(sizeof *new_tx);
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    /* Prepare new bond mapping. */
    new_tx->bond_id = bond_id;
    for (int bucket = 0; bucket < BOND_BUCKETS; bucket++) {
        new_tx->member_buckets[bucket].member_id = member_map[bucket];
    }

    ovs_mutex_lock(&dp->bond_mutex);
    /* Check if bond already existed. */
    struct tx_bond *old_tx = tx_bond_lookup(&dp->tx_bonds, bond_id);
    if (old_tx) {
        cmap_replace(&dp->tx_bonds, &old_tx->node, &new_tx->node,
                     hash_bond_id(bond_id));
        ovsrcu_postpone(free, old_tx);
    } else {
        cmap_insert(&dp->tx_bonds, &new_tx->node, hash_bond_id(bond_id));
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    /* Update all PMDs with new bond mapping. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_add_bond_tx_to_pmd(pmd, new_tx, true);
    }
    return 0;
}

/* 删除 bond 并从所有 PMD 中移除。 */
static int
dpif_netdev_bond_del(struct dpif *dpif, uint32_t bond_id)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    struct tx_bond *tx;

    ovs_mutex_lock(&dp->bond_mutex);
    /* Check if bond existed. */
    tx = tx_bond_lookup(&dp->tx_bonds, bond_id);
    if (tx) {
        cmap_remove(&dp->tx_bonds, &tx->node, hash_bond_id(bond_id));
        ovsrcu_postpone(free, tx);
    } else {
        /* Bond is not present. */
        ovs_mutex_unlock(&dp->bond_mutex);
        return ENOENT;
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    /* Remove the bond map in all pmds. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_del_bond_tx_from_pmd(pmd, bond_id);
    }
    return 0;
}

/* 获取 bond 各桶的字节统计（汇总所有 PMD）。 */
static int
dpif_netdev_bond_stats_get(struct dpif *dpif, uint32_t bond_id,
                           uint64_t *n_bytes)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    if (!tx_bond_lookup(&dp->tx_bonds, bond_id)) {
        return ENOENT;
    }

    /* Search the bond in all PMDs. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct tx_bond *pmd_bond_entry
            = tx_bond_lookup(&pmd->tx_bonds, bond_id);

        if (!pmd_bond_entry) {
            continue;
        }

        /* Read bond stats. */
        for (int i = 0; i < BOND_BUCKETS; i++) {
            uint64_t pmd_n_bytes;

            atomic_read_relaxed(&pmd_bond_entry->member_buckets[i].n_bytes,
                                &pmd_n_bytes);
            n_bytes[i] += pmd_n_bytes;
        }
    }
    return 0;
}

/* dpif_netdev_class — netdev datapath 的虚函数表。
 * 将所有 dpif 接口函数注册到 "netdev" 类型的 datapath 类中。
 * 这是 OVS 用户空间数据路径的核心入口点集合。 */
const struct dpif_class dpif_netdev_class = {
    "netdev",
    true,                       /* cleanup_required */
    dpif_netdev_init,
    dpif_netdev_enumerate,
    dpif_netdev_port_open_type,
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,
    dpif_netdev_wait,
    dpif_netdev_get_stats,
    NULL,                      /* set_features */
    NULL,                      /* get_features */
    dpif_netdev_port_add,
    dpif_netdev_port_del,
    dpif_netdev_port_set_config,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,
    dpif_netdev_port_dump_next,
    dpif_netdev_port_dump_done,
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,
    dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_create,
    dpif_netdev_flow_dump_destroy,
    dpif_netdev_flow_dump_thread_create,
    dpif_netdev_flow_dump_thread_destroy,
    dpif_netdev_flow_dump_next,
    dpif_netdev_operate,
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */
    dpif_netdev_number_handlers_required,
    dpif_netdev_set_config,
    dpif_netdev_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_netdev_register_dp_purge_cb,
    dpif_netdev_register_upcall_cb,
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
    dpif_netdev_get_datapath_version,
    dpif_netdev_ct_dump_start,
    dpif_netdev_ct_dump_next,
    dpif_netdev_ct_dump_done,
    dpif_netdev_ct_exp_dump_start,
    dpif_netdev_ct_exp_dump_next,
    dpif_netdev_ct_exp_dump_done,
    dpif_netdev_ct_flush,
    dpif_netdev_ct_set_maxconns,
    dpif_netdev_ct_get_maxconns,
    dpif_netdev_ct_get_nconns,
    dpif_netdev_ct_set_tcp_seq_chk,
    dpif_netdev_ct_get_tcp_seq_chk,
    dpif_netdev_ct_set_sweep_interval,
    dpif_netdev_ct_get_sweep_interval,
    dpif_netdev_ct_set_limits,
    dpif_netdev_ct_get_limits,
    dpif_netdev_ct_del_limits,
    dpif_netdev_ct_set_timeout_policy,
    dpif_netdev_ct_get_timeout_policy,
    dpif_netdev_ct_del_timeout_policy,
    NULL,                       /* ct_timeout_policy_dump_start */
    NULL,                       /* ct_timeout_policy_dump_next */
    NULL,                       /* ct_timeout_policy_dump_done */
    dpif_netdev_ct_get_timeout_policy_name,
    dpif_netdev_ct_get_features,
    dpif_netdev_ipf_set_enabled,
    dpif_netdev_ipf_set_min_frag,
    dpif_netdev_ipf_set_max_nfrags,
    dpif_netdev_ipf_get_status,
    dpif_netdev_ipf_dump_start,
    dpif_netdev_ipf_dump_next,
    dpif_netdev_ipf_dump_done,
    dpif_netdev_meter_get_features,
    dpif_netdev_meter_set,
    dpif_netdev_meter_get,
    dpif_netdev_meter_del,
    dpif_netdev_bond_add,
    dpif_netdev_bond_del,
    dpif_netdev_bond_stats_get,
    NULL,                       /* cache_get_supported_levels */
    NULL,                       /* cache_get_name */
    NULL,                       /* cache_get_size */
    NULL,                       /* cache_set_size */
};

/* =====================================================
 * Dummy dpif — 测试用的虚拟数据路径。
 *
 * 用于 OVS 单元测试（testsuite）。注册一个名为 "dummy" 的 dpif 类型，
 * 其实现与 netdev datapath 相同，但允许在测试中模拟端口变更等操作。
 * dpif_dummy_override() 可以替换真实的 "system" 类型用于测试。
 * ===================================================== */

/* 测试命令：更改 dummy datapath 中端口的端口号。 */
static void
dpif_dummy_change_port_number(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    odp_port_t port_no;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }
    ovs_refcount_ref(&dp->ref_cnt);
    ovs_mutex_unlock(&dp_netdev_mutex);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        goto exit;
    }

    port_no = u32_to_odp(atoi(argv[3]));
    if (!port_no || port_no == ODPP_NONE) {
        unixctl_command_reply_error(conn, "bad port number");
        goto exit;
    }
    if (dp_netdev_lookup_port(dp, port_no)) {
        unixctl_command_reply_error(conn, "port number already in use");
        goto exit;
    }

    /* Remove port. */
    hmap_remove(&dp->ports, &port->node);
    reconfigure_datapath(dp);

    /* Reinsert with new port number. */
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    reconfigure_datapath(dp);

    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
    ovs_rwlock_unlock(&dp->port_rwlock);
    dp_netdev_unref(dp);
}

/* 注册一个新的 dummy dpif 类型（复制 dpif_netdev_class 并改名）。 */
static void
dpif_dummy_register__(const char *type)
{
    struct dpif_class *class;

    class = xmalloc(sizeof *class);
    *class = dpif_netdev_class;
    class->type = xstrdup(type);
    dp_register_provider(class);
}

/* 用 dummy 实现替换已注册的 dpif 类型（如 "system"）。
 * 先注销原类型，再注册同名的 dummy 版本。 */
static void
dpif_dummy_override(const char *type)
{
    int error;

    /*
     * Ignore EAFNOSUPPORT to allow --enable-dummy=system with
     * a userland-only build.  It's useful for testsuite.
     */
    error = dp_unregister_provider(type);
    if (error == 0 || error == EAFNOSUPPORT) {
        dpif_dummy_register__(type);
    }
}

/* 注册 dummy dpif 类型和相关测试命令。
 * DUMMY_OVERRIDE_ALL：替换所有已注册的 dpif 类型
 * DUMMY_OVERRIDE_SYSTEM：只替换 "system" 类型
 * 总是额外注册一个名为 "dummy" 的类型。 */
void
dpif_dummy_register(enum dummy_level level)
{
    if (level == DUMMY_OVERRIDE_ALL) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            dpif_dummy_override(type);
        }
        sset_destroy(&types);
    } else if (level == DUMMY_OVERRIDE_SYSTEM) {
        dpif_dummy_override("system");
    }

    dpif_dummy_register__("dummy");

    unixctl_command_register("dpif-dummy/change-port-number",
                             "dp port new-number",
                             3, 3, dpif_dummy_change_port_number, NULL);
}

/* =====================================================
 * Datapath Classifier (dpcls) — 数据路径通配符分类器实现。
 *
 * dpcls 是 OVS-DPDK 流表查找的第三级（最后一级）：
 *   EMC（精确匹配缓存）→ SMC（签名匹配缓存）→ dpcls（通配符分类器）
 *
 * 结构：每个入端口一个 dpcls，内含多个子表（subtable）。
 * 每个子表对应一种 mask 模式（即哪些字段参与匹配）。
 * 查找时按 pvector 优先级依次遍历子表，命中率高的子表排在前面。
 *
 * 子表查找使用 SIMD 优化的批量查找函数（如 AVX512），
 * 通过 miniflow 的 mask 操作快速匹配。
 * ===================================================== */

/* RCU 延迟释放子表的回调。 */
static void
dpcls_subtable_destroy_cb(struct dpcls_subtable *subtable)
{
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable->mf_masks);
    ovsrcu_postpone(free, subtable);
}

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
/* 初始化分类器：创建子表映射和优先级向量。 */
static void
dpcls_init(struct dpcls *cls)
{
    cmap_init(&cls->subtables_map);
    pvector_init(&cls->subtables);
}

/* 销毁指定子表：从优先级向量和 cmap 中移除，通过 RCU 延迟释放。 */
static void
dpcls_destroy_subtable(struct dpcls *cls, struct dpcls_subtable *subtable)
{
    VLOG_DBG("Destroying subtable %p for in_port %d", subtable, cls->in_port);
    pvector_remove(&cls->subtables, subtable);
    cmap_remove(&cls->subtables_map, &subtable->cmap_node,
                subtable->mask.hash);
    dpcls_info_dec_usage(subtable->lookup_func_info);
    ovsrcu_postpone(dpcls_subtable_destroy_cb, subtable);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility.
 * May only be called after all the readers have been terminated. */
/* 销毁整个分类器：遍历并销毁所有子表，释放 cmap 和 pvector。
 * 注意：子表中的 rule 不在此释放，由调用者负责。 */
static void
dpcls_destroy(struct dpcls *cls)
{
    if (cls) {
        struct dpcls_subtable *subtable;

        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
            ovs_assert(cmap_count(&subtable->rules) == 0);
            dpcls_destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);
        pvector_destroy(&cls->subtables);
    }
}

/* 创建新子表：
 * 1) 分配内存，初始化 rule 的 cmap
 * 2) 根据 mask 的位图计算 unit0/unit1 的位数，预生成 mask 数组
 * 3) 选择最优的子表查找函数（可能是 SIMD 优化版本）
 * 4) 插入 cmap 和 pvector（初始优先级为0，之后按命中率排序） */
static struct dpcls_subtable *
dpcls_create_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    /* Need to add one. */
    subtable = xmalloc(sizeof *subtable
                       - sizeof subtable->mask.mf + mask->len);
    cmap_init(&subtable->rules);
    subtable->hit_cnt = 0;
    netdev_flow_key_clone(&subtable->mask, mask);

    /* The count of bits in the mask defines the space required for masks.
     * Then call gen_masks() to create the appropriate masks, avoiding the cost
     * of doing runtime calculations. */
    uint32_t unit0 = count_1bits(mask->mf.map.bits[0]);
    uint32_t unit1 = count_1bits(mask->mf.map.bits[1]);
    subtable->mf_bits_set_unit0 = unit0;
    subtable->mf_bits_set_unit1 = unit1;
    subtable->mf_masks = xmalloc(sizeof(uint64_t) * (unit0 + unit1));
    dpcls_flow_key_gen_masks(mask, subtable->mf_masks, unit0, unit1);

    /* Get the preferred subtable search function for this (u0,u1) subtable.
     * The function is guaranteed to always return a valid implementation, and
     * possibly an ISA optimized, and/or specialized implementation. Initialize
     * the subtable search function atomically to avoid garbage data being read
     * by the PMD thread.
     */
    atomic_init(&subtable->lookup_func,
                dpcls_subtable_get_best_impl(unit0, unit1,
                                             &subtable->lookup_func_info));
    dpcls_info_inc_usage(subtable->lookup_func_info);

    cmap_insert(&cls->subtables_map, &subtable->cmap_node, mask->hash);
    /* Add the new subtable at the end of the pvector (with no hits yet) */
    pvector_insert(&cls->subtables, subtable, 0);
    VLOG_DBG("Creating %"PRIuSIZE". subtable %p for in_port %d",
             cmap_count(&cls->subtables_map), subtable, cls->in_port);
    pvector_publish(&cls->subtables);

    return subtable;
}

/* 按 mask 查找子表，不存在时自动创建新子表。 */
static inline struct dpcls_subtable *
dpcls_find_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    CMAP_FOR_EACH_WITH_HASH (subtable, cmap_node, mask->hash,
                             &cls->subtables_map) {
        if (netdev_flow_key_equal(&subtable->mask, mask)) {
            return subtable;
        }
    }
    return dpcls_create_subtable(cls, mask);
}

/* Checks for the best available implementation for each subtable lookup
 * function, and assigns it as the lookup function pointer for each subtable.
 * Returns the number of subtables that have changed lookup implementation.
 * This function requires holding a flow_mutex when called. This is to make
 * sure modifications done by this function are not overwritten. This could
 * happen if dpcls_sort_subtable_vector() is called at the same time as this
 * function.
 */
/* 重新探测所有子表的最优查找实现：
 * 当用户通过 appctl 切换查找算法（如从 generic 切换到 avx512）时调用。
 * 遍历每个子表，根据其 (unit0, unit1) 位数重新选择最佳查找函数。
 * 返回实际发生了实现变更的子表数量。 */
static uint32_t
dpcls_subtable_lookup_reprobe(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    uint32_t subtables_changed = 0;
    struct dpcls_subtable *subtable = NULL;

    PVECTOR_FOR_EACH (subtable, pvec) {
        uint32_t u0_bits = subtable->mf_bits_set_unit0;
        uint32_t u1_bits = subtable->mf_bits_set_unit1;
        void *old_func = subtable->lookup_func;
        struct dpcls_subtable_lookup_info_t *old_info;
        old_info = subtable->lookup_func_info;
        /* Set the subtable lookup function atomically to avoid garbage data
         * being read by the PMD thread. */
        atomic_store_relaxed(&subtable->lookup_func,
                dpcls_subtable_get_best_impl(u0_bits, u1_bits,
                                             &subtable->lookup_func_info));
        if (old_func != subtable->lookup_func) {
            subtables_changed += 1;
        }

        if (old_info != subtable->lookup_func_info) {
            /* In theory, functions can be shared between implementations, so
             * do an explicit check on the function info structures. */
            dpcls_info_dec_usage(old_info);
            dpcls_info_inc_usage(subtable->lookup_func_info);
        }
    }

    return subtables_changed;
}

/* Periodically sort the dpcls subtable vectors according to hit counts */
/* 按命中次数对子表排序：命中多的子表优先级更高，下次查找时会先被检查。
 * 排序后重置 hit_cnt 计数器，开始新一轮统计。 */
static void
dpcls_sort_subtable_vector(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    struct dpcls_subtable *subtable;

    PVECTOR_FOR_EACH (subtable, pvec) {
        pvector_change_priority(pvec, subtable, subtable->hit_cnt);
        subtable->hit_cnt = 0;
    }
    pvector_publish(pvec);
}

/* PMD 周期性优化函数，在 PMD 主循环中每 1024 次迭代调用一次。
 *
 * 两个独立的定时任务：
 * ┌──────────────────────────────────────────────────────────┐
 * │ 任务 1：周期统计（PMD_INTERVAL_LEN 间隔）                 │
 * │  - 计算 idle/busy/sleep 周期差值 → PMD 负载率             │
 * │  - 负载率超阈值 → 标记过载 → 触发自动负载均衡（auto-lb）   │
 * │  - 采集每个 RXQ 的处理周期 → 用于 RXQ 重分配决策           │
 * │  - 记录忙碌周期到环形缓冲 → 用于控制线程读取负载           │
 * ├──────────────────────────────────────────────────────────┤
 * │ 任务 2：子表排序（DPCLS_OPTIMIZATION_INTERVAL 间隔）      │
 * │  - 对所有 dpcls 分类器的子表按命中率排序                   │
 * │  - 命中率高的子表排到前面 → 减少平均查找次数               │
 * └──────────────────────────────────────────────────────────┘ */
static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt)
{
    struct dpcls *cls;
    uint64_t tot_idle = 0, tot_proc = 0, tot_sleep = 0;
    unsigned int pmd_load = 0;

    /* === 任务 1：周期统计（每 PMD_INTERVAL_LEN 纳秒执行一次）=== */
    if (pmd->ctx.now > pmd->next_cycle_store) {
        uint64_t curr_tsc;
        uint8_t rebalance_load_trigger;
        struct pmd_auto_lb *pmd_alb = &pmd->dp->pmd_alb;
        unsigned int idx;

        /* 计算本周期内的 idle/busy/sleep 增量。
         * 需要检查计数器未被外部清零（>= prev 判断），否则跳过。 */
        if (pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] >=
                pmd->prev_stats[PMD_CYCLES_ITER_IDLE] &&
            pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] >=
                pmd->prev_stats[PMD_CYCLES_ITER_BUSY]) {
            /* 增量 = 当前累计 - 上次记录值 */
            tot_idle = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] -
                       pmd->prev_stats[PMD_CYCLES_ITER_IDLE];
            tot_proc = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] -
                       pmd->prev_stats[PMD_CYCLES_ITER_BUSY];
            tot_sleep = pmd->perf_stats.counters.n[PMD_CYCLES_SLEEP] -
                        pmd->prev_stats[PMD_CYCLES_SLEEP];

            /* 自动负载均衡（auto-lb）：仅对非隔离的 PMD 生效 */
            if (pmd_alb->is_enabled && !pmd->isolated) {
                if (tot_proc) {
                    /* 负载率 = busy / (idle + busy + sleep) × 100% */
                    pmd_load = ((tot_proc * 100) /
                                    (tot_idle + tot_proc + tot_sleep));
                }

                /* 读取过载阈值（由 other_config:pmd-auto-lb-load-threshold 配置） */
                atomic_read_relaxed(&pmd_alb->rebalance_load_thresh,
                                    &rebalance_load_trigger);
                if (pmd_load >= rebalance_load_trigger) {
                    /* 超过阈值：递增过载计数（连续超标才会触发重均衡） */
                    atomic_count_inc(&pmd->pmd_overloaded);
                } else {
                    /* 负载恢复正常：重置过载计数 */
                    atomic_count_set(&pmd->pmd_overloaded, 0);
                }
            }
        }

        /* 保存当前计数器值作为下次计算增量的基准 */
        pmd->prev_stats[PMD_CYCLES_ITER_IDLE] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE];
        pmd->prev_stats[PMD_CYCLES_ITER_BUSY] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY];
        pmd->prev_stats[PMD_CYCLES_SLEEP] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_SLEEP];

        /* 采集每个 RXQ 在本周期内的处理周期数，
         * 存入 RXQ 的间隔环形缓冲（用于 roundrobin/cycles 调度策略），
         * 然后重置当前计数器为 0 开始下一周期。 */
        for (unsigned i = 0; i < poll_cnt; i++) {
            uint64_t rxq_cyc_curr = dp_netdev_rxq_get_cycles(poll_list[i].rxq,
                                                        RXQ_CYCLES_PROC_CURR);
            dp_netdev_rxq_set_intrvl_cycles(poll_list[i].rxq, rxq_cyc_curr);
            dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR,
                                     0);
        }

        /* 记录当前 TSC，计算本周期的总 TSC 差值（idle+busy+sleep 的总时间） */
        curr_tsc = cycles_counter_update(&pmd->perf_stats);
        if (pmd->intrvl_tsc_prev) {
            /* 存储总间隔周期，供控制线程计算此 PMD 的总体利用率 */
            atomic_store_relaxed(&pmd->intrvl_cycles,
                                 curr_tsc - pmd->intrvl_tsc_prev);
        }
        /* 将本周期的 busy 周期数存入环形缓冲（PMD_INTERVAL_MAX 个槽位） */
        idx = atomic_count_inc(&pmd->intrvl_idx) % PMD_INTERVAL_MAX;
        atomic_store_relaxed(&pmd->busy_cycles_intrvl[idx], tot_proc);
        pmd->intrvl_tsc_prev = curr_tsc;
        /* 设置下一次周期统计的触发时间 */
        pmd->next_cycle_store = pmd->ctx.now + PMD_INTERVAL_LEN;
    }

    /* === 任务 2：dpcls 子表排序（每 DPCLS_OPTIMIZATION_INTERVAL 纳秒一次）=== */
    if (pmd->ctx.now > pmd->next_optimization) {
        /* 尝试获取 flow_mutex，避免与 revalidator 线程冲突。
         * 使用 trylock 而非阻塞锁 — 获取不到就下次再来，
         * 不能在 PMD 热路径上阻塞。 */
        if (!ovs_mutex_trylock(&pmd->flow_mutex)) {
            /* 遍历所有分类器（每个入端口一个），
             * 按子表的累计命中次数重新排列 pvector 优先级 */
            CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
                dpcls_sort_subtable_vector(cls);
            }
            ovs_mutex_unlock(&pmd->flow_mutex);
            /* 设置下一次子表排序的触发时间 */
            pmd->next_optimization = pmd->ctx.now
                                     + DPCLS_OPTIMIZATION_INTERVAL;
        }
    }
}

/* Returns the sum of a specified number of newest to
 * oldest interval values. 'cur_idx' is where the next
 * write will be and wrap around needs to be handled.
 */
/* 从环形缓冲区中读取最近 num_to_read 个区间值并求和。
 * 用于计算 RXQ 的平均处理周期数，支持负载均衡决策。 */
static uint64_t
get_interval_values(atomic_ullong *source, atomic_count *cur_idx,
                    int num_to_read) {
    unsigned int i;
    uint64_t total = 0;

    i = atomic_count_get(cur_idx) % PMD_INTERVAL_MAX;
    for (int read = 0; read < num_to_read; read++) {
        uint64_t interval_value;

        i = i ? i - 1 : PMD_INTERVAL_MAX - 1;
        atomic_read_relaxed(&source[i], &interval_value);
        total += interval_value;
    }
    return total;
}

/* Insert 'rule' into 'cls'. */
/* 向分类器插入规则：找到（或创建）对应 mask 的子表，将规则插入子表的 cmap。 */
static void
dpcls_insert(struct dpcls *cls, struct dpcls_rule *rule,
             const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable = dpcls_find_subtable(cls, mask);

    /* Refer to subtable's mask, also for later removal. */
    rule->mask = &subtable->mask;
    cmap_insert(&subtable->rules, &rule->cmap_node, rule->flow.hash);
}

/* Removes 'rule' from 'cls', also destructing the 'rule'. */
/* 从分类器删除规则：从子表 cmap 中移除，若子表变空则销毁该子表。 */
static void
dpcls_remove(struct dpcls *cls, struct dpcls_rule *rule)
{
    struct dpcls_subtable *subtable;

    ovs_assert(rule->mask);

    /* Get subtable from reference in rule->mask. */
    INIT_CONTAINER(subtable, rule->mask, mask);
    if (cmap_remove(&subtable->rules, &rule->cmap_node, rule->flow.hash)
        == 0) {
        /* Delete empty subtable. */
        dpcls_destroy_subtable(cls, subtable);
        pvector_publish(&cls->subtables);
    }
}

/* Inner loop for mask generation of a unit, see dpcls_flow_key_gen_masks. */
/* 为单个 unit（miniflow 的前半或后半）生成 mask 数组。
 * 利用位操作逐个提取 iter 中的最低位，生成前缀掩码（lowest_bit - 1）。
 * 这样在查找时可以直接用预计算的 mask 做与操作，避免运行时计算。 */
static inline void
dpcls_flow_key_gen_mask_unit(uint64_t iter, const uint64_t count,
                             uint64_t *mf_masks)
{
    int i;
    for (i = 0; i < count; i++) {
        uint64_t lowest_bit = (iter & -iter);
        iter &= ~lowest_bit;
        mf_masks[i] = (lowest_bit - 1);
    }
    /* Checks that count has covered all bits in the iter bitmap. */
    ovs_assert(iter == 0);
}

/* Generate a mask for each block in the miniflow, based on the bits set. This
 * allows easily masking packets with the generated array here, without
 * calculations. This replaces runtime-calculating the masks.
 * @param key The table to generate the mf_masks for
 * @param mf_masks Pointer to a u64 array of at least *mf_bits* in size
 * @param mf_bits_total Number of bits set in the whole miniflow (both units)
 * @param mf_bits_unit0 Number of bits set in unit0 of the miniflow
 */
/* 为子表的 mask 生成预计算掩码数组，分别处理 unit0 和 unit1。
 * 生成的 mf_masks 数组在子表查找时直接使用，避免运行时位操作开销。 */
void
dpcls_flow_key_gen_masks(const struct netdev_flow_key *tbl,
                         uint64_t *mf_masks,
                         const uint32_t mf_bits_u0,
                         const uint32_t mf_bits_u1)
{
    uint64_t iter_u0 = tbl->mf.map.bits[0];
    uint64_t iter_u1 = tbl->mf.map.bits[1];

    dpcls_flow_key_gen_mask_unit(iter_u0, mf_bits_u0, &mf_masks[0]);
    dpcls_flow_key_gen_mask_unit(iter_u1, mf_bits_u1, &mf_masks[mf_bits_u0]);
}

/* Returns true if 'target' satisfies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same. */
/* 逐字段检查报文 key 是否匹配规则：(target & mask) == key。
 * 这是 generic 查找路径的核心匹配函数。 */
inline bool
dpcls_rule_matches_key(const struct dpcls_rule *rule,
                       const struct netdev_flow_key *target)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    uint64_t value;

    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, target, rule->flow.mf.map) {
        if (OVS_UNLIKELY((value & *maskp++) != *keyp++)) {
            return false;
        }
    }
    return true;
}

/* For each miniflow in 'keys' performs a classifier lookup writing the result
 * into the corresponding slot in 'rules'.  If a particular entry in 'keys' is
 * NULL it is skipped.
 *
 * This function is optimized for use in the userspace datapath and therefore
 * does not implement a lot of features available in the standard
 * classifier_lookup() function.  Specifically, it does not implement
 * priorities, instead returning any rule which matches the flow.
 *
 * Returns true if all miniflows found a corresponding rule. */
/* dpcls 批量查找核心函数：
 * 对一批报文（最多 NETDEV_MAX_BURST 个）同时进行子表查找。
 *
 * 算法流程：
 * 1) 用位图 keys_map 跟踪尚未匹配的报文
 * 2) 按优先级遍历子表（pvector），调用子表的批量查找函数
 * 3) 每找到匹配就从 keys_map 中清除对应位
 * 4) 所有报文都匹配后提前返回 true；遍历完仍有未匹配则返回 false
 *
 * 同时统计 lookups_match（加权查找深度），用于子表排序优化。 */
bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key *keys[],
             struct dpcls_rule **rules, const size_t cnt,
             int *num_lookups_p)
{
    /* The received 'cnt' miniflows are the search-keys that will be processed
     * to find a matching entry into the available subtables.
     * The number of bits in map_type is equal to NETDEV_MAX_BURST. */
#define MAP_BITS (sizeof(uint32_t) * CHAR_BIT)
    BUILD_ASSERT_DECL(MAP_BITS >= NETDEV_MAX_BURST);

    struct dpcls_subtable *subtable;
    uint32_t keys_map = TYPE_MAXIMUM(uint32_t); /* Set all bits. */

    if (cnt != MAP_BITS) {
        keys_map >>= MAP_BITS - cnt; /* Clear extra bits. */
    }
    memset(rules, 0, cnt * sizeof *rules);

    int lookups_match = 0, subtable_pos = 1;
    uint32_t found_map;

    /* The Datapath classifier - aka dpcls - is composed of subtables.
     * Subtables are dynamically created as needed when new rules are inserted.
     * Each subtable collects rules with matches on a specific subset of packet
     * fields as defined by the subtable's mask.  We proceed to process every
     * search-key against each subtable, but when a match is found for a
     * search-key, the search for that key can stop because the rules are
     * non-overlapping. */
    PVECTOR_FOR_EACH (subtable, &cls->subtables) {
        /* Call the subtable specific lookup function. */
        found_map = subtable->lookup_func(subtable, keys_map, keys, rules);

        /* Count the number of subtables searched for this packet match. This
         * estimates the "spread" of subtables looked at per matched packet. */
        uint32_t pkts_matched = count_1bits(found_map);
        lookups_match += pkts_matched * subtable_pos;

        /* Clear the found rules, and return early if all packets are found. */
        keys_map &= ~found_map;
        if (!keys_map) {
            if (num_lookups_p) {
                *num_lookups_p = lookups_match;
            }
            return true;
        }
        subtable_pos++;
    }

    if (num_lookups_p) {
        *num_lookups_p = lookups_match;
    }
    return false;
}
