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

#ifndef DPIF_NETDEV_PRIVATE_THREAD_H
#define DPIF_NETDEV_PRIVATE_THREAD_H 1

#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-netdev-private-dfc.h"
#include "dpif-netdev-private-dpif.h"

#include <stdbool.h>
#include <stdint.h>

#include "ccmap.h"
#include "cmap.h"

#include "dpif-netdev-private-dfc.h"
#include "dpif-netdev-private-dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-netdev-private-extract.h"
#include "openvswitch/thread.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* PMD Thread Structures */

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */
struct dp_netdev_pmd_thread_ctx {
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;
    /* EMC insertion probability context for the current processing cycle. */
    uint32_t emc_insert_min;
    /* Enable the SMC cache from ovsdb config. */
    bool smc_enable_db;
};

/* @veencn_260223: Per-stage latency statistics for datapath profiling.
 * Only written by the owning PMD thread; may be read from any thread. */

#define LATENCY_HIST_BUCKETS 7
/* Histogram bucket boundaries (nanoseconds):
 * [0] <100ns  [1] 100-200ns  [2] 200-500ns  [3] 500ns-1us
 * [4] 1-10us  [5] 10-100us   [6] >=100us */

struct latency_stage_stats {
    uint64_t count;
    uint64_t total_cycles;
    uint64_t min_cycles;        /* Init to UINT64_MAX. */
    uint64_t max_cycles;
    uint64_t histogram[LATENCY_HIST_BUCKETS];
};

struct pmd_latency_stats {
    bool enabled;

    /* Per-stage latency. */
    struct latency_stage_stats phwol_lookup;   /* PHWOL hw offload */
    struct latency_stage_stats simple_match;   /* simple match */
    struct latency_stage_stats miniflow;       /* miniflow extract */
    struct latency_stage_stats emc_lookup;     /* EMC hit lookup */
    struct latency_stage_stats smc_lookup;     /* SMC hit lookup */
    struct latency_stage_stats dpcls_lookup;   /* megaflow lookup */
    struct latency_stage_stats upcall;         /* upcall slow path */
    struct latency_stage_stats conntrack;      /* conntrack execution */
    struct latency_stage_stats tnl_push;       /* tunnel push */
    struct latency_stage_stats tnl_pop;        /* tunnel pop */
    struct latency_stage_stats action_exec;    /* action execution */
    struct latency_stage_stats total;          /* rx to action done */

    /* Hit path counters. */
    uint64_t phwol_hit_count;
    uint64_t simple_hit_count;
    uint64_t emc_hit_count;
    uint64_t smc_hit_count;
    uint64_t dpcls_hit_count;
    uint64_t upcall_count;
    uint64_t conntrack_count;
    uint64_t recirc_count;
};
/* @veencn_260223 end */

/* @veencn: Per-packet trace — 记录单包经过各处理阶段的 TSC 时间戳。
 * 仅 owning PMD 线程写入；appctl 回调线程读取，不加锁。 */

enum pkt_trace_stage {
    TRACE_RX = 0,        /* 收包入口 */
    TRACE_PHWOL,         /* PHWOL 硬件卸载命中 */
    TRACE_SIMPLE_MATCH,  /* Simple Match 快路径命中 */
    TRACE_MINIFLOW,      /* miniflow_extract 完成 */
    TRACE_EMC,           /* EMC 命中 */
    TRACE_SMC,           /* SMC 命中 */
    TRACE_DPCLS,         /* dpcls 命中 */
    TRACE_UPCALL,        /* upcall 完成 */
    TRACE_CONNTRACK,     /* conntrack 执行完成 */
    TRACE_TNL_PUSH,      /* tunnel push 完成 */
    TRACE_TNL_POP,       /* tunnel pop 完成 */
    TRACE_ACTION,        /* action 执行完成 */
    TRACE_RECIRC,        /* recirculation 入口 */
    TRACE_TX,            /* 发包出口 */
    TRACE_N_STAGES
};

#define PKT_TRACE_RING_SIZE 64

struct pkt_trace_entry {
    bool valid;                    /* 此条目是否有效 */
    /* 包标识信息 */
    struct eth_addr dl_src;
    struct eth_addr dl_dst;
    ovs_be16 dl_type;
    ovs_be32 nw_src;
    ovs_be32 nw_dst;
    uint8_t nw_proto;
    uint8_t nw_ttl;
    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    odp_port_t in_port;
    odp_port_t out_port;           /* TX 时记录 */
    uint32_t recirc_id;            /* recirculation ID（0=首次） */
    /* 各阶段 TSC 时间戳（0 = 未经过该阶段） */
    uint64_t ts[TRACE_N_STAGES];
};

struct pkt_trace_state {
    bool enabled;
    uint32_t write_idx;            /* 下一个写入位置（环形） */
    uint32_t total_traced;         /* 累计追踪的包数 */
    struct pkt_trace_entry ring[PKT_TRACE_RING_SIZE];
};
/* @veencn end: per-packet trace */

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * Each struct has its own flow cache and classifier per managed ingress port.
 * For packets received on ingress port, a look up is done on corresponding PMD
 * thread's flow cache and in case of a miss, lookup is performed in the
 * corresponding classifier of port.  Packets are executed with the found
 * actions in either case.
 * */
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */

    /* Per thread exact match cache and signature match cache.  Note, the
     * instance for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct dfc_cache flow_cache;

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table'/'simple_match_table' and their n* ccmap's must
     * take the 'flow_mutex'.  Corresponding changes to 'classifiers' must be
     * made while still holding the 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct cmap flow_table; /* Flow table. */
    struct cmap simple_match_table; /* Flow table with simple
                                     * match flows only. */
    /* Number of flows in the 'flow_table' per in_port. */
    struct ccmap n_flows;
    /* Number of flows in the 'simple_match_table' per in_port. */
    struct ccmap n_simple_flows;

    /* One classifier per in_port polled by the pmd */
    struct cmap classifiers;
    /* Periodically sort subtable vectors according to hit frequencies */
    long long int next_optimization;
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;

    /* Write index for 'busy_cycles_intrvl'. */
    atomic_count intrvl_idx;
    /* Busy cycles in last PMD_INTERVAL_MAX intervals. */
    atomic_ullong *busy_cycles_intrvl;

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;

    /* Function pointer to call for dp_netdev_input() functionality. */
    ATOMIC(dp_netdev_input_func) netdev_input_func;

    /* Pointer for per-DPIF implementation scratch space. */
    void *netdev_input_func_userdata;

    /* Function pointer to call for miniflow_extract() functionality. */
    ATOMIC(miniflow_extract_func) miniflow_extract_opt;

    struct seq *reload_seq;
    uint64_t last_reload_seq;

    /* These are atomic variables used as a synchronization and configuration
     * points for thread reload/exit.
     *
     * 'reload' atomic is the main one and it's used as a memory
     * synchronization point for all other knobs and data.
     *
     * For a thread that requests PMD reload:
     *
     *   * All changes that should be visible to the PMD thread must be made
     *     before setting the 'reload'.  These changes could use any memory
     *     ordering model including 'relaxed'.
     *   * Setting the 'reload' atomic should occur in the same thread where
     *     all other PMD configuration options updated.
     *   * Setting the 'reload' atomic should be done with 'release' memory
     *     ordering model or stricter.  This will guarantee that all previous
     *     changes (including non-atomic and 'relaxed') will be visible to
     *     the PMD thread.
     *   * To check that reload is done, thread should poll the 'reload' atomic
     *     to become 'false'.  Polling should be done with 'acquire' memory
     *     ordering model or stricter.  This ensures that PMD thread completed
     *     the reload process.
     *
     * For the PMD thread:
     *
     *   * PMD thread should read 'reload' atomic with 'acquire' memory
     *     ordering model or stricter.  This will guarantee that all changes
     *     made before setting the 'reload' in the requesting thread will be
     *     visible to the PMD thread.
     *   * All other configuration data could be read with any memory
     *     ordering model (including non-atomic and 'relaxed') but *only after*
     *     reading the 'reload' atomic set to 'true'.
     *   * When the PMD reload done, PMD should (optionally) set all the below
     *     knobs except the 'reload' to their default ('false') values and
     *     (mandatory), as the last step, set the 'reload' to 'false' using
     *     'release' memory ordering model or stricter.  This will inform the
     *     requesting thread that PMD has completed a reload cycle.
     */
    atomic_bool reload;             /* Do we need to reload ports? */
    atomic_bool wait_for_reload;    /* Can we busy wait for the next reload? */
    atomic_bool reload_tx_qid;      /* Do we need to reload static_tx_qid? */
    atomic_bool exit;               /* For terminating the pmd thread. */

    pthread_t thread;
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    bool isolated;

    /* Max sleep request in microseconds. */
    atomic_uint64_t max_sleep;

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    uint32_t static_tx_qid;

    /* Number of filled output batches. */
    int n_output_batches;

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED;
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    struct hmap tx_ports OVS_GUARDED;

    struct ovs_mutex bond_mutex;    /* Protects updates of 'tx_bonds'. */
    /* Map of 'tx_bond's used for transmission.  Written by the main thread
     * and read by the pmd thread. */
    struct cmap tx_bonds;

    /* These are thread-local copies of 'tx_ports'.  One contains only tunnel
     * ports (that support push_tunnel/pop_tunnel), the other contains ports
     * with at least one txq (that support send).  A port can be in both.
     *
     * There are two separate maps to make sure that we don't try to execute
     * OUTPUT on a device which has 0 txqs or PUSH/POP on a non-tunnel device.
     *
     * The instances for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct hmap tnl_port_cache;
    struct hmap send_port_cache;

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;

    /* @veencn_260223: Per-stage latency measurement. */
    struct pmd_latency_stats latency_stats;

    /* @veencn: Per-packet trace ring buffer. */
    struct pkt_trace_state trace;

    /* Stats from previous iteration used by automatic pmd
     * load balance logic. */
    uint64_t prev_stats[PMD_N_STATS];
    atomic_count pmd_overloaded;

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;

    /* Next time when PMD should try RCU quiescing. */
    long long next_rcu_quiesce;
};

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-thread.h */
