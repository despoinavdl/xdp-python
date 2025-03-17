/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
                             " - Allows selecting BPF --progname name to XDP-attach to --dev\n";

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <xdp/libxdp.h>
#include <linux/jhash.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "flow_headers.h"
#include "csv_utils.h"

static const char *default_filename = "flow_ft.o";
static const char *default_progname = "packet_handler";
const char *model_path = "model.tflite"; // Path to model file

int map_fds[NUM_MAPS];
int passed_map_fd, dbg_fd, sig_fd;

int map_seeds[] = {12, 37, 42, 68, 91};

void handle_sigint(int sig)
{
    int i;
    struct datarec rec = {0};
    // Close all map file descriptors
    for (i = 0; i < 5; i++)
    {
        close(map_fds[i]);
    }
    // Find the num of packets from map
    int ret;
    __u32 prev_key = -1;
    __u32 key = -1;
    ret = bpf_map_get_next_key(passed_map_fd, &prev_key, &key);
    if (ret == 0)
    {
        ret = bpf_map_lookup_elem(passed_map_fd, &key, &rec);
    }

    printf("Caught signal %d\n", sig);
    printf("Total packets captured: %llu\n", rec.packets);
    close(passed_map_fd);
    close(dbg_fd);
    close(sig_fd);
    exit(0);
}

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'},
     "Show help",
     false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>",
     "<ifname>",
     true},

    {{"skb-mode", no_argument, NULL, 'S'},
     "Install XDP program in SKB (AKA generic) mode"},

    {{"native-mode", no_argument, NULL, 'N'},
     "Install XDP program in native mode"},

    {{"auto-mode", no_argument, NULL, 'A'},
     "Auto-detect SKB or native mode"},

    {{"unload", required_argument, NULL, 'U'},
     "Unload XDP program <id> instead of loading",
     "<id>"},

    {{"unload-all", no_argument, NULL, 4},
     "Unload all XDP programs on device"},

    {{"quiet", no_argument, NULL, 'q'},
     "Quiet mode (no output)"},

    {{"filename", required_argument, NULL, 1},
     "Load program from <file>",
     "<file>"},

    {{"progname", required_argument, NULL, 2},
     "Load program from function <name> in the ELF file",
     "<name>"},

    {{0, 0, NULL, 0}}};

static unsigned long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int map_fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);
    if (!map)
    {
        fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
        goto out;
    }

    map_fd = bpf_map__fd(map);
out:
    return map_fd;
}

static int locate_fd(struct xdp_program *program, const char *map_name)
{
    int stats_map_fd;
    stats_map_fd = find_map_fd(xdp_program__bpf_obj(program), map_name);
    if (stats_map_fd < 0)
    {
        /* xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */
        return EXIT_FAIL_BPF;
    }
    return stats_map_fd;
}

// Function to get the protocol name from its number
const char *get_protocol_name(__u8 protocol)
{
    switch (protocol)
    {
    case 1:
        return "ICMP";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    default:
        return "Unknown";
    }
}

void print_flow_info(struct flow_info *flow)
{
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    // Convert IP addresses from network to presentation format
    inet_ntop(AF_INET, &flow->src_ip, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &flow->dst_ip, dst_ip_str, INET_ADDRSTRLEN);

    printf("-------------------------------\n");
    printf("Source IP:       %s\n", src_ip_str);
    printf("Destination IP:  %s\n", dst_ip_str);
    printf("Source Port:     %u\n", ntohs(flow->src_port)); // Convert to host byte order
    printf("Destination Port:%u\n", ntohs(flow->dst_port)); // Convert to host byte order
    printf("Protocol:        %s\n", get_protocol_name(flow->protocol));
    printf("Packets:         %u\n", flow->packets);
    printf("Bytes:           %llu\n", flow->bytes);
    printf("First Seen:      %llu\n", flow->first_seen);
    printf("Last Seen:       %llu\n", flow->last_seen);
    printf("Duration:        %llu\n", flow->duration);
    printf("PPS:             %.1f\n", (float)flow->pps / 10);
    printf("BPS:             %u\n", flow->bps);
    printf("IAT:             %llu\n", flow->iat);
    printf("-------------------------------\n");
}

void process_flow(int dbg_fd, __u32 curr_key, struct flow_info *info)
{
    // __u64 current_time = get_nsecs();
    int ret;
    ret = bpf_map_lookup_elem(dbg_fd, &curr_key, info);

    if (ret == 0)
    {
        print_flow_info(info);
    }
    else
    {
        fprintf(stderr, "Failed to get flow info from debug map");
        exit(ret);
    }

    // if (packets >= PACKETS_SAMPLE || current_time - last_seen > FLOW_TIMEOUT)
    //     write_flow_to_csv("flows.csv", &infos[1]);
}

void check_for_deletion(int map_fds[NUM_MAPS], struct flow_info *info)
{
    __u64 current_time = get_nsecs();
    struct flow_key key = {0};
    key.src_ip = info->src_ip;
    key.dst_ip = info->dst_ip;
    key.src_port = info->src_port;
    key.dst_port = info->dst_port;
    key.protocol = info->protocol;

    __u32 hashed_key = 0;
    int ret;
    // struct flow_info *rec = {0};

    int i;
    enum states state;
    __u32 state_key = jhash(&key, sizeof(key), STATE_HASH_SEED);

    ret = bpf_map_lookup_elem(sig_fd, &state_key, &state);
    if (ret < 0)
    {
        printf("No entry yet in sig_map\n");
    }

    // Check for timeout and if state = Ready
    if (current_time - info->last_seen > FLOW_TIMEOUT || state == Ready)
    {

        // !!!!!!! MAKE THE FLOW DECISION !!!!!!!//
        /*

        */

        state = Malicious; // For testing purposes, decide every flow to be malicious
        ret = bpf_map_update_elem(sig_fd, &state_key, &state, BPF_ANY);
        if (ret < 0)
        {
            printf("Couldn't update the sig_map entry\n");
            exit(1);
        }

        for (i = 0; i < NUM_MAPS; i++)
        {
            hashed_key = jhash((const void *)&key, sizeof(key), map_seeds[i]);
            // printf("Hashed key %u\n", hashed_key);
            // ret = bpf_map_lookup_elem(map_fds[i], &hashed_key, &rec);
            // if (ret != 0)
            // {
            //     printf("Element could not be found in map %d\n", i);
            //     fprintf(stderr, "Element could not be found in map %d\n", i);
            //     exit(ret);
            // }
            // printf("Lookup succeded for key: %u\n With map fd: %d\n\n", hashed_key, map_fds[i]);

            ret = bpf_map_delete_elem(map_fds[i], &hashed_key);
            if (ret < 0)
            {
                // printf("Element could not be removed from map %d\n Error code: %d\n", i, ret);
                // fflush(stdout);
                fprintf(stderr, "Element could not be removed from map %d\n", i);
                exit(ret);
            }
        }
        hashed_key = jhash((const void *)&key, sizeof(key), DBG_HASH_SEED);
        ret = bpf_map_delete_elem(dbg_fd, &hashed_key);
        if (ret < 0)
        {
            fprintf(stderr, "Element could not be removed from debug map \n");
            exit(ret);
        }
    }
    // print_flow_info(info);

    // // if (packets >= PACKETS_SAMPLE || current_time - last_seen > FLOW_TIMEOUT)
    // //     write_flow_to_csv("flows.csv", &infos[1]);

    // print_flow_info(info);
}

static int __check_map_fd_info(int map_fd, struct bpf_map_info *info, struct bpf_map_info *exp)
{
    __u32 info_len = sizeof(*info);
    int err;

    if (map_fd < 0)
        return EXIT_FAIL;

    /* BPF-info via bpf-syscall */
    err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
    if (err)
    {
        fprintf(stderr, "ERR: %s() can't get info - %s\n",
                __func__, strerror(errno));
        return EXIT_FAIL_BPF;
    }

    if (exp->key_size && exp->key_size != info->key_size)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map key size(%d) mismatch expected size(%d)\n",
                __func__, info->key_size, exp->key_size);
        return EXIT_FAIL;
    }
    if (exp->value_size && exp->value_size != info->value_size)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map value size(%d) mismatch expected size(%d)\n",
                __func__, info->value_size, exp->value_size);
        return EXIT_FAIL;
    }
    if (exp->max_entries && exp->max_entries != info->max_entries)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map max_entries(%d) mismatch expected size(%d)\n",
                __func__, info->max_entries, exp->max_entries);
        return EXIT_FAIL;
    }
    if (exp->type && exp->type != info->type)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map type(%d) mismatch expected type(%d)\n",
                __func__, info->type, exp->type);
        return EXIT_FAIL;
    }

    return 0;
}

int main(int argc, char **argv)
{
    initialize_csv("flows.csv");

    struct bpf_map_info map_expect = {0};
    struct bpf_map_info info = {0};
    struct xdp_program *program;
    int interval = 1;
    char errmsg[1024];
    int err;

    struct config cfg = {
        .ifindex = -1,
        .do_unload = false,
    };
    /* Set default BPF-ELF object file and BPF program name */
    strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
    strncpy(cfg.progname, default_progname, sizeof(cfg.progname));
    /* Cmdline options can change progname */
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    /* Required option */
    if (cfg.ifindex == -1)
    {
        fprintf(stderr, "ERR: required option --dev missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    /* Unload a program by prog_id, or
     * unload all programs on net device
     */
    if (cfg.do_unload || cfg.unload_all)
    {
        err = do_unload(&cfg);
        if (err)
        {
            libxdp_strerror(err, errmsg, sizeof(errmsg));
            fprintf(stderr, "Couldn't unload XDP program %d: %s\n",
                    cfg.prog_id, errmsg);
            return err;
        }

        printf("Success: Unloading XDP prog name: %s\n", cfg.progname);
        return EXIT_OK;
    }
    program = load_bpf_and_xdp_attach(&cfg);
    if (!program)
    {
        return EXIT_FAIL_BPF;
    }

    if (verbose)
    {
        printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
               cfg.filename, cfg.progname);
        printf(" - XDP prog id:%d attached on device:%s(ifindex:%d)\n",
               xdp_program__id(program), cfg.ifname, cfg.ifindex);
    }

    /* Initialize map fds */
    map_fds[0] = locate_fd(program, "hash_func_1");
    map_fds[1] = locate_fd(program, "hash_func_2");
    map_fds[2] = locate_fd(program, "hash_func_3");
    map_fds[3] = locate_fd(program, "hash_func_4");
    map_fds[4] = locate_fd(program, "hash_func_5");

    passed_map_fd = locate_fd(program, "passed_packets");
    dbg_fd = locate_fd(program, "dbg");
    sig_fd = locate_fd(program, "sig_map");
    int ret;

    /* Check map info */
    map_expect.key_size = sizeof(__u32);
    map_expect.value_size = sizeof(struct flow_info);
    map_expect.max_entries = XDP_MAX_MAP_ENTRIES;

    int i;
    for (i = 0; i < 5; i++)
    {
        err = __check_map_fd_info(map_fds[i], &info, &map_expect);
        if (err)
        {
            fprintf(stderr, "ERR: map via FD not compatible\n");
            return err;
        }
    }

    // Check for passed_packets map
    map_expect.key_size = sizeof(__u32);
    map_expect.value_size = sizeof(struct datarec);
    map_expect.max_entries = 1;

    err = __check_map_fd_info(passed_map_fd, &info, &map_expect);
    if (err)
    {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        return err;
    }

    // Check for dbg map
    map_expect.key_size = sizeof(__u32);
    map_expect.value_size = sizeof(struct flow_info);
    map_expect.max_entries = XDP_MAX_MAP_ENTRIES;

    err = __check_map_fd_info(dbg_fd, &info, &map_expect);
    if (err)
    {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        return err;
    }

    // Check for sig map
    map_expect.key_size = sizeof(__u32);
    map_expect.value_size = sizeof(enum states);
    map_expect.max_entries = XDP_MAX_MAP_ENTRIES;

    err = __check_map_fd_info(sig_fd, &info, &map_expect);
    if (err)
    {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        return err;
    }

    if (verbose)
    {
        printf("\nCollecting stats from BPF map\n");
        printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
               " key_size:%d value_size:%d max_entries:%d\n",
               info.type, info.id, info.name,
               info.key_size, info.value_size, info.max_entries);
    }

    /* Iterate through the keys for the first map */
    __u32 prev_key = -1;
    __u32 key = -1;
    struct flow_info info_flow = {0};
    signal(SIGINT, handle_sigint);

    while (1)
    {
        ret = bpf_map_get_next_key(dbg_fd, &prev_key, &key);
        if (ret == 0)
        {
            printf("\n--------- Flow Report ---------\n");
            // /* For a given key from the first map, gather the corresponding values from the debug map */
            process_flow(dbg_fd, key, &info_flow);
            // Check if flow has timed out, if yes make the decision and then delete the maps
            check_for_deletion(map_fds, &info_flow);
            prev_key = key;
        }
        /* If we reach the end of the map, or the map was empty, start from the beginning */
        if (ret == -2)
        {
            printf("\n======================================\n");
            prev_key = -1;
            key = -1;
            sleep(interval); /* Wait before next iteration */
        }
    }
    /* Close all map file descriptors */
    for (i = 0; i < 5; i++)
    {
        close(map_fds[i]);
    }
    close(passed_map_fd);
    close(dbg_fd);
    close(sig_fd);
    return 0;
}