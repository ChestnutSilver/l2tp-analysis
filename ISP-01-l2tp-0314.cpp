/**
 * Filename: ISP-01
 * Author: 2053182 王润霖，2052338 鲍宇轩
 * Date: 2023.03.09
 * Version: 1.1
 * Description: Proj 01--L2tp Protocol Analysis Experiment and Design
 * References:
 */

#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<pcap.h>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
using namespace std;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, const char* argv[])
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct tm* ltime;
    char timestr[16];
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    time_t local_tv_sec;
    u_int netmask;
    /* src host 124.223.79.89 or dst host 124.223.79.89 */
    /* 过滤器，筛选出 从124.223.79.89发送的数据(src) 和 到达124.223.79.89的数据(dst) */
    //char packet_filter[] = "src host 124.223.79.89 or dst host 124.223.79.89"; 
    //char packet_filter[] = "src host 192.168.137.126 and dst host 124.223.79.89";
    char packet_filter[] = "src host 124.223.79.89 and dst host 192.168.137.126";
    /**
     * 124.223.79.89 == 7c df 4f 59（服务端）
     * 100.80.33.109 == 64 50 21 6D（应该是我的本地电脑？但是又好像不是）
     * 192.168.137.xx == c0 a8 89 xx（我的手机）
     */
    struct bpf_program fcode;

    /* 获取本机设备列表 */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* 打印列表 */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 跳转到已选中的适配器 */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* 打开设备 */
    if ((adhandle = pcap_open(d->name,          // 设备名
        65536,            // 要捕捉的数据包的部分
                          // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
        1000,             // 读取超时时间
        NULL,             // 远程机器验证
        errbuf            // 错误缓冲池
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\nlistening on %s...\n", d->description);

    /* 设置过滤器 */
    if (d->addresses != NULL)
        /* 获取接口第一个地址的掩码 */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果这个接口没有地址，那么我们假设这个接口在C类网络中 */
        netmask = 0xffffff;
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) >= 0)
    {
        //设置过滤器
        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            fprintf(stderr, "\nError setting the filter.\n");
            /* 释放设备列表 */
            pcap_freealldevs(alldevs);
            return -1;
        }
    }
    else
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);

    /* 获取数据包 */
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

        if (res == 0)
            /* 超时时间到 */
            continue;

        /* 将时间戳转换成可识别的格式 */
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
        /* 打印包 */
        int len = header->caplen + 1;
        for (i = 1; i < len; i++)
        {
            printf("%.2x ", pkt_data[i - 1]);
            if ((i % 16) == 0)
                printf("\n");
        }
        printf("\n-----------------------------------------------------------------\n");
    }
    if (res == -1) {
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }
    return 0;
}