/**
 * Filename: ISP-01
 * Author:
 * Date: 2023.03.09
 * Version: 1.4
 * Description: Proj 01--L2tp Protocol Analysis Experiment and Design
 * References:
 */
#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MAX_PROTO_TEXT_LEN 16 // 子协议名称最大长度
#define MAX_PROTO_NUM 12      // 子协议数量
#define IPSEC_PORT 4500
#define L2TP_PORT 1701
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "headers.h"
char a[15] = "TJ-University";

// 将一个unsigned long型的IP转换为字符串类型的IP
#define IPTOSBUFFERS 12
char* iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p;
    p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);

    // 格式化字符串
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

// 输出网卡信息
void ifprint(pcap_if_t* d, int num) 
{
    pcap_addr_t* a;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n=================================================\n");
    printf("网卡%d信息：\n", num);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    // 输出网卡名称
    printf("网卡名      :%s\n", d->name);
    // 网卡描述信息
    if (d->description){
        printf("网卡描述    :%s\n", d->description);
    }
    // 反馈
    printf("反馈        :%s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
    // IP地址
    for (a = d->addresses; a; a = a->next){
        switch (a->addr->sa_family){
            case AF_INET:
                printf("IP地址类型  :AF_INET\n");
                if (a->addr)
                    printf("IP地址      :%s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                if (a->netmask)
                    printf("掩码        :%s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)
                    printf("广播地址    :%s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)
                    printf("目标地址    :%s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
                break;
            default:
                //printf("Address Family Name:Unkown\n");
                break;
        }
    }
}

// l2tp解包函数
int decode_l2tp(char* l2tpbuf)
{
    struct l2tp_header* pl2tpheader;
    pl2tpheader = (l2tp_header*)l2tpbuf;
    u_short t, l, s, o;
    t = (pl2tpheader->tlxxsxop & 0x80) >> 7;
    l = (pl2tpheader->tlxxsxop & 0x40) >> 6;
    s = (pl2tpheader->tlxxsxop & 0x08) >> 3;
    o = (pl2tpheader->tlxxsxop & 0x02) >> 1;

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
    printf("\n=================================================\n");
    printf("L2TP协议分析：\n");
    printf("0x%x\n", pl2tpheader->tlxxsxop);
    printf("类型            :%s\n", t ? "1(控制信息)" : "0(数据信息)");
    printf("长度在位标志    :%d\n", l);
    printf("顺序字段在位标志:%d\n", s);
    printf("偏移值在位标志  :%d\n", o);
    printf("优先级          :%d\n", pl2tpheader->tlxxsxop & 0x01);
    printf("版本号          :%d\n", pl2tpheader->xxxxver & 0x0f);
    if (l == 1) { // 长度在位标志为1
        printf("消息总长度      :%d\n", ntohs(pl2tpheader->length));
    }
    printf("隧道标识符      :%d\n", ntohs(pl2tpheader->tunnel_id));
    printf("会话标识符      :%d\n", ntohs(pl2tpheader->session_id));
    if (s == 1) { // 顺序字段在位标志为1
        printf("当前消息顺序号  :%d\n", ntohs(pl2tpheader->ns));
        if (t == 1) { // 控制信息nr才有意义
            printf("下一消息顺序号  :%d\n", ntohs(pl2tpheader->nr));
        }
    }
    if (l == 1) { // 偏移值在位标志为1
        printf("偏移量          :%d\n", ntohs(pl2tpheader->offset));
    }
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    return true;
}

// UDP解包函数,l2tp用UDP协议
int decode_udp(char* udpbuf)
{
    udp_header* pudpheader;
    pudpheader = (udp_header*)udpbuf;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
    printf("\n=================================================\n");
    printf("UDP协议分析：\n");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("源端口  :%d\n", ntohs(pudpheader->sport));
    printf("目的端口:%d\n", ntohs(pudpheader->dport));
    printf("数据长度:%d\n", ntohs(pudpheader->len));
    printf("校验和  :%d\n", ntohs(pudpheader->crc));

    if (ntohs(pudpheader->sport) == 4500 && ntohs(pudpheader->dport) == 4500) {
        printf("L2tp over IpSec connection has been found.\n");
    }
    else if (ntohs(pudpheader->sport) == 1701 && ntohs(pudpheader->dport) == 1701) {
        printf("L2tp connection has been found.\n");
        decode_l2tp((char*)(udpbuf + 8));
    } 
    return true;
}

// IP解包函数
int decode_ipv4(char* ipbuf)
{
    ip_header* ih;
    u_int ip_len;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
    printf("\n=================================================\n");
    printf("IPv4协议分析：\n");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    // 返回IP首部的位置
    ih = (ip_header*)(ipbuf);
    // IP首部长度
    ip_len = (ih->ver_ihl & 0xf) * 4;

    printf("版本号  :%d\n", (ih->ver_ihl & 0xf0) >> 4);
    printf("首部长度:%dB\n", ip_len);
    printf("服务类型:%d\n", ih->tos);
    printf("总长度  :%d\n", ntohs(ih->tlen));
    printf("标识    :%d\n", ntohs(ih->identification));
    printf("标志    :%d\n", (ih->flags_fo & 0xe000) >> 12);
    printf("片偏移  :%dB\n", (ih->flags_fo & 0x1fff) * 8);
    printf("生存时间:%d\n", int(ih->ttl));
    printf("协议    :%s\n", ih->proto == IPPROTO_UDP ? "UDP" : "*");
    printf("校验和  :%d\n", ntohs(ih->crc));
    printf("源地址  :%d.%d.%d.%d\n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
    printf("目的地址:%d.%d.%d.%d\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
    
    // 选项和填补位
    printf("\n");
    if (ih->proto == IPPROTO_UDP) {
        decode_udp((char*)(ipbuf + ip_len));
    }
    return true;
}

// 以太网分析
int decode_ethernet(char* etherbuf)
{
    ethernet_header* peheader;
    u_short type;
    peheader = (ethernet_header*)etherbuf;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
    printf("\n=================================================\n");
    printf("以太网协议分析：\n");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    type = ntohs(peheader->type);
    printf("类型    :0x%x", type);
    switch (type){
        case 0x0800:
            printf("(IPV4)\n");
            break;
        case 0x86DD:
            printf("(IPV6)\n");
            break;
        case 0x0806:
            printf("(ARP)\n");
            break;
        case 0x0835:
            printf("(RARP)\n");
            break;
        default:
            break;
    }
    printf("源地址  :%d:%d:%d:%d:%d:%d\n",
        peheader->src_mac_addr.byte1,
        peheader->src_mac_addr.byte2,
        peheader->src_mac_addr.byte3,
        peheader->src_mac_addr.byte4,
        peheader->src_mac_addr.byte5,
        peheader->src_mac_addr.byte6);
    printf("目的地址:%d:%d:%d:%d:%d:%d\n",
        peheader->des_mac_addr.byte1,
        peheader->des_mac_addr.byte2,
        peheader->des_mac_addr.byte3,
        peheader->des_mac_addr.byte4,
        peheader->des_mac_addr.byte5,
        peheader->des_mac_addr.byte6);
    printf("\n");
    if (type == 0x0800) {
        decode_ipv4((char*)(etherbuf + 14));
    }
    return true;

}

// 包处理回调函数，对于每个嗅探到的数据包
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;
    char mypkt[1000];

    // 将时间戳转换成可识别的格式
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "time:%H:%M:%S", ltime);
    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

    // 打印包
    int len = header->caplen + 1;
    for (int i = 1; i < len; i++)
    {
        if (i < 93)
            mypkt[i - 1] = pkt_data[i - 1];
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }
    printf("\n-----------------------------------------------------------------\n");

    for (int i = 1; i < len; i++)
    {
        char temp = mypkt[i - 1];
        if (temp >= 32 && temp <= 126) {
            printf("%c", temp);
        }
        else {
            printf(".");
        }
        if ((i % 16) == 0)
            printf("\n");
    }
    printf("\n-----------------------------------------------------------------\n");

    for (int i = 93; i < 93 + 15; i++) {
        mypkt[i - 1] = a[i - 93];
    }

    for (int i = 1; i < 93 + 15; i++)
    {
        if (i == 93)
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE);
        char temp = mypkt[i - 1];
        if (temp >= 32 && temp <= 126) {
            printf("%c", temp);
        }
        else {
            printf(".");
        }
        if ((i % 16) == 0)
            printf("\n");
    }
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

    decode_ethernet((char*)pkt_data);

    printf("\n-----------------------------------------------------------------\n");
    printf("\n\n");
}

int main(int argc, const char* argv[])
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];// 出错信息
    u_int netmask;

    // 过滤器，筛选出 从124.223.79.89发送的数据(src) 和 到达124.223.79.89的数据(dst)
    char packet_filter[] = "src host 192.168.137.105 and dst host 139.196.166.142 and src port 1701 and dst port 1701";
    struct bpf_program fcode;

    // 获取本机设备列表
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    // 打印列表
    for (i = 0, d = alldevs; d; d = d->next, i++){
        ifprint(d, i + 1);
    }
    if (i == 0){
        printf("No interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i){
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs); // 释放设备列表
        return -1;
    }

    // 跳转到已选中的适配器
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // 打开设备
    if ((adhandle = pcap_open(d->name,          // 设备名
        65536,            // 要捕捉的数据包的部分，65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
        1000,             // 读取超时时间
        NULL,             // 远程机器验证
        errbuf            // 错误缓冲池
    )) == NULL){
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 检测链接层
    if (pcap_datalink(adhandle) != DLT_EN10MB){
        fprintf(stderr, "\n此程序只能运行在以太网上.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (d->addresses != NULL) {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;// 获取接口第一个地址的掩码
    }
    else {
        netmask = 0xffffff; // 如果这个接口没有地址，那么我们假设这个接口在C类网络中
    }

    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) >= 0){
        // 设置过滤器
        if (pcap_setfilter(adhandle, &fcode) < 0){
            fprintf(stderr, "\nError setting the filter.\n");
            pcap_freealldevs(alldevs);
            return -1;
        }
    }
    else {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);
    pcap_freealldevs(alldevs);

    // 开始嗅探
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}