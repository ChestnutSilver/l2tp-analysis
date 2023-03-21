#pragma once
#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MAX_PROTO_TEXT_LEN 16 // 子协议名称最大长度
#define MAX_PROTO_NUM 12      // 子协议数量

// 定义mac地址格式
typedef struct mac_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}mac_address;

// 定义以太网首部格式
typedef struct ethernet_header
{
    mac_address des_mac_addr;
    mac_address src_mac_addr;
    u_short type;
}ethernet_header;

// 定义IPv4地址结构
typedef struct ipv4_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// 定义IP首部格式
typedef struct ipv4_header
{
    u_char ver_ihl;         // 版本和首部长度
    u_char tos;             // 服务类型
    u_short tlen;           // 总长度
    u_short identification; // 标识号
    u_short flags_fo;       // 段偏移量
    u_char ttl;             // 生存时间
    u_char proto;           // 协议
    u_short crc;            // 首部校验和
    ipv4_address saddr;     // 源ip地址
    ipv4_address daddr;     // 目的地址
    u_int op_pad;           // 选项和填补位
}ip_header;

// 定义UDP首部格式
typedef struct udp_header
{
    u_short sport; // 16bit源端口
    u_short dport; // 16bit目的端口
    u_short len;   // 16bit长度
    u_short crc;   // 16bit 校验和
}udp_header;

// 定义l2tp首部格式
typedef struct l2tp_header
{
    u_char tlxxsxop;       // t类型（0数据1控制） 
                           // l长度在位标志（控制必为1） 
                           // s顺序字段在位标志（1存在ns nr控制必为1）
                           // o偏移值在位标志
                           // p优先级（用于数据消息 控制必为0）
    u_char xxxxver;        // 版本号
    u_short length;        // 消息总长度
    u_short tunnel_id;     // 隧道标识符 本地意义
    u_short session_id;    // 会话标识符 本地意义
    u_short ns;            // 当前消息顺序号
    u_short nr;            // 下一控制消息顺序号，数据消息为保留字段
    u_short offset;        // 偏移值 指示载荷开始位置
    u_short offser_pading; // 偏移量填充

}l2tp_header;