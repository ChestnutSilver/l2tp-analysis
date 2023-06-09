# l2tp/IPsec协议分析

**简介：**

同济大学 2020级 信息安全原理 课程作业（Project 1-Project 2）。

差不多算是做完了罢......笑得，Project 1 第三问代码有点搞笑，（逻辑看起来是正确的，只是代码写的不太好），**主要是时间有些紧张**。

总评为“优”。

**引用：**

如您在作业中使用了我们的代码或报告的任何部分，请在参考文献中列出。

引文格式（yyyy.mm.dd是您访问本网站的日期）：

> [1] ChestnutSilver. 同济大学信息安全原理课程作业[EB/OL]. 2023[yyyy.mm.dd]. https://github.com/ChestnutSilver/l2tp-analysis

**食用方法：**

通过阅读实验报告，可以了解 Project 1-2 的详细实现方法，**报告中详细给出了每一个步骤的操作。**

**Project 1 的总体思路是：**

利用脚本在阿里云 ECS 搭建 l2tp over IPsec vpn，两个电脑连入vpn，两个电脑热点相连，两个电脑禁用IPsec，一个电脑抓取另一个电脑端口为1701的协议流量，得到未经加密的 l2tp 数据包（由于手机无法禁用IPSec，用一个电脑替代了手机）；编写代码，按照数据包的结构层层拆解，分析 l2tp 头的内容；拆解完成后，将静载荷字段替换为自己的内容。

Update：通过一些步骤，可以实现在阿里云 ECS 搭建 l2tp vpn，这使得手机也能够连入vpn，通过电脑抓取手机协议流量，圆满完成了实验要求。（这部分的方法附于报告最后）

**Project 2 的总体思路是：**

使用 Libreswan 开源程序库，利用四个阿里云 ECS 搭建 Gate to Gate IPsec vpn，通过修改ipsec.conf（或者添加自己的ipsec.conf文件），实现对ike、l2tp、ipsec参数的配置，最后查阅资料总结 linux 下 IPsec 模块构架及其相互关系。

**帮助：**

如果你有更好的建议或想法，或者在操作过程中遇到问题，欢迎在本仓库 Issues 与我联系。

## Project 1

### 1. 作业题目

基于C++设计并实现一个简单系统，实现：

（1）基于windows或linux抓取l2tp协议流量；

（2）针对每一个目标用户，实时监控其l2tp请求，并分析、还原、呈现其连接和业务载荷；

（3）支持对特定目标的静载荷替换。

构建一个demo：用笔记本电脑实现对手机上网对象的以上功能。

### 2. 解题方案

#### 2.1 基于windows或linux抓取l2tp协议流量

我们基于windows10系统和阿里云服务器（CentOS），搭建了能够抓取l2tp协议流量的服务端和电脑环境。在服务端，使用l2tp over IpSec协议，开放1701端口和4500端口，在windows系统，通过修改注册表和管理策略，禁用IpSec功能，使得协议流量均为未加密的l2tp协议流量，便于后续实验分析。编写C++程序，并配置使用WinPcap4.1.3，抓取协议流量。

同时，通过观察对比实验，验证了第一问的正确性。

![image](https://github.com/ChestnutSilver/l2tp-analysis/blob/main/pics/1-1.png)

（图1-1：基于windows或linux抓取l2tp协议流量）

#### 2.2 针对每一个目标用户，实时监控其l2tp请求，并分析、还原、呈现其连接和业务载荷

首先，我们实时监控了手机的l2tp请求。由于手机无法禁用IpSec功能，因此通过l2tp over IpSec协议与服务端进行数据交换，通过抓取其数据包，使用的端口为4500，证明了其为加密过的报文。

为了进一步拆解l2tp请求数据，我们使用另一台电脑模拟手机环境，在该电脑同样禁用IpSec，这两台电脑通过热点相互连接，并使用l2tp vpn，使得能够对目标用户的l2tp请求拆解，分析、还原并呈现其连接和业务载荷，包括类型、长度在位标志、顺序字段在位标志、偏移值在位标志、优先级、版本号、消息总长度、隧道标识符、会话标识符、当前消息顺序号、下一消息顺序号、偏移量等信息。

我们也拆解并分析了更高层次的以太网协议、Ipv4协议和UDP协议，详细呈现了其连接和业务载荷。

同时，通过wireshark抓取数据包的对比，验证了第二问的正确性。

<img src="https://github.com/ChestnutSilver/l2tp-analysis/blob/main/pics/1-2.png" width="400"/>

![image](https://github.com/ChestnutSilver/l2tp-analysis/blob/main/pics/1-3.png)

（图1-2、1-3：针对每一个目标用户，实时监控其l2tp请求，分析、还原、呈现其连接和业务载荷-l2tp协议）

<img src="https://github.com/ChestnutSilver/l2tp-analysis/blob/main/pics/1-4.png" width="400"/>

（图1-4：针对每一个目标用户，实时监控其l2tp请求，分析、还原、呈现其连接和业务载荷-IPv4协议）

#### 2.3 支持对特定目标的静载荷替换

我们通过对l2tp报文封装结构的分析，找到数据包的静载荷部分，并将特定数据包的静载荷替换为自己的data数据，替换完成后，再按照l2tp报文结构进行封装，产生一个新的数据包。

同时，使用第2问的拆解算法，对新的数据包重新拆解，得到了我们替换的新静载荷。

![image](https://github.com/ChestnutSilver/l2tp-analysis/blob/main/pics/1-5.png)

（图1-5：支持对特定目标的静载荷替换）

## Project 2

### 1. 作业题目

基于 linux 搭建一个基本 ipsec-vpn 原型 

1.选择一个开源程序库，总结一下 linux 下 ipsec 网关程序模块构架及其相互关系 

（1）总结配置 ike 的方法与参数 

（2）总结 l2tp-ipsec 的配置方法与参数 

（3）总结 ipsec 模式选择及参数配置方法

2.搭建一个 gate2gate ipsec vpn 网关对（gate 后 lan 为私有网络）。

### 2. 解题方案

为了便于描述和验证试验，我们首先完成搭建 gate2gate ipsec vpn 网关对，并验证正确；再进行 ike、l2tp、ipsec 参数的配置和分析；最后总结 linux 下 ipsec 网关程序模块构架及其相互关系。

#### 2.1 搭建一个 gate2gate ipsec vpn 网关对（gate 后 lan 为私有网络）

本次实验先后尝试了多种方法，包括 0-2 个本地电脑、0-4 个虚拟机、0-4 个云主机的多种可能的排列组合，先后尝试了 OpenSwan、StrongSwan、Libreswan 等多种开源程序库，先后尝试了 Windows10、CentOS7.8、Ubuntu16 等多种环境，先后尝试了运行 Project1 主程序、wireshark 抓包等多种辅助验证方法，先后进行了脚本搭建和手工配置搭建操作。然而，在虚拟机上完成本次实验操作非常困难，在 2 本地+2 云主机的实验中也遇到了不少困难，这可能是由于本地和云主机的体质并不完全一样导致的。

最终，确定使用 4 个云主机的实验方法，成功搭建了 gate to gate ipsec vpn 网关对，并成功进行了正确性验证试验（包括验证 gate to gate 搭建成功、验证 vpn 经过了 ipsec 加密）。

实验需要：4 个阿里云 ECS 实例（1 vCPU、2 GiB、I/O 优化、ecs.n4.small），CentOS 7.8 镜像，Libreswan 开源程序库。

#### 2.2 ike、l2tp、ipsec 参数配置

查阅 Libreswan 官方网址，了解各个参数的作用和备选项。通过 vim /etc/ipsec.d/myvpn.conf 等指令，修改相应的参数配置。
