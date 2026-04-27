# QEMU-LVZ

本项目主要为LoongArch64架构的QEMU TCG虚拟机提供虚拟化扩展（LVZ）支持。目前已基本实现所有指令、CSR及架构支持，处于bug修复阶段。

## 当前问题

目前在TCG虚拟机中运行KVM虚拟机，存在相当大的内存问题，具体表现为系统随机触发page fault、stack smashing detected等错误。已经发现的特征如下：

- 在设置外侧TCG虚拟机的smp=1后，错误概率增加，可能刚启动内侧KVM虚拟机，便会在每一次定时器中断中触发一次内存错误，直至内核崩溃。
- 通过与串口输出日志、QEMU日志的比对，发现可能存在GVA映射到不同的GPA的现象，且输出的串口内容可能会被写入到Guest页表中。
- 对所有的invtlb指令采用清除所有（包括Host与Guest）TLB项，将tlbwr与tlbfill所使用的invalidate\_tlb函数改为直接tlb\_flush，均无法解决问题。
- 在ertn指令执行后清空Guest TLB，能显著降低内存错误触发几率，但无法完全解决，且暂时并不认为这是正确的修复方法。

## 编译与测试

在项目根目录依次执行：

- ./configure --target-list=loongarch64-softmmu --disable-doc
- make -j

测试需要进行手工操作：进入lvz目录，执行./qemu.img进入外侧TCG虚拟机，再在其中启动KVM虚拟机，尝试一些内存读写操作，验证稳定性。测试结束后，手动将串口输出保存在lvz/kvm-log.txt，与lvz/qemu-log.txt配合分析。

## 当前设计

### CPU虚拟化

在CPULoongArchState结构体中加入Guest变量，以确定Host/Guest模式，为两个模式提供了两套不同的TLB、CSR寄存器与定时器。Host模式下通过设置CSR.GSTAT.PGM为1后执行ertn，进入Guest模式；Guest模式下触发HVCL、GSPR以及与Host地址翻译相关的例外，或Host触发中断，回到Host模式。

### 内存虚拟化

LoongArch继承了MIPS软件处理页表的设计，硬件通过TLB完成访存。GVA->HPA的完整地址转换模式如下：

1. 在Guest TLB中查找GVA-\>GPA的映射。若未找到，直接在Guest触发例外，不退回Host。
2. 找到Guest TLB后，在Host TLB中查找GPA-\>HPA的映射。若未找到，退回Host并触发TLB重填例外。
3. Host在页表中查找GPA-\>HPA项并填入TLB，若页表不存在该项，则会填入V=0项。
4. 再次查找TLB，若找到V=0项，则退回Host并触发页无效例外。
5. 进入Guest模式前，Host的一般例外入口已被KVM设置，因此后续由KVM处理GPA->HPA映射，更新页表。


### 定时器虚拟化

为Guest模式单独实现了一个定时器，在进入Guest模式时，若TCFG已配置则开启定时器，退出Gust模式后无条件停止。定时器到期则触发Guest中断。

Host模式期间，由kvm通过软件模拟定时器计时，进入Guest时将更新的时间写回Guest CSR.TVAL。若在此期间定时器到期，则将ESTAT中定时器中断位置1，并触发中断。

### 中断虚拟化

LoongArch64架构提供了多种将Host中断映射到Guest的方式：

- CSR.GINTCTL.HWIC被设置时，外部硬件的中断由Host处理，Host向Guest的CSR.ESTAT对应中断位置1，则Host的CSR.ESTAT对应位自动归0。
- CSR.GINTCTL.HWIP被设置时，外部硬件的中断直接映射到Guest。

Guest模式下，Host依旧响应自己的中断，不会长时间占据CPU。kvm\_handle\_exit函数会在将中断处理入口换成常规入口后，开启中断，由Host处理自己的中断。

### 杂项

MMIO访问与上述内存访问流程大致相同，不同点为KVM直接模拟MMIO操作，不更新页表。

执行IOCSR、CPUCFG、IDLE等指令，直接触发GSPR例外，由KVM处理。

### 与内部文档描述的设计差异

1. 文档中提到Host与Guest共享TLB，但未阐述如何避免TLB项冲突，因此目前采用Guest、Host TLB分开实现的方法。
2. invtlb在文档中共有15个操作值，目前尚未对所有操作值进行实现，对0x10-0x16值采用了对指定GID项的TLB项全部无效化的实现，理论上不应影响运行的正确性。
