/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018/10/28     Bernard      The unify RISC-V porting implementation
 * 2018/12/27     Jesven       Add SMP support
 * 2020/11/20     BalanceTWK   Add FPU support
 */

#include "cpuport.h"

#ifdef RT_USING_SMP
#define rt_hw_interrupt_disable rt_hw_local_irq_disable
#define rt_hw_interrupt_enable  rt_hw_local_irq_enable
#endif

/*
 * rt_base_t rt_hw_interrupt_disable(void);
 */
    .globl rt_hw_interrupt_disable
rt_hw_interrupt_disable:
    /* 
     * 1. a0 = mstatus; 备份mstatus这个csr寄存器的值到a0寄存器中
     * 2. mstatus &= ~(8)， 将mstatus的bit3，即mstatus.MIE 清0，表示关闭全局中断
     */
    csrrci a0, mstatus, 8
    ret

/*
 * void rt_hw_interrupt_enable(rt_base_t level);
 */
    .globl rt_hw_interrupt_enable
rt_hw_interrupt_enable:
    /* 
     * 将CPU寄存器a0的值，写入到mstatus CSR寄存器中，相当于恢复了，调用 rt_hw_interrupt_disable 时的mstatus的值
     */
    csrw mstatus, a0
    ret

/*
 * #ifdef RT_USING_SMP
 * void rt_hw_context_switch_to(rt_ubase_t to, stuct rt_thread *to_thread);
 * #else
 * void rt_hw_context_switch_to(rt_ubase_t to);
 * #endif
 * a0 --> to
 * a1 --> to_thread
 */

 /**
  * rt_hw_context_switch_to 函数，一般仅在系统初始化阶段（ signal 中除外），在启动调度器中（ rt_system_scheduler_start ），
  * 使用一次，仅仅进行下文的切换，而无上文的保存动作
  * 
  * 1. 初始化，启动调度器，仅进行下文的切换，这里的下文，具体是指，从就绪任务表中，查询到的，优先级最高的，最先要被执行的任务的任务栈信息
  * 2. 任务栈信息具体是：
  * 3. 所谓的切换是指：将任务栈信息，赋值给了CPU的寄存器，以及CPU的控制状态寄存器CSR
  * 4. 包含CPU的哪些寄存器和CSR寄存器呢？
  * 
  */
    .globl rt_hw_context_switch_to
rt_hw_context_switch_to:
    /* 
     * 1. LOAD sp, (a0) 这里其实省略了一个0长的offset，完整表示为： LOAD sp, 0(a0)
     * 2. 将a0这个CPU寄存器的值，加上0偏移量，赋值给了CPU的栈指针 sp
     * 3. 这里a0表示的是，调用 rt_hw_context_switch_to 函数时，传递过来的参数值
     * 4. 传递过来的参数值，其实就是即将要执行的任务的任务栈指针，具体如： rt_hw_context_switch_to((rt_ubase_t)&to_thread->sp);
     * 5. to_thread->sp 指向的是任务栈的栈底，即 struct rt_hw_stack_frame 对象，也就是 to_thread->sp 指向 epc
     */
    
    // struct rt_hw_stack_frame
    //{
    //    rt_ubase_t epc;        /* epc - epc    - program counter                     */
    //    rt_ubase_t ra;         /* x1  - ra     - return address for jumps            */
    //    rt_ubase_t mstatus;    /*              - machine status register             */
    //    rt_ubase_t gp;         /* x3  - gp     - global pointer                      */
    //    rt_ubase_t tp;         /* x4  - tp     - thread pointer                      */
    //    rt_ubase_t t0;         /* x5  - t0     - temporary register 0                */
    //    rt_ubase_t t1;         /* x6  - t1     - temporary register 1                */
    //    rt_ubase_t t2;         /* x7  - t2     - temporary register 2                */
    //    rt_ubase_t s0_fp;      /* x8  - s0/fp  - saved register 0 or frame pointer   */
    //    rt_ubase_t s1;         /* x9  - s1     - saved register 1                    */
    //    rt_ubase_t a0;         /* x10 - a0     - return value or function argument 0 */
    //    rt_ubase_t a1;         /* x11 - a1     - return value or function argument 1 */
    //    rt_ubase_t a2;         /* x12 - a2     - function argument 2                 */
    //    rt_ubase_t a3;         /* x13 - a3     - function argument 3                 */
    //    rt_ubase_t a4;         /* x14 - a4     - function argument 4                 */
    //    rt_ubase_t a5;         /* x15 - a5     - function argument 5                 */
    //    rt_ubase_t a6;         /* x16 - a6     - function argument 6                 */
    //    rt_ubase_t a7;         /* x17 - s7     - function argument 7                 */
    //    rt_ubase_t s2;         /* x18 - s2     - saved register 2                    */
    //    rt_ubase_t s3;         /* x19 - s3     - saved register 3                    */
    //    rt_ubase_t s4;         /* x20 - s4     - saved register 4                    */
    //    rt_ubase_t s5;         /* x21 - s5     - saved register 5                    */
    //    rt_ubase_t s6;         /* x22 - s6     - saved register 6                    */
    //    rt_ubase_t s7;         /* x23 - s7     - saved register 7                    */
    //    rt_ubase_t s8;         /* x24 - s8     - saved register 8                    */
    //    rt_ubase_t s9;         /* x25 - s9     - saved register 9                    */
    //    rt_ubase_t s10;        /* x26 - s10    - saved register 10                   */
    //    rt_ubase_t s11;        /* x27 - s11    - saved register 11                   */
    //    rt_ubase_t t3;         /* x28 - t3     - temporary register 3                */
    //    rt_ubase_t t4;         /* x29 - t4     - temporary register 4                */
    //    rt_ubase_t t5;         /* x30 - t5     - temporary register 5                */
    //    rt_ubase_t t6;         /* x31 - t6     - temporary register 6                */
    //}

    /* 1. 将a0寄存器的值，即 to_thread->sp 赋值 CPU 寄存器 sp*/
    LOAD sp, (a0)

#ifdef RT_USING_SMP
    mv   a0,   a1
    call  rt_cpus_lock_status_restore
#endif
    /* 2. 将任务栈中的 mstatus 的值，赋值给 CPU a0 寄存器 */
    LOAD a0,   2 * REGBYTES(sp)

    /* 3. 将 CPU a0 寄存器的值，赋值给 CPU CSR 寄存器 mstatus */
    /* 其实，步骤 2 和步骤 3，这两个步骤，其实就是将任务栈的 mstatus 备份到 CPU CSR 寄存器 mstatus  中 */
    csrw mstatus, a0

    /* 4. 上面备份完任务的 mstatus 后，还需要备份，任务的其他运行时寄存器（ CPU 寄存器和 CSR 寄存器 ）  */
    j    rt_hw_context_switch_exit

/*
 * #ifdef RT_USING_SMP
 * void rt_hw_context_switch(rt_ubase_t from, rt_ubase_t to, struct rt_thread *to_thread);
 * #else
 * void rt_hw_context_switch(rt_ubase_t from, rt_ubase_t to);
 * #endif
 *
 * a0 --> from
 * a1 --> to
 * a2 --> to_thread
 */
    .globl rt_hw_context_switch
rt_hw_context_switch:
    /* saved from thread context
     *     x1/ra       -> sp(0)
     *     x1/ra       -> sp(1)
     *     mstatus.mie -> sp(2)
     *     x(i)        -> sp(i-4)
     */
#ifdef ARCH_RISCV_FPU
    addi    sp, sp, -32 * FREGBYTES

    FSTORE  f0, 0 * FREGBYTES(sp)
    FSTORE  f1, 1 * FREGBYTES(sp)
    FSTORE  f2, 2 * FREGBYTES(sp)
    FSTORE  f3, 3 * FREGBYTES(sp)
    FSTORE  f4, 4 * FREGBYTES(sp)
    FSTORE  f5, 5 * FREGBYTES(sp)
    FSTORE  f6, 6 * FREGBYTES(sp)
    FSTORE  f7, 7 * FREGBYTES(sp)
    FSTORE  f8, 8 * FREGBYTES(sp)
    FSTORE  f9, 9 * FREGBYTES(sp)
    FSTORE  f10, 10 * FREGBYTES(sp)
    FSTORE  f11, 11 * FREGBYTES(sp)
    FSTORE  f12, 12 * FREGBYTES(sp)
    FSTORE  f13, 13 * FREGBYTES(sp)
    FSTORE  f14, 14 * FREGBYTES(sp)
    FSTORE  f15, 15 * FREGBYTES(sp)
    FSTORE  f16, 16 * FREGBYTES(sp)
    FSTORE  f17, 17 * FREGBYTES(sp)
    FSTORE  f18, 18 * FREGBYTES(sp)
    FSTORE  f19, 19 * FREGBYTES(sp)
    FSTORE  f20, 20 * FREGBYTES(sp)
    FSTORE  f21, 21 * FREGBYTES(sp)
    FSTORE  f22, 22 * FREGBYTES(sp)
    FSTORE  f23, 23 * FREGBYTES(sp)
    FSTORE  f24, 24 * FREGBYTES(sp)
    FSTORE  f25, 25 * FREGBYTES(sp)
    FSTORE  f26, 26 * FREGBYTES(sp)
    FSTORE  f27, 27 * FREGBYTES(sp)
    FSTORE  f28, 28 * FREGBYTES(sp)
    FSTORE  f29, 29 * FREGBYTES(sp)
    FSTORE  f30, 30 * FREGBYTES(sp)
    FSTORE  f31, 31 * FREGBYTES(sp)

#endif
    /* 暂且认为：CPU 的 sp 寄存器，在任务运行过程中，不会被修改掉 */
    /* 此时 sp 的值为将要被挂起的任务的栈顶 */
    /* 将 CPU 的 sp 指针，从将被挂起的任务的栈顶（t6）,移动到被挂起任务的栈底（epc）*/
    addi  sp,  sp, -32 * REGBYTES
    /* 将 CPU sp 的内容，赋值给 a0 寄存器所指向的地址内容*/
    /* 也就是epc的值 */
    STORE sp,  (a0)

    STORE x1,   0 * REGBYTES(sp)
    STORE x1,   1 * REGBYTES(sp)

    csrr a0, mstatus
    andi a0, a0, 8
    beqz a0, save_mpie
    li   a0, 0x80
save_mpie:
    STORE a0,   2 * REGBYTES(sp)

    STORE x4,   4 * REGBYTES(sp)
    STORE x5,   5 * REGBYTES(sp)
    STORE x6,   6 * REGBYTES(sp)
    STORE x7,   7 * REGBYTES(sp)
    STORE x8,   8 * REGBYTES(sp)
    STORE x9,   9 * REGBYTES(sp)
    STORE x10, 10 * REGBYTES(sp)
    STORE x11, 11 * REGBYTES(sp)
    STORE x12, 12 * REGBYTES(sp)
    STORE x13, 13 * REGBYTES(sp)
    STORE x14, 14 * REGBYTES(sp)
    STORE x15, 15 * REGBYTES(sp)
    STORE x16, 16 * REGBYTES(sp)
    STORE x17, 17 * REGBYTES(sp)
    STORE x18, 18 * REGBYTES(sp)
    STORE x19, 19 * REGBYTES(sp)
    STORE x20, 20 * REGBYTES(sp)
    STORE x21, 21 * REGBYTES(sp)
    STORE x22, 22 * REGBYTES(sp)
    STORE x23, 23 * REGBYTES(sp)
    STORE x24, 24 * REGBYTES(sp)
    STORE x25, 25 * REGBYTES(sp)
    STORE x26, 26 * REGBYTES(sp)
    STORE x27, 27 * REGBYTES(sp)
    STORE x28, 28 * REGBYTES(sp)
    STORE x29, 29 * REGBYTES(sp)
    STORE x30, 30 * REGBYTES(sp)
    STORE x31, 31 * REGBYTES(sp)

    /* restore to thread context
     * sp(0) -> epc;
     * sp(1) -> ra;
     * sp(i) -> x(i+2)
     */
    LOAD sp,  (a1)

#ifdef RT_USING_SMP
    mv   a0,   a2
    call  rt_cpus_lock_status_restore
#endif /*RT_USING_SMP*/

    j rt_hw_context_switch_exit

#ifdef RT_USING_SMP
/*
 * void rt_hw_context_switch_interrupt(void *context, rt_ubase_t from, rt_ubase_t to, struct rt_thread *to_thread);
 *
 * a0 --> context
 * a1 --> from
 * a2 --> to
 * a3 --> to_thread
 */
    .globl rt_hw_context_switch_interrupt
rt_hw_context_switch_interrupt:

    STORE a0, 0(a1)

    LOAD  sp, 0(a2)
    move  a0, a3
    call rt_cpus_lock_status_restore

    j rt_hw_context_switch_exit

#endif

.global rt_hw_context_switch_exit
rt_hw_context_switch_exit:
#ifdef RT_USING_SMP
#ifdef RT_USING_SIGNALS
    mv a0, sp

    csrr  t0, mhartid
    /* switch interrupt stack of current cpu */
    la    sp, __stack_start__
    addi  t1, t0, 1
    li    t2, __STACKSIZE__
    mul   t1, t1, t2
    add   sp, sp, t1 /* sp = (cpuid + 1) * __STACKSIZE__ + __stack_start__ */

    call rt_signal_check
    mv sp, a0
#endif
#endif
    /* resw ra to mepc */

    /* 把将要运行的任务的任务栈中的 epc 写入到 CPU 的寄存器 mepc 中 */

    /* 当执行了 mret 指令时，将 mepc的值，自动写入到 CPU 的 PC 中， 也就意味着，任务切换运行 */
    LOAD a0,   0 * REGBYTES(sp)
    csrw mepc, a0

    /* 把将要运行的任务的任务栈中的 ra 寄存器，也可以称为 x1 寄存器 写入到 CPU 的 x1 寄存器中 */
    LOAD x1,   1 * REGBYTES(sp)

    /* t0 = 0x00007800 , 该16进制数据的，bit[14:11] 都为1，其他 bit 为0 */
    li    t0, 0x00007800

    /* 将 CSR mstatus 寄存器的 bit 11~ bit 14 都赋值为1 */
    /* bit11~bit12 设置为 1 表示将 mstatus.MPP 设置为 1 */
    /* mstatus.MPP 表示进入异常前的 CPU 的特权模式，这里强制设置为了 3，具体含义，后续待查 */
    csrw  mstatus, t0

    /* 把将要运行的任务的任务栈中的 mstatus 寄存器 赋值给 CPU 的 a0 寄存器  */
    LOAD a0,   2 * REGBYTES(sp)

    /* 将 CSR 寄存器 mstatus 的其他位不变，仅将a0中位1的对应bit设置为1 */
    /* 相当于执行了 CSRs[mstatus]=  CSRs[mstatus] | x[a0] ,其中 CSRs[mstatus] 表示mstatus的值，x[a0] 表示 a0 寄存器的值*/
    csrs mstatus, a0

    /* 把将要运行的任务的任务栈中的其他寄存器 写入到 CPU 寄存器中 */
    LOAD x4,   4 * REGBYTES(sp)
    LOAD x5,   5 * REGBYTES(sp)
    LOAD x6,   6 * REGBYTES(sp)
    LOAD x7,   7 * REGBYTES(sp)
    LOAD x8,   8 * REGBYTES(sp)
    LOAD x9,   9 * REGBYTES(sp)
    LOAD x10, 10 * REGBYTES(sp)
    LOAD x11, 11 * REGBYTES(sp)
    LOAD x12, 12 * REGBYTES(sp)
    LOAD x13, 13 * REGBYTES(sp)
    LOAD x14, 14 * REGBYTES(sp)
    LOAD x15, 15 * REGBYTES(sp)
    LOAD x16, 16 * REGBYTES(sp)
    LOAD x17, 17 * REGBYTES(sp)
    LOAD x18, 18 * REGBYTES(sp)
    LOAD x19, 19 * REGBYTES(sp)
    LOAD x20, 20 * REGBYTES(sp)
    LOAD x21, 21 * REGBYTES(sp)
    LOAD x22, 22 * REGBYTES(sp)
    LOAD x23, 23 * REGBYTES(sp)
    LOAD x24, 24 * REGBYTES(sp)
    LOAD x25, 25 * REGBYTES(sp)
    LOAD x26, 26 * REGBYTES(sp)
    LOAD x27, 27 * REGBYTES(sp)
    LOAD x28, 28 * REGBYTES(sp)
    LOAD x29, 29 * REGBYTES(sp)
    LOAD x30, 30 * REGBYTES(sp)
    LOAD x31, 31 * REGBYTES(sp)

    /* 当前 CPU 的 sp 寄存器的值，其实是等于，将要被执行的任务的栈底，即任务栈的 epc所在位置的地址
     * 将当前 CPU 的 sp 寄存器的值，加上32个寄存器位宽，其实，相当于,此时 CPU 的 sp指针，已经指向了
     * 将要被执行的任务栈的栈顶，比如t6寄存器的地址处
     */
    addi sp,  sp, 32 * REGBYTES

#ifdef ARCH_RISCV_FPU
    FLOAD   f0, 0 * FREGBYTES(sp)
    FLOAD   f1, 1 * FREGBYTES(sp)
    FLOAD   f2, 2 * FREGBYTES(sp)
    FLOAD   f3, 3 * FREGBYTES(sp)
    FLOAD   f4, 4 * FREGBYTES(sp)
    FLOAD   f5, 5 * FREGBYTES(sp)
    FLOAD   f6, 6 * FREGBYTES(sp)
    FLOAD   f7, 7 * FREGBYTES(sp)
    FLOAD   f8, 8 * FREGBYTES(sp)
    FLOAD   f9, 9 * FREGBYTES(sp)
    FLOAD   f10, 10 * FREGBYTES(sp)
    FLOAD   f11, 11 * FREGBYTES(sp)
    FLOAD   f12, 12 * FREGBYTES(sp)
    FLOAD   f13, 13 * FREGBYTES(sp)
    FLOAD   f14, 14 * FREGBYTES(sp)
    FLOAD   f15, 15 * FREGBYTES(sp)
    FLOAD   f16, 16 * FREGBYTES(sp)
    FLOAD   f17, 17 * FREGBYTES(sp)
    FLOAD   f18, 18 * FREGBYTES(sp)
    FLOAD   f19, 19 * FREGBYTES(sp)
    FLOAD   f20, 20 * FREGBYTES(sp)
    FLOAD   f21, 21 * FREGBYTES(sp)
    FLOAD   f22, 22 * FREGBYTES(sp)
    FLOAD   f23, 23 * FREGBYTES(sp)
    FLOAD   f24, 24 * FREGBYTES(sp)
    FLOAD   f25, 25 * FREGBYTES(sp)
    FLOAD   f26, 26 * FREGBYTES(sp)
    FLOAD   f27, 27 * FREGBYTES(sp)
    FLOAD   f28, 28 * FREGBYTES(sp)
    FLOAD   f29, 29 * FREGBYTES(sp)
    FLOAD   f30, 30 * FREGBYTES(sp)
    FLOAD   f31, 31 * FREGBYTES(sp)

    addi    sp, sp, 32 * FREGBYTES
#endif

    /* 执行 mret 指令 有如下几个硬件操作：
     * 1. 将 CPU 的 PC值，设置为CSRs[mepc] （mepc的值，在上面已经设置为了将要被执行的任务的任务栈中的epc值）
     * 2. 将特权级别设置成CSRs[mstatus].MPP （这里MPP，在上面已经设置为了 3）
     * 3. 将CSRs[mstatus].MIE设置成CSRs[mstatus].MPIE
     */
    mret
