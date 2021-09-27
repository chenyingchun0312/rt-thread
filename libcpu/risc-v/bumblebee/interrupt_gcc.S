/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 */
 
#include "cpuport.h"

 .section      .text.entry
  .align 6     /* In ECLIC mode, the trap entry must be 64bytes aligned */
  .global irq_entry
irq_entry:

    /* save all from thread context */
    /* 比如，从任务A切换到的中断执行 */

    /* 当前 CPU 的 sp 指针，指向的是任务A的任务栈中的某个地址 */
    /* 将sp指针向下移动32个寄存器长度，用来保存当前 CPU 的一些寄存器到任务A的任务栈中 */
    addi sp, sp, -32 * REGBYTES

    /* 将 CPU 的 x1 ,也就是 ra 寄存器， 保存到任务A的任务栈中的 ra 寄存器中*/
    STORE x1,   1 * REGBYTES(sp)

    /* t0寄存器的值赋值为0x80 */
    li    t0,   0x80

    /* 将 t0 寄存器的值，保存到任务A的任务栈中的 mstatus 寄存器中 */
    STORE t0,   2 * REGBYTES(sp)

    /* 将 CPU 的其他寄存器的值，保存到任务A的任务栈中的 其他的寄存器中 */
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

    /* 备份 CPU 的 sp 寄存器的值到 s0 寄存器中，下面会使用s0，恢复 CPU 的寄存器 */
    move  s0, sp

    /* 在中断函数中，中断函数中调用的C函数，需要使用 sp， 这里，在中断函数中，使用的 sp 为，系统的栈资源 */
    /* switch to interrupt stack */
    la    sp, _sp

    /* interrupt handle */
    /* 注意： 在调用C函数之前,比如sp的值为0x30001000, 在执行完C函数后，sp的值还是会变成 0x30001000 */
    call  rt_interrupt_enter

    /* 将 mcause 的值，赋值给 a0 寄存器 */
    csrr  a0, mcause

    /* 将 mepc 的值，赋值给 a1 寄存器 */
    csrr  a1, mepc

    /* 将 CPU sp 寄存器的值，赋值给 a2 寄存器 */
    mv    a2, sp

    /* 下面指令，其实是bumblebee内核特有的，其实就是调用中断入口函数*/
    /* 比如，中断使用DIRECTOR模式， 那么这里可以直接写成 call irq_hanle 函数即可 */
    csrrw ra, 0x07ED, ra
    call  rt_interrupt_leave

    /* switch to from thread stack */

    /* 上面，将保存执行中断服务函数之前的CPU的寄存器到了s0所指向的位置处，当执行完中断服务函数，需要将之前的CPU寄存器，恢复一下 */
    move  sp, s0

    /* need to switch new thread */
    /* 将 rt_thread_switch_interrupt_flag 的地址值，赋值给 s0 寄存器*/
    la    s0, rt_thread_switch_interrupt_flag

    /* 将 s0 所指向的地址处的内容，取出来，赋值给 s2 寄存器，其实就是将  rt_thread_switch_interrupt_flag 的值，赋值给了 s2 寄存器*/
    lw    s2, 0(s0)

    /* 如果 s2的值，即 rt_thread_switch_interrupt_flag 值，如果不为0，则需要继续执行下一条指令，如果为0，则需要跳转到 spurious_interrupt 标号处 执行 */
    beqz  s2, spurious_interrupt
    /* clear switch interrupt flag */

    /* 将 s0 所执向的地址的内容设置为0， 也就是，将变量 rt_thread_switch_interrupt_flag 赋值为了 0 */
    sw    zero, 0(s0)

    /* 将 mepc 的值，赋值给 a0 寄存器，mepc 的值是，跳转到中断函数执行之前的 PC 指针 */
    csrr  a0, mepc

    /* 将 mpec 的值写回到任务栈中的 epc 中 */
    STORE a0, 0 * REGBYTES(sp)

    /* 将 rt_interrupt_from_thread 地址，赋值给 s0 ， 这里 rt_interrupt_from_thread 本身，表示的是from_thread线程对象的 sp 元素的地址，
     * 因此 rt_interrupt_from_thread 地址表示的是，指向 from_thread线程对象的 sp 元素的地址
     * 而 from_thread 线程对象的 sp 本身，指向的是 from_thread 的任务栈，保存，from_thread 任务被挂起时，CPU 的 寄存器以及 CSR 寄存器的值
    */
    la    s0, rt_interrupt_from_thread

    /* 将 rt_interrupt_from_thread 的值 （即from_thread对象sp元素的地址），赋值给了 s1 ，此时 s1 指向了 from_thread sp 元素 */
    LOAD  s1, 0(s0)

    /* 将当前 sp 寄存器中的值，赋值给 s1 所指向的地址处，即 from_thread 的 sp 元素的值 等于当前 */
    /* 这里，其实在恢复任务A（假设从任务A，切换到了中断函数执行）的 sp指针的值，即from_thread->sp 仍然指向了 from_thread 的任务栈 */
    STORE sp, 0(s1)


    /* 将 rt_interrupt_to_thread 的地址，赋值给 s0*/
    la    s0, rt_interrupt_to_thread

    /* 将 s0 的内容，赋值给了s1 , s0的内容，其实就是 to_thread->sp 元素的地址*/
    LOAD  s1, 0(s0)

    /* 将to_thread->sp 元素的内容，赋值给了sp，即当前CPU的sp，已经回复到指向to_thead的任务栈了 */
    LOAD  sp, 0(s1)

    /* 将to_thread的任务栈中的内容，恢复到 CPU 的寄存器中 */
    /* 这里a0的值为to_thrad恢复到运行状态时，需要执行的PC地址 */
    LOAD  a0,  0 * REGBYTES(sp)
    /* 将to_thread恢复到运行状态时，执行的PC地址赋值给mepc，当执行完mret指令后，硬件会自动将mepc的值，赋值给PC，这样 to_thread就可以顺利运行了 */
    csrw  mepc, a0

spurious_interrupt:

    /* 这里的sp 可以能 to_thread的任务栈，也可能是 from_thread的任务栈 */
    /* beqz  s2, spurious_interrupt ,如果 这里s2,即 rt_thread_switch_interrupt_flag 为0，那么，这里的sp就是from_thread的任务栈*/
    /* 如果 rt_thread_switch_interrupt_flag 为 1， 这里的sp就是 to_thread 的 任务栈了 */

    /* 恢复即将要运行的任务的任务栈信息到CPU的寄存器中 */
    LOAD  x1,   1 * REGBYTES(sp)

    /* Remain in M-mode after mret */
    li    t0, 0x00001800
    csrs  mstatus, t0
    LOAD  t0,   2 * REGBYTES(sp)
    csrs  mstatus, t0

    LOAD  x4,   4 * REGBYTES(sp)
    LOAD  x5,   5 * REGBYTES(sp)
    LOAD  x6,   6 * REGBYTES(sp)
    LOAD  x7,   7 * REGBYTES(sp)
    LOAD  x8,   8 * REGBYTES(sp)
    LOAD  x9,   9 * REGBYTES(sp)
    LOAD  x10, 10 * REGBYTES(sp)
    LOAD  x11, 11 * REGBYTES(sp)
    LOAD  x12, 12 * REGBYTES(sp)
    LOAD  x13, 13 * REGBYTES(sp)
    LOAD  x14, 14 * REGBYTES(sp)
    LOAD  x15, 15 * REGBYTES(sp)
    LOAD  x16, 16 * REGBYTES(sp)
    LOAD  x17, 17 * REGBYTES(sp)
    LOAD  x18, 18 * REGBYTES(sp)
    LOAD  x19, 19 * REGBYTES(sp)
    LOAD  x20, 20 * REGBYTES(sp)
    LOAD  x21, 21 * REGBYTES(sp)
    LOAD  x22, 22 * REGBYTES(sp)
    LOAD  x23, 23 * REGBYTES(sp)
    LOAD  x24, 24 * REGBYTES(sp)
    LOAD  x25, 25 * REGBYTES(sp)
    LOAD  x26, 26 * REGBYTES(sp)
    LOAD  x27, 27 * REGBYTES(sp)
    LOAD  x28, 28 * REGBYTES(sp)
    LOAD  x29, 29 * REGBYTES(sp)
    LOAD  x30, 30 * REGBYTES(sp)
    LOAD  x31, 31 * REGBYTES(sp)

    addi  sp, sp, 32 * REGBYTES
    mret
