from bcc import BPF

# eBPF程序代码
bpf_text = '''
int kprobe__sys_clone(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
'''

# 主函数
def main():
    # 加载eBPF程序
    b = BPF(text=bpf_text)

    # 打印跟踪输出
    b.trace_print()

if __name__ == "__main__":
    main()

