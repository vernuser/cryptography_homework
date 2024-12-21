import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess
from sender import send_file
from receiver import receive_file
from utils import load_key

class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("文件传输系统")
        self.root.geometry("800x900")  # 增大窗口尺寸
        self.root.resizable(False, False)  # 禁止调整窗口大小

        # 设置窗口背景色
        self.root.configure(bg="#f5f5f5")

        # 加载密钥
        self.sender_private_key = load_key('sender_private.pem')
        self.receiver_public_key = load_key('receiver_public.pem')
        self.receiver_private_key = load_key('receiver_private.pem')
        self.sender_public_key = load_key('sender_public.pem')

        # 创建UI
        self.create_main_frame()

    def create_main_frame(self):
        # 主界面，选择发送方或接收方
        self.main_frame = tk.Frame(self.root, bg="#f5f5f5")
        self.main_frame.pack(fill="both", expand=True)

        self.selection_var = tk.StringVar(value="sender")  # 默认选择发送方

        # 选择发送方或接收方
        tk.Radiobutton(self.main_frame, text="我是发送方", variable=self.selection_var, value="sender", font=("Arial", 16),
                       bg="#f5f5f5", command=self.switch_mode).pack(pady=20)
        tk.Radiobutton(self.main_frame, text="我是接收方", variable=self.selection_var, value="receiver", font=("Arial", 16),
                       bg="#f5f5f5", command=self.switch_mode).pack(pady=20)

        # 按钮：生成密钥
        tk.Button(self.main_frame, text="生成公钥/私钥对", font=("Arial", 16), bg="#8BC34A", fg="white", relief="raised", bd=4,
                  width=20, height=2, command=self.generate_keys).pack(pady=20)

        # 初始显示发送方界面
        self.sender_frame = None
        self.receiver_frame = None
        self.switch_mode()

    def switch_mode(self):
        """切换模式（发送方或接收方）"""
        # 清空当前界面
        if self.sender_frame:
            self.sender_frame.destroy()
        if self.receiver_frame:
            self.receiver_frame.destroy()

        mode = self.selection_var.get()

        if mode == "sender":
            self.create_sender_frame()
        elif mode == "receiver":
            self.create_receiver_frame()

    def create_sender_frame(self):
        """创建发送方界面"""
        self.sender_frame = tk.LabelFrame(self.main_frame, text="发送文件", padx=30, pady=30, bg="#ffffff", font=("Arial", 14, "bold"))
        self.sender_frame.pack(padx=30, pady=30, fill="both", expand=True)

        self.filename_var = tk.StringVar()

        # 选择文件按钮
        tk.Button(self.sender_frame, text="选择文件", command=self.select_file,
                  font=("Arial", 16), bg="#4CAF50", fg="white", relief="raised", bd=4,
                  width=20, height=3, activebackground="#45a049").pack(padx=10, pady=15)

        # 显示文件路径
        self.filename_entry = tk.Entry(self.sender_frame, textvariable=self.filename_var, width=60, font=("Arial", 14), state='readonly', bd=3)
        self.filename_entry.pack(padx=10, pady=15)

        # 输入接收方 IP 和端口
        tk.Label(self.sender_frame, text="接收方 IP:", font=("Arial", 14), bg="#ffffff").pack(pady=10)
        self.receiver_ip_entry = tk.Entry(self.sender_frame, width=40, font=("Arial", 14), bd=3)
        self.receiver_ip_entry.pack(pady=10)
        self.receiver_ip_entry.insert(0, "192.168.1.1")

        tk.Label(self.sender_frame, text="接收方端口:", font=("Arial", 14), bg="#ffffff").pack(pady=10)
        self.receiver_port_entry = tk.Entry(self.sender_frame, width=40, font=("Arial", 14), bd=3)
        self.receiver_port_entry.pack(pady=10)
        self.receiver_port_entry.insert(0, "12345")

        # 增大按钮大小
        send_button = tk.Button(self.sender_frame, text="发送文件", command=self.send_file,
                                font=("Arial", 16), bg="#007BFF", fg="white", relief="raised", bd=4,
                                width=25, height=3, activebackground="#0056b3")
        send_button.pack(padx=10, pady=30, fill='x')

    def create_receiver_frame(self):
        """创建接收方界面"""
        self.receiver_frame = tk.LabelFrame(self.main_frame, text="接收文件", padx=30, pady=30, bg="#ffffff", font=("Arial", 14, "bold"))
        self.receiver_frame.pack(padx=30, pady=30, fill="both", expand=True)

        # 接收文件按钮
        receive_button = tk.Button(self.receiver_frame, text="接收文件", command=self.receive_file,
                                   font=("Arial", 16), bg="#FF5722", fg="white", relief="raised", bd=4,
                                   width=25, height=3, activebackground="#e64a19")
        receive_button.pack(padx=10, pady=30, fill='x')

    def generate_keys(self):
        """调用 generate_key.py 生成公钥和私钥"""
        try:
            # 使用 subprocess 调用 generate_key.py 生成密钥对
            subprocess.run(["python", "generate_key.py"], check=True)
            messagebox.showinfo("成功", "公钥和私钥已生成！")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("错误", f"密钥生成失败：{e}")

    def select_file(self):
        """选择文件"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.filename_var.set(file_path)

    def send_file(self):
        """发送文件"""
        filename = self.filename_var.get()
        if not filename or not os.path.exists(filename):
            messagebox.showerror("错误", "请选择有效的文件！")
            return

        receiver_ip = self.receiver_ip_entry.get()
        receiver_port = self.receiver_port_entry.get()

        if not receiver_ip or not receiver_port:
            messagebox.showerror("错误", "请填写接收方的 IP 和端口！")
            return

        try:
            # 调用 sender.py 中的 send_file 函数
            send_file(filename, receiver_ip, int(receiver_port), self.receiver_public_key, self.sender_private_key)
            messagebox.showinfo("成功", "文件发送成功！")
        except Exception as e:
            messagebox.showerror("错误", f"文件发送失败：{e}")

    def receive_file(self):
        """接收文件"""
        try:
            port = 12345
            # 调用 receiver.py 中的 receive_file 函数
            receive_file(port, self.receiver_private_key, self.sender_public_key)
            messagebox.showinfo("成功", "文件接收成功！")
        except Exception as e:
            messagebox.showerror("错误", f"文件接收失败：{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()
