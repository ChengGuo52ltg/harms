import tkinter as tk
from tkinter import ttk, messagebox, Menu
from tkinter import simpledialog
import harmat as hm
from tabulate import tabulate  # 需要安装tabulate库来格式化表格数据
import statistics

# Modes
MODE_NONE = 0

MODE_AG_NODE = 1
MODE_AG_ARC = 2
MODE_AG_CLEAR = 3
MODE_AG_ANALYSIS = 4
MODE_AG_METRICS = 5

MODE_AT_VUL = 3
MODE_AT_ARC = 4
MODE_AT_AND = 5
MODE_AT_OR = 6
MODE_AT_CLEAR = 7

# Node - type
NODE_HOST = 0
NODE_ATTACKER = 1
NODE_TARGET = 2

class GUI:
    def __init__(self):
        self.client = None
        self.root = tk.Tk()
        self.root.title('Welcome to HARMs!')
        self.root.geometry('700x450')

        # Style setting
        self.style = ttk.Style(self.root)
        self.style.configure('.', font=("Comic Sans MS", 12))
        self.style_active = ttk.Style(self.root)
        self.style_active.configure('A.TButton', background='yellow', padding=(5, 10))
        self.style_default = ttk.Style(self.root)
        self.style_default.configure('D.TButton', background='white', padding=(5, 10))
        
        # ---------------------------------
        self.mode = None

        # 工具栏 Menu
        self.menubar = Menu(self.root, tearoff=0)
        self.root.config(menu=self.menubar)
        # "File"
        file_menu = Menu(self.menubar, tearoff=0)
        file_menu.add_command(label="Save")
        file_menu.add_command(label="Save As...")
        file_menu.add_command(label="Create New")
        file_menu.add_command(label="Open File...")
        file_menu.add_command(label="Open Recent")
        file_menu.add_command(label="Exit",command=self.root.destroy)
        # "Edit"
        edit_menu = Menu(self.menubar, tearoff=0)
        edit_menu.add_command(label="Undo")
        edit_menu.add_command(label="Redo")
        # "View
        view_menu = Menu(self.menubar, tearoff=0)

        self.menubar.add_cascade(label="File", menu=file_menu)
        self.menubar.add_cascade(label="Edit", menu=edit_menu)
        self.menubar.add_cascade(label="View", menu=view_menu)
        self.menubar.add_cascade(label="Help")

        # Canvas 画布
        self.canvas = tk.Canvas(
            self.root,
            width=550,
            height=430,
            bg="white"
        )
        self.canvas.place(x=140, y=10, anchor='nw')

        self.nodes = []  # 存储node信息，每个节点是一个元组 (x, y, id, label, name, name_id)
        self.lines = []  # 储存arc信息 (x, y, line_id, node1_id, node2_id)

        # 左键功能
        self.canvas.bind("<Button-1>", self.AG_left_click)
        # 右键功能
        self.canvas.bind("<Button-3>", self.AG_right_click)
    
        # 创建右键Node菜单
        self.node_menu = Menu(self.root, tearoff=0)
        self.node_menu.add_command(label="Set as attacker", command=self.set_attacker)
        self.node_menu.add_command(label="Set as target", command=self.set_target)
        self.node_menu.add_command(label="Open Lower Layer", command=self.open_attack_tree)
        self.node_menu.add_command(label="Rename", command=self.rename_node)
        # self.opened_node_id = None

        # arc - 用于存储两个选定的节点
        self.AG_arc_selected2 = []
        self.AT_arc_selected2 = [] # [(id,tags),(id,tags)]

        # Buttons
        self.btn_node = ttk.Button(
            self.root,
            text='Node',
            style='D.TButton',
            command=self.mode_AG_node)
        
        self.btn_arc = ttk.Button(
            self.root,
            text='Arc',
            style='D.TButton',
            command=self.mode_AG_arc)
        
        self.btn_clear = ttk.Button(
            self.root,
            text='Clear',
            style='D.TButton',
            command=self.AG_clear)
        
        self.btn_analysis = ttk.Button(
            self.root,
            text='Analysis',
            style='D.TButton',
            command=self.AG_analysis
        )
        
        self.btn_metrics = ttk.Button(
            self.root,
            text='Metrics',
            style='D.TButton',
            command=self.AG_metrics
        )
        
        self.btn_node.place(x=20, y=40, anchor='nw')
        self.btn_arc.place(x=20, y=100, anchor='nw')
        self.btn_clear.place(x=20, y=160, anchor='nw')
        self.btn_analysis.place(x=20, y=260, anchor='nw')
        self.btn_metrics.place(x=20, y=320, anchor='nw')

# --------------------------------------------------------------------------- Modes
    def mode_AG_node(self):
        if self.mode != MODE_AG_NODE: #选中mode模式
            self.mode = MODE_AG_NODE
            self.btn_node.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_arc.config(style='D.TButton')
            self.btn_clear.config(style='D.TButton')
            self.btn_analysis.config(style='D.TButton')
            self.btn_metrics.config(style='D.TButton')
        else: # 再按一次 取消node模式
            self.mode = MODE_NONE
            self.btn_node.config(style='D.TButton')
    
    def mode_AG_arc(self):
        if self.mode != MODE_AG_ARC:
            self.mode = MODE_AG_ARC
            self.btn_arc.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_node.config(style='D.TButton')
            self.btn_clear.config(style='D.TButton')
            self.btn_analysis.config(style='D.TButton')
            self.btn_metrics.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_arc.config(style='D.TButton')

    def mode_AT_vul(self):
        if self.mode != MODE_AT_VUL:
            self.mode = MODE_AT_VUL
            self.btn_AT_vul.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_AT_AND.config(style='D.TButton')
            self.btn_AT_OR.config(style='D.TButton')
            self.btn_AT_arc.config(style='D.TButton')
            self.btn_AT_clear.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_AT_vul.config(style='D.TButton')

    def mode_AT_AND(self):
        if self.mode != MODE_AT_AND:
            self.mode = MODE_AT_AND
            self.btn_AT_AND.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_AT_vul.config(style='D.TButton')
            self.btn_AT_OR.config(style='D.TButton')
            self.btn_AT_arc.config(style='D.TButton')
            self.btn_AT_clear.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_AT_AND.config(style='D.TButton')

    def mode_AT_OR(self):
        if self.mode != MODE_AT_OR:
            self.mode = MODE_AT_OR
            self.btn_AT_OR.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_AT_vul.config(style='D.TButton')
            self.btn_AT_AND.config(style='D.TButton')
            self.btn_AT_arc.config(style='D.TButton')
            self.btn_AT_clear.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_AT_OR.config(style='D.TButton')

    def mode_AT_arc(self):
        if self.mode != MODE_AT_ARC:
            self.mode = MODE_AT_ARC
            self.btn_AT_arc.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_AT_vul.config(style='D.TButton')
            self.btn_AT_AND.config(style='D.TButton')
            self.btn_AT_OR.config(style='D.TButton')
            self.btn_AT_clear.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_AT_arc.config(style='D.TButton')

    def mode_AT_clear(self):
        if self.mode != MODE_AT_CLEAR:
            self.mode = MODE_AT_CLEAR
            self.btn_AT_clear.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_AT_vul.config(style='D.TButton')
            self.btn_AT_AND.config(style='D.TButton')
            self.btn_AT_OR.config(style='D.TButton')
            self.btn_AT_arc.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_AT_clear.config(style='D.TButton')
    # ---------------------------------------------------------------------------
    
    def AG_left_click(self, event):
        x, y = event.x, event.y

        if self.mode == MODE_AG_NODE:
            # NODE: 左键单击画布来添加节点，通过右键单击节点来删除它。节点以蓝色圆点的形式表示。
            
            node_id = self.canvas.create_oval(x - 10, y - 10, x + 10, y + 10, fill="light blue")
            label = NODE_HOST
            name = 'Host ' + str(len(self.nodes)+1)
            
            # 添加name
            name_id = self.canvas.create_text(x, y + 20, text=name, fill="black", anchor="center",tags="name")
            
            self.nodes.append((x, y, node_id, label, name, name_id))
            print("add node ", node_id, "info:(",x, y, node_id, label, name,")")

        elif self.mode == MODE_AG_ARC:
            # ARC: 绘制线条 - 选中点
            closest_node = self.canvas.find_closest(x, y)
            if closest_node:
                node_id = closest_node[0]
                self.AG_arc_selected2.append(node_id)
                print("select node for arc",node_id)
                if len(self.AG_arc_selected2) == 2: # 选定了两个节点，绘制线条
                    node1_id, node2_id = self.AG_arc_selected2
                    line_id = self.draw_arrow_line(node1_id, node2_id)
                    # 储存line
                    values = x, y, line_id, node1_id, node2_id
                    self.lines.append(values)
                    print("print arc", line_id, "from", node1_id, "to", node2_id)
                    # 清空
                    self.AG_arc_selected2 = []

    def AG_right_click(self, event):
        x, y = event.x, event.y

        if self.mode == MODE_AG_NODE:
            # NODE: 通过右键单击节点来删除节点
            closest_node = self.canvas.find_closest(x, y)
            if closest_node:
                node_id = closest_node[0]
                nodes = [node for node in self.nodes if node[2] == node_id]
                node = nodes[0]
                name_id = node[5]
                self.canvas.delete(node_id)
                self.canvas.delete(name_id)
                # 从self.nodes列表中删除了具有指定vul_id的元素
                self.nodes[:] = [node for node in self.nodes if node[2] != node_id] 
                print("delete node ", node_id)

        elif self.mode == MODE_NONE:
            # NONE: 不在任何模式下，右键选中node弹出菜单
            closest_node = self.canvas.find_closest(x, y)
            if closest_node:
                node_id = closest_node[0] # 右击->获取最近的node_id
                # self.opened_node_id = node_id # 储存打开的node_id
                self.node_menu.post(event.x_root, event.y_root)  # 在鼠标位置显示右键菜单
                # 将右键菜单关联到当前节点
                for i, node in enumerate(self.nodes):
                    if node[2] == node_id: # 对每一个node: (x, y, id, label, name)
                        self.active_node_index = i # 第几个
                        print('show menu of node: ', node, ' id:', node_id)
                        break
    
    # ---------------------------------------------------------------------------
    def set_attacker(self):
        if hasattr(self, "active_node_index"):
            # 属性,name设置
            new_name = "Attacker"
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:3], NODE_ATTACKER, new_name, *self.nodes[self.active_node_index][5:])
            # 删除原来的name_id, update text
            self.canvas.delete(self.nodes[self.active_node_index][5]) # 删除text
            x = self.nodes[self.active_node_index][0]
            y = self.nodes[self.active_node_index][1]
            new_name_id = self.canvas.create_text(x, y + 20, text=new_name, fill="black", anchor="center")
            # 替换成新的name_id
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:5], new_name_id)
            print("attacker: ", self.nodes[self.active_node_index])
            # 改变颜色
            item_id = self.nodes[self.active_node_index][2]
            self.canvas.itemconfig(item_id, fill="pink")
        
    def set_target(self):
        if hasattr(self, "active_node_index"):
            new_name = "Target"
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:3], NODE_TARGET, new_name, *self.nodes[self.active_node_index][5:])
            self.canvas.delete(self.nodes[self.active_node_index][5])
            x = self.nodes[self.active_node_index][0]
            y = self.nodes[self.active_node_index][1]
            new_name_id = self.canvas.create_text(x, y + 20, text=new_name, fill="black", anchor="center")
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:5], new_name_id)
            print("target: ", self.nodes[self.active_node_index])
            # 改变颜色
            item_id = self.nodes[self.active_node_index][2]
            self.canvas.itemconfig(item_id, fill="light green")
    
    def rename_node(self):
        if hasattr(self, "active_node_index"):
            # 属性,name设置
            new_name = simpledialog.askstring("Rename", "Enter a new name:")
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:3], NODE_HOST, new_name, *self.nodes[self.active_node_index][5:])
            # 删除原来的name_id, update text
            self.canvas.delete(self.nodes[self.active_node_index][5]) # 删除text
            x = self.nodes[self.active_node_index][0]
            y = self.nodes[self.active_node_index][1]
            new_name_id = self.canvas.create_text(x, y + 20, text=new_name, fill="black", anchor="center")
            # 替换成新的name_id
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:5], new_name_id)
            print("rename: ", self.nodes[self.active_node_index])


    # 绘制带箭头的直线
    def draw_arrow_line(self, node1_id, node2_id):
        # 获取节点1的圆心坐标
        x1, y1 = self.get_node_center(node1_id)
        # 获取节点2的圆心坐标
        x2, y2 = self.get_node_center(node2_id)

        # 调整起始点和结束点的坐标，分别向中心点靠近一定的距离
        line_length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        shorten_distance = 20  # 设置要缩短的距离
        if line_length > shorten_distance:
            ratio = shorten_distance / line_length
            x1_shortened = x1 + (x2 - x1) * ratio
            y1_shortened = y1 + (y2 - y1) * ratio
            x2_shortened = x2 - (x2 - x1) * ratio
            y2_shortened = y2 - (y2 - y1) * ratio
        else:
            # 如果直线太短，不进行缩短
            x1_shortened, y1_shortened = x1, y1
            x2_shortened, y2_shortened = x2, y2

        # 绘制直线
        line_id = self.canvas.create_line(
            x1_shortened, y1_shortened, x2_shortened, y2_shortened,
            arrow=tk.LAST, width=2, fill="black")
        return line_id
        # 可以存储线条的 ID 或其他信息，以便将来对线条进行管理或删除
        # self.lines.append(line_id)

    # 获取节点的圆心坐标
    def get_node_center(self, node_id):
        # 获取节点的坐标范围
        x1, y1, x2, y2 = self.canvas.coords(node_id)
        # 计算圆心坐标
        x_center = (x1 + x2) / 2
        y_center = (y1 + y2) / 2
        return x_center, y_center
    
    def AG_clear(self):
        # 恢复界面/模式
        self.mode = MODE_NONE
        self.btn_node.config(style='D.TButton')
        self.btn_arc.config(style='D.TButton')
        # 清除数据
        self.canvas.delete("all")
        self.nodes = []
        print("clear. now nodes list: ", self.nodes)
    
    def AG_metrics(self):
        return
    
    def AG_analysis(self):
        # initialise the harm
        h = hm.Harm()
        # create the top layer of the harm
        h.top_layer = hm.AttackGraph()
        # hosts 查看目前的nodes个数
        # 除去attacker(label==1)
        count_expect_attacker = len([node for node in self.nodes if node[3] != 1])
        hosts = [hm.Host("Host {}".format(i)) for i in range(count_expect_attacker)]
        print(hosts)
        print(self.nodes)

        # 设置 vulnerabilities
        # 1. 检查self.vulnerabilities, node_id - host
        # 2. 对每一个设置好的host 添加vul; 设置好and or gate
        # 3. set attacker, target
        # 4. set arcs
        # 5. flowup()
        # 6. report analysis

        # then we will make a basic attack tree for each host
        for host in hosts:
            host.lower_layer = hm.AttackTree()
            # We will make two vulnerabilities and give some metrics
            vulnerability1 = hm.Vulnerability('CVE-0000', values = {
                'risk' : 10,
                'cost' : 4,
                'probability' : 0.5,
                'impact' : 12
            })
            vulnerability2 = hm.Vulnerability('CVE-0001', values = {
                'risk' : 1,
                'cost' : 5,
                'probability' : 0.2,
                'impact' : 2
            })
            # basic_at creates just one OR gate and puts all vulnerabilites
            # the children nodes
            host.lower_layer.basic_at([vulnerability1, vulnerability2])

        # Now we will create an Attacker. This is not a physical node but it exists to describe
        # the potential entry points of attackers.
        attacker = hm.Attacker() 

        # To add edges we simply use the add_edge function
        # here h[0] refers to the top layer
        # add_edge(A,B) creates a uni-directional from A -> B.

        # 默认host[0]是attacker

        h[0].add_edge(attacker, hosts[1]) 
        h[0].add_edge(attacker, hosts[2])
        h[0].add_edge(hosts[1], hosts[2])  

        # Now we set the attacker and target
        h[0].source = attacker
        h[0].target = hosts[2]

        # do some flow up
        h.flowup()

        # Now we will run some metrics
        result = hm.HarmSummary(h).show()

        popup = tk.Toplevel(self.root)
        popup.title("Pop-up Window")

        label = tk.Label(popup)
        label.pack(padx=20, pady=20)

        # 创建一个多行文本输入框
        text_input = tk.Text(popup, wrap=tk.WORD, width=60, height=30)
        text_input.pack(padx=20, pady=20)

        long_text = """Metrics              Values\n
        -----------------------  ---------\n
        Number of hosts                             3\n
        Risk                                       20\n
        Cost                                        4\n
        Mean of attack path lengths                 1.5\n
        Mode of attack path lengths                 2\n
        Standard Deviation of attack path lengths   0.707107\n
        Shortest attack path length                 1\n
        Return on Attack                            5\n
        Density                                     0.5\n
        Probability of attack success               0.6"""
        text_input.insert(tk.END, long_text)

        close_button = tk.Button(popup, text="Close", command=popup.destroy)
        close_button.pack()

    # --------------------------------- Attack tree - Lower layer ----------

    def open_attack_tree(self):
        if hasattr(self, "active_node_index"):
            global AT_window
            AT_window = tk.Toplevel(self.root)
            AT_window.title("Attack Tree of " + str(self.nodes[self.active_node_index][4]))
            AT_window.geometry('700x450')

            # Buttons
            self.btn_AT_vul = ttk.Button(
                AT_window,
                text='Vul',
                style='D.TButton',
                command=self.mode_AT_vul)
                
            self.btn_AT_arc = ttk.Button(
                AT_window,
                text='Arc',
                style='D.TButton',
                command=self.mode_AT_arc)
            
            self.btn_AT_AND = ttk.Button(
                AT_window,
                text='AND Gate',
                style='D.TButton',
                command=self.mode_AT_AND)
            
            self.btn_AT_OR = ttk.Button(
                AT_window,
                text='OR Gate',
                style='D.TButton',
                command=self.mode_AT_OR)
            
            self.btn_AT_clear = ttk.Button(
                AT_window,
                text='Clear',
                style='D.TButton',
                command=self.mode_AT_clear
            )
            
            self.btn_AT_vul.place(x=20, y=40, anchor='nw')
            self.btn_AT_arc.place(x=20, y=100, anchor='nw')
            self.btn_AT_AND.place(x=20, y=160, anchor='nw')
            self.btn_AT_OR.place(x=20, y=220, anchor='nw')
            self.btn_AT_clear.place(x=20, y=280, anchor='nw')

            # Canvas 画布
            self.AT_canvas = tk.Canvas(
                AT_window,
                width=550,
                height=430,
                bg="white"
            )
            self.AT_canvas.place(x=140, y=10, anchor='nw')

            self.vulnerabilities = []  # 用于存储漏洞信息的列表 
            # [x, y, vul_id, 属于的node_id, input_info]
            # each -> ["Name","Risk","Probability","Cost","Impact"]
            self.andgate = [] # 储存 [x, y, and gate id]
            self.orgate = [] # 储存 [x, y, or_gate_id, or_gate_half_id]
        
            self.AT_canvas.bind("<Button-1>", self.AT_left_click)
            self.AT_canvas.bind("<Button-3>", self.AT_right_click)

    # --------------------------------------------------------------
    def AT_left_click(self, event):
        x, y = event.x, event.y
        # VUL: 添加Vul
        if self.mode == MODE_AT_VUL:
            # 弹出输入信息框，获取用户输入
            self.vul_info = None
            self.get_vulnerability_info(x,y)
            # save->保存->根据vul_info["Name"]创建文本；cancel->关闭界面
            
        # AND: 添加 and gate
        elif self.mode == MODE_AT_AND:
            radius = 30  # AND GATE 半径 - 决定大小
            # 计算半圆的起始角度和结束角度
            start_angle = 0
            end_angle = 180

            # 绘制半圆形 AND GATE
            and_gate_id = self.AT_canvas.create_arc(
                x - radius, y - radius, x + radius, y + radius,
                start=start_angle, extent=end_angle,
                outline="black", fill="white",
                tags='and_gate_tag')
            print('add AND', and_gate_id)
            
            values = x, y, and_gate_id
            self.andgate.append(values)
            
        # OR: 添加 or gate
        elif self.mode == MODE_AT_OR:
            radius_1 = 30  # OR GATE 半径
            radius_2 = 15  
            # 计算半圆的起始角度和结束角度
            start_angle = 0
            end_angle = 180

            # 绘制半圆形 OR GATE
            or_gate_id = self.AT_canvas.create_arc(
                x - radius_1, y - radius_1, x + radius_1, y + radius_1,
                start=start_angle, extent=end_angle,
                outline="black",
                style=tk.ARC,
                tags='or_gate_tag')

            # 绘制连接线 OR GATE
            or_gate_half_id = self.AT_canvas.create_arc(
                x - radius_1, y - radius_2, x + radius_1, y + radius_2,
                start=0, extent=180,
                outline="black",
                style=tk.ARC,
                tags='or_gate_half_tag')
            
            print('add OR', or_gate_id, "+", or_gate_half_id)
            
            values = x, y, or_gate_id, or_gate_half_id
            self.orgate.append(values)

        # ARC: 添加 ARC
        elif self.mode == MODE_AT_ARC:
            # 1.最近的元素
            closest_element_id = self.AT_canvas.find_closest(x, y) # 最近的
            closest_element_tags = self.AT_canvas.gettags(closest_element_id)
            if closest_element_id:
                element1_id = closest_element_id[0]
                element_tags = closest_element_tags[0]
                # 2.保存进 AG_arc_selected2，保存id和tag
                values = element1_id, element_tags
                self.AG_arc_selected2.append(values)
                print("select element", values)
                # 3.满了两个 (必须是 vul->门,或者 门->门)
                if len(self.AG_arc_selected2) == 2:
                    element1_id, element1_tag = self.AG_arc_selected2[0]
                    element2_id, element2_tag = self.AG_arc_selected2[1]
                    print("draw between", element1_id, element2_id)
                    # if 'vul_tag' not in element2_tag:
                    # 4.绘制线条
                    self.draw_arc(element1_id, element2_id, element1_tag, element2_tag)
                    self.AG_arc_selected2 = []
                    
    def draw_arc(self, id_1, id_2, tag_1, tag_2):
        # 获取元素中心坐标
        x1, y1 = self.get_element_center(id_1, tag_1)
        x2, y2 = self.get_element_center(id_2, tag_2)
        # 调整起始点和结束点的坐标，分别向中心点靠近一定的距离
        line_length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        shorten_distance = 30  # 设置要缩短的距离
        if line_length > shorten_distance:
            ratio = shorten_distance / line_length
            x1_shortened = x1 + (x2 - x1) * ratio
            y1_shortened = y1 + (y2 - y1) * ratio
            x2_shortened = x2 - (x2 - x1) * ratio
            y2_shortened = y2 - (y2 - y1) * ratio
        else:
            # 如果直线太短，不进行缩短
            x1_shortened, y1_shortened = x1, y1
            x2_shortened, y2_shortened = x2, y2
        # 绘制直线
        line_id = self.AT_canvas.create_line(
            x1_shortened, y1_shortened, x2_shortened, y2_shortened,
            arrow=tk.LAST, width=2, fill="black")
        # self.lines.append(line_id)
    
    def get_element_center(self, id, tag):
        # 获取坐标范围
        if 'vul_tag' in tag:
            x1, y1, x2, y2 = self.AT_canvas.bbox(id)
        else:
            x1, y1, x2, y2 = self.AT_canvas.coords(id)
        # 计算圆心坐标
        x_center = (x1 + x2) / 2
        y_center = (y1 + y2) / 2
        return x_center, y_center

    def AT_right_click(self, event):
        x, y = event.x, event.y

        # VUL: 删除Vul
        if self.mode == MODE_AT_VUL:
            vul_id = 0
            closest_element_id = self.AT_canvas.find_closest(x, y) # 最近的
            element_tags = self.AT_canvas.gettags(closest_element_id)
            if "vul_tag" in element_tags:
                vul_id = closest_element_id[0]
            if vul_id:
                self.AT_canvas.delete(vul_id)
                self.vulnerabilities[:] = [vul for vul in self.vulnerabilities if vul[2] != vul_id]
                print("delete vul ", vul_id, ' from node x ')
        
        # AND: 删除 AND gate
        elif self.mode == MODE_AT_AND:
            and_id = 0
            closest_element_id = self.AT_canvas.find_closest(x, y) # 最近的
            element_tags = self.AT_canvas.gettags(closest_element_id)
            if "and_gate_tag" in element_tags:
                and_id = closest_element_id[0]
            if and_id:
                self.AT_canvas.delete(and_id)
                self.andgate[:] = [andgate for andgate in self.andgate if andgate[2] != and_id]
                print("delete AND ", and_id)
                print("current and gates:", self.andgate)

        # OR: 删除 OR gate
        elif self.mode == MODE_AT_OR:
            or_id = 0
            closest_or_half_id = 0
            closest_element_id = self.AT_canvas.find_closest(x, y) # 最近的
            element_tags = self.AT_canvas.gettags(closest_element_id)
            if "or_gate_tag" in element_tags:
                or_id = closest_element_id[0]
            if or_id:
                self.AT_canvas.delete(or_id)
                closest_or_half_id = self.AT_canvas.find_closest(x, y) # 最近的or gate half
                closest_or_half_tags = self.AT_canvas.gettags(closest_or_half_id)
                if "or_gate_half_tag" in closest_or_half_tags:
                    or_half_id = closest_or_half_id
                if closest_or_half_id:
                    self.AT_canvas.delete(closest_or_half_id)

                    self.orgate[:] = [orgate for orgate in self.orgate if orgate[2] != or_id]
                    print("delete OR ", or_id, '+', or_half_id)
                    print("current or gates:", self.orgate)

    def get_vulnerability_info(self, x, y):
        # 弹出新界面,获取vulnerability info
        global vul_info_window
        vul_info_window = tk.Toplevel(AT_window)
        vul_info_window.title("Edit Vulnerability")
        vul_info_window.geometry('300x300')
        # Labels
        self.lbl_vul_name = ttk.Label(vul_info_window,text='Name:')
        self.lbl_vul_risk = ttk.Label(vul_info_window,text='Risk:')
        self.lbl_vul_prob = ttk.Label(vul_info_window,text='Probability:')
        self.lbl_vul_cost = ttk.Label(vul_info_window,text='Cost:')
        self.lbl_vul_impt = ttk.Label(vul_info_window,text='Impact:')
        # Entries
        self.entry_name = ttk.Entry(vul_info_window, width=15)
        self.entry_risk = ttk.Entry(vul_info_window, width=15)
        self.entry_prob = ttk.Entry(vul_info_window, width=15)
        self.entry_cost = ttk.Entry(vul_info_window, width=15)
        self.entry_impt = ttk.Entry(vul_info_window, width=15)
        # Buttons
        self.btn_vul_save = ttk.Button(
            vul_info_window,
            text='Save',
            width=10,
            style='D.TButton',
            command=lambda x=x, y=y: self.vul_save(x, y)
        )
        self.btn_vul_cancel = ttk.Button(
            vul_info_window,
            text='Cancel',
            width=10,
            style='D.TButton',
            command=self.vul_cancel
        )
        self.btn_vul_save.place(x=30, y=250, anchor='nw')
        self.btn_vul_cancel.place(x=160, y=250, anchor='nw')
        self.lbl_vul_name.place(x=30, y=30, anchor='nw')
        self.lbl_vul_risk.place(x=30, y=70, anchor='nw')
        self.lbl_vul_prob.place(x=30, y=110, anchor='nw')
        self.lbl_vul_cost.place(x=30, y=150, anchor='nw')
        self.lbl_vul_impt.place(x=30, y=190, anchor='nw')
        self.entry_name.place(x=140, y=30, anchor='nw')
        self.entry_risk.place(x=140, y=70, anchor='nw')
        self.entry_prob.place(x=140, y=110, anchor='nw')
        self.entry_cost.place(x=140, y=150, anchor='nw')
        self.entry_impt.place(x=140, y=190, anchor='nw')

    def vul_save(self, x, y):
        # 获取entry里的值
        name = self.entry_name.get()
        risk_input = self.entry_risk.get()
        prob_input = self.entry_prob.get()
        cost_input = self.entry_cost.get()
        impt_input = self.entry_impt.get()

        risk = float(0)
        prob = float(0)
        cost = float(0)
        impt = float(0)
        try:
            risk = float(risk_input)
            prob = float(prob_input)
            cost = float(cost_input)
            impt = float(impt_input)
        except ValueError:
            print("invalid")

        # 赋值保存
        vul_info = {"Name": name, "Risk": risk, "Probability": prob, "Cost": cost, "Impact": impt}
        
        vul_info_window.destroy()
        # vul_info = {"Name": name, "Risk": float(risk), "Probability": float(prob), "Cost": float(cost), "Impact": float(impt)}
        if vul_info:
                text = vul_info["Name"] # 创建文本
                vul_id = self.AT_canvas.create_text(
                    x, y, text=text, 
                    font=("Arial", 12), anchor="nw",
                    tags="vul_tag")
                node_id = self.nodes[self.active_node_index][2]

        values = x, y, vul_id, node_id, vul_info # 存进列表
        self.vulnerabilities.append(values)
        print("vul save end:", self.vul_info)
        print(self.vulnerabilities)

    
    def vul_cancel(self):
        # 关闭窗口，不显示vul
        print(self.vulnerabilities)
        vul_info_window.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    app = GUI()
    app.run()