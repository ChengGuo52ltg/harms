import tkinter as tk
from tkinter import ttk, messagebox, Menu
from tkinter import simpledialog

import harmat as hm
from requests import delete
from tabulate import tabulate  # 需要安装tabulate库来格式化表格数据
import statistics

# Modes
MODE_NONE = 0

MODE_AG_NODE = 1
MODE_AG_ARC = 2
MODE_AG_CLEAR = 3
MODE_AG_ANALYSIS = 4
MODE_AG_METRICS = 5

MODE_AT_VUL = 6
MODE_AT_ARC = 7
MODE_AT_AND = 8
MODE_AT_OR = 9
MODE_AT_CLEAR = 10
MODE_AT_ROOTNODE = 11

# Node - type
NODE_HOST = 0
NODE_ATTACKER = 1
NODE_TARGET = 2

# Gate if it is rootnode
GATE_IS_ROOT = 1
GATE_NOT_ROOT = 0

class GUI:
    def __init__(self):
        # self.client = None
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
        
        # track history for undo and redo
        self.history = []  # 用于存储撤销历史记录
        self.history_redo = []

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

        # ATTACK TREE:
        self.vulnerabilities = []  # 用于存储漏洞信息的列表 
        # [x, y, vul_id, 属于的node_id, input_info]
        # each -> ["Name","Risk","Probability","Cost","Impact"]
        self.andgates = [] # 储存 [x, y, and_gate_id, node_id, sub_vuls={vul_id, vul_id, ...}]
        self.orgates = [] # 储存 [x, y, or_gate_id, or_gate_half_id, node_id, sub_vuls={vul_id, vul_id, ...}]
        self.gate_lines = [] # [gate_line_id, element1_id, element2_id, element1_tag, element2_tag, node_id]


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

        self.btn_undo = ttk.Button(
            self.root,
            text='Undo',
            style='D.TButton',
            width=5,
            command=self.AG_undo
        )

        self.btn_redo = ttk.Button(
            self.root,
            text='Redo',
            style='D.TButton',
            width=5,
            command=self.AG_redo
        )

        self.btn_node.place(x=20, y=40, anchor='nw')
        self.btn_arc.place(x=20, y=100, anchor='nw')
        self.btn_undo.place(x=20, y=180, anchor='nw')
        self.btn_redo.place(x=20, y=240, anchor='nw')
        self.btn_clear.place(x=20, y=310, anchor='nw')
        self.btn_analysis.place(x=20, y=370, anchor='nw')

# --------------------------------------------------------------------------- Modes
    def mode_AG_node(self):
        if self.mode != MODE_AG_NODE: #选中mode模式
            self.mode = MODE_AG_NODE
            self.btn_node.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_arc.config(style='D.TButton')
        else: # 再按一次 取消node模式
            self.mode = MODE_NONE
            self.btn_node.config(style='D.TButton')
    
    def mode_AG_arc(self):
        if self.mode != MODE_AG_ARC:
            self.mode = MODE_AG_ARC
            self.btn_arc.config(style='A.TButton')
            # 其他按钮恢复
            self.btn_node.config(style='D.TButton')
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
            self.btn_AT_rootnode.config(style='D.TButton')
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
            self.btn_AT_rootnode.config(style='D.TButton')
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
            self.btn_AT_rootnode.config(style='D.TButton')
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
            self.btn_AT_rootnode.config(style='D.TButton')
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
            self.btn_AT_rootnode.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_AT_clear.config(style='D.TButton')

    def mode_AT_rootnode(self):
        if self.mode != MODE_AT_ROOTNODE:
            self.mode = MODE_AT_ROOTNODE
            self.btn_AT_rootnode.config(style='A.TButton')
            #
            self.btn_AT_vul.config(style='D.TButton')
            self.btn_AT_AND.config(style='D.TButton')
            self.btn_AT_OR.config(style='D.TButton')
            self.btn_AT_arc.config(style='D.TButton')
            self.btn_AT_clear.config(style='D.TButton')
        else:
            self.mode = MODE_NONE
            self.btn_AT_rootnode.config(style='D.TButton')
    # ---------------------------------------------------------------------------

    def add_node(self, x, y):
        # In attack graph, add host/node
        node_id = self.canvas.create_oval(x - 10, y - 10, x + 10, y + 10, fill="light blue")
        label = NODE_HOST
        name = 'Host ' + str(len(self.nodes)+1)
        # Add node's name
        name_id = self.canvas.create_text(x, y + 20, text=name, fill="black", anchor="center",tags="name")
        # Append the data list
        self.nodes.append((x, y, node_id, label, name, name_id))
        print("add node ", node_id, "info:(",x, y, node_id, label, name,")")

        return 1
    
    def remove_node(self, x, y):
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

            return 1
    
    def ag_add_arc(self, x, y):
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

                return 1
            else:
                return 0

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
            arrow=tk.LAST, width=2, fill="black", tags="line")
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
    
    def ag_remove_arc(self, x, y):
        lines_id = self.canvas.find_withtag("line")

        closest_line_id = None
        closest_distance = float("inf")

        # 计算最近的线条
        for line_id in lines_id:
            # 获取线条的坐标信息
            x1, y1, x2, y2 = self.canvas.coords(line_id)
            # 计算鼠标点击点到线条的距离
            distance = ((x2 - x1) * (y1 - y) - (x1 - x) * (y2 - y1)) / ((x2 - x1) ** 2 + (y2 - y1) ** 2)

            # 如果距离更近，则更新最近的线条和距离
            if abs(distance) < closest_distance:
                closest_line_id = line_id
                closest_distance = abs(distance)

        if closest_line_id is not None:
            self.canvas.delete(closest_line_id)

            # Save to history
            values = [line for line in self.lines if line[2] == closest_line_id]
            self.history.append(("ag_remove_arc", values))

            self.lines[:] = [line for line in self.lines if line[2] != closest_line_id] 
            print("delete arc", closest_line_id)
            
        
    def AG_left_click(self, event):
        x, y = event.x, event.y

        if self.mode == MODE_AG_NODE:
            # NODE: 左键单击画布来添加节点，通过右键单击节点来删除它。节点以蓝色圆点的形式表示。
            out = self.add_node(x, y)
            if out == 1:
                # Add the last node to history
                self.history.append(("add_node", self.nodes[-1]))

        elif self.mode == MODE_AG_ARC:
            # ARC: 绘制线条 - 选中点
            out = self.ag_add_arc(x, y)
            if out == 1:
                # Add the last node to history
                self.history.append(("ag_add_arc", self.lines[-1]))

    def AG_right_click(self, event):
        x, y = event.x, event.y

        if self.mode == MODE_AG_NODE:
            out = self.remove_node(x, y)
            if out == 1:
                # Add the last node to history
                self.history.append(("remove_node", (x, y)))

        elif self.mode == MODE_AG_ARC:
            self.ag_remove_arc(x, y)

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
            if new_name is not None:
                self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:3], NODE_HOST, new_name, *self.nodes[self.active_node_index][5:])
                # 删除原来的name_id, update text
                self.canvas.delete(self.nodes[self.active_node_index][5]) # 删除text
                x = self.nodes[self.active_node_index][0]
                y = self.nodes[self.active_node_index][1]
                new_name_id = self.canvas.create_text(x, y + 20, text=str(new_name), fill="black", anchor="center")
                # 替换成新的name_id
                self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:5], new_name_id)
                print("rename: ", self.nodes[self.active_node_index])
    
    def AG_clear(self):
        # Back to normal mode
        self.mode = MODE_NONE
        # Clear button state
        self.btn_node.config(style='D.TButton')
        self.btn_arc.config(style='D.TButton')
        # Clear data
        self.canvas.delete("all")
        self.nodes = []
        self.vulnerabilities = []
        self.lines = []
        self.andgates = []
        self.orgates = []
        self.gate_lines = []
        print("Clear")
    
    def AG_undo(self):
        if self.history:
            # 从历史记录中获取上一个操作
            action, values = self.history.pop()
            # 执行相应的撤销操作
            if action == "add_node":
                x = values[0]
                y = values[1]
                self.remove_node(x, y)
            elif action == "remove_node":
                x, y = values
                self.add_node(x, y)
            elif action == "ag_add_arc":
                x = values[0]
                y = values[1]
                self.ag_remove_arc(x, y)
            elif action == "ag_remove_arc":
                node1_id = values[3]
                node2_id = values[4]
                # same to add_arc
                self.draw_arrow_line(node1_id, node2_id)
                self.lines.append(values)
                print("print arc", values)

            # Add action to "Redo"
            self.history_redo.append((action, values))
    
    def AG_redo(self):
        if self.history_redo:
            # 从重做历史记录中获取下一个操作
            action, values = self.history_redo.pop()
            # 执行相应的重做操作
            if action == "add_node":
                # get x, y from values
                x, y = values[:2]
                self.add_node(x, y)
            elif action == "remove_node":
                x, y = values
                self.remove_node(x, y)
            elif action == "ag_add_arc":
                node1_id = values[3]
                node2_id = values[4]
                self.draw_arrow_line(node1_id, node2_id)
                self.lines.append(values)
                print("print arc", values)
            elif action == "ag_remove_arc":
                x = values[0]
                y = values[1]
                self.ag_remove_arc(x, y)
    
    def AG_analysis(self):
        # initialise the harm
        h = hm.Harm()
        # create the top layer of the harm
        h.top_layer = hm.AttackGraph()
        # hosts 查看目前的nodes个数
        # 除去attacker(label==1)
        self.nodes_withoutattacker = [node for node in self.nodes if node[3] != 1]
        count_expect_attacker = len(self.nodes_withoutattacker)
        hosts = [hm.Host("Host {}".format(i)) for i in range(count_expect_attacker)]
        print(hosts)
        print(self.nodes)
        print(self.nodes_withoutattacker)

        # 设置 vulnerabilities
        # 1. 检查self.vulnerabilities, node_id - host
        # 2. 对每一个设置好的host 添加vul; 设置好and or gate
        # 3. set attacker, target
        # 4. set arcs
        # 5. flowup()
        # 6. report analysis

        # for vul in self.vulnerabilities:
            # node_id = vul[3]
        print("all vuls: ",self.vulnerabilities)

        for index, host in enumerate(hosts):
            host.lower_layer = hm.AttackTree()

            # e.g. index=0
            # hosts[0]对应的self.nodes_withoutattacker[0] 的node_id是多少
            node_id = self.nodes_withoutattacker[index][2]
            print("host's node_id = ", node_id)

            # 筛选这个node_id下的vul 
            vuls = None
            vuls = [vul for vul in self.vulnerabilities if vul[3] == node_id]
            print("host's vuls = ", vuls)
            # make vuls
            # ...
            if vuls:
                at_vulnerabilities_list = []
                for vul in vuls:
                    vulnerability = None
                    vulnerability = hm.Vulnerability(vul[4]["Name"], values = {
                    'risk' : vul[4]["Risk"],
                    'cost' : vul[4]["Probability"],
                    'probability' : vul[4]["Cost"],
                    'impact' : vul[4]["Impact"]
                    })
                    if vulnerability:
                        at_vulnerabilities_list.append(vulnerability)
                print(at_vulnerabilities_list)
            
                # 筛选出这个node_id 下的gates
                and_gates = None
                and_gates = [and_gate for and_gate in self.andgates if and_gate[3] == node_id]
                print("host's and_gates = ", and_gates)
                or_gates = None
                or_gates = [or_gate for or_gate in self.orgates if or_gate[4] == node_id]
                print("host's or_gates = ", or_gates)

                # make gates
                # ...
                # 对每一个gate
                at_and_gate_list = []
                at_or_gate_list = []
                for and_gate in and_gates:
                    at_and_gate = hm.LogicGate(gatetype='and')
                    at_and_gate_list.append(at_and_gate)
                    # ROOTNODE:
                    # 如果gate是root 把logicGate连到rootnode: 直接用at_add_node
                    if and_gate[5] == GATE_IS_ROOT:
                        host.lower_layer.at_add_node(at_and_gate)

                for or_gate in or_gates:
                    at_or_gate = hm.LogicGate(gatetype='or')
                    at_or_gate_list.append(at_or_gate)
                    if or_gate[6] == GATE_IS_ROOT:
                        host.lower_layer.at_add_node(at_or_gate)

                for i, and_gate in enumerate(and_gates):
                    for element_id in and_gate[4]:
                        # 根据element_id 推出这个是vuls[?] 
                        vuls_index = None
                        andgate_index = None
                        orgate_index = None
                        for x, element_vul in enumerate(vuls):
                            if element_id == element_vul[2]:
                                vuls_index = x
                                break
                        if vuls_index is not None:
                            host.lower_layer.at_add_node(at_vulnerabilities_list[vuls_index], logic_gate=at_and_gate_list[i]) #  def at_add_node(self, node, logic_gate=None)
                            print(f"add sub_vul (id){element_id} to and gate (info){and_gate}")
                        else:
                            # 或者是哪个gate? element_id 对应哪个and_gate或or_gate
                            for y, element_and in enumerate(and_gates):
                                if element_id == element_and[2]:
                                    andgate_index = y
                                    break
                            if andgate_index is not None:
                                host.lower_layer.at_add_node(at_and_gate_list[andgate_index], logic_gate=at_and_gate_list[i])
                                print(f"add sub_and (id){element_id} to and gate (info){and_gate}")
                            else:
                                # 或者是哪个orgate
                                for z, element_or in enumerate(or_gates):
                                    if element_id == element_or[2] or element_id == element_or[3]:
                                        orgate_index = z
                                        break
                                if orgate_index is not None:
                                    host.lower_layer.at_add_node(at_or_gate_list[orgate_index], logic_gate=at_and_gate_list[i])
                                    print(f"add sub_or (id){element_id} to and gate (info){and_gate}")
                
                for i, or_gate in enumerate(or_gates):
                    for element_id in or_gate[5]:
                        vuls_index = None
                        andgate_index = None
                        orgate_index = None
                        # element_id - vul ?
                        for x, element_vul in enumerate(vuls):
                            if element_id == element_vul[2]:
                                vuls_index = x
                                break
                        if vuls_index is not None:
                            print(f"vuls_index={vuls_index}, i={i}")
                            print(f"at_vulnerabilities_list={at_vulnerabilities_list}")
                            print(at_vulnerabilities_list[vuls_index])
                            print(f"at_or_gate_list={at_or_gate_list}")
                            print(at_or_gate_list[i])
                            host.lower_layer.at_add_node(at_vulnerabilities_list[vuls_index], logic_gate=at_or_gate_list[i])
                            print(f"add sub_vul (id){element_id} to or gate (info){or_gate}")
                        # and - gate ?
                        else:
                            for y, element_and in enumerate(and_gates):
                                if element_id == element_and[2]:
                                    andgate_index = y
                                    break
                            if andgate_index is not None:
                                host.lower_layer.at_add_node(at_and_gate_list[andgate_index], logic_gate=at_or_gate_list[i])
                                print(f"add sub_and (id){element_id} to or gate (info){or_gate}")
                        # or - gate ?
                            else:
                                for z, element_or in enumerate(or_gates):
                                    if element_id == element_or[2] or element_id == element_or[3]:
                                        orgate_index = z
                                        break
                                if orgate_index is not None:
                                    host.lower_layer.at_add_node(at_or_gate_list[orgate_index], logic_gate=at_or_gate_list[i])
                                    print(f"add sub_or (id){element_id} to or gate (info){or_gate}")

        # Now we will create an Attacker. This is not a physical node but it exists to describe
        # the potential entry points of attackers.
        attacker = hm.Attacker() 

        # To add edges we simply use the add_edge function
        # here h[0] refers to the top layer
        # add_edge(A,B) creates a uni-directional from A -> B.

        # 默认host[0]是attacker
        # 根据self.lines
        for line in self.lines:
            print("For arc:", line)

            # 找出self.lines[3][4]对应的node_id - 起始、结束点
            node_id_to_find_1 = line[3]
            node_id_to_find_2 = line[4]
            # if node_id_to_find == attacker_node_id
            attacker_node_ids = [node[2] for node in self.nodes if node[3] == NODE_ATTACKER]
            if len(attacker_node_ids) != 1:
                print("more than 1 attacker")
                return
            else:
                attacker_node_id = attacker_node_ids[0]
                print("attacker_node_id = ", attacker_node_id)

            index_1 = None
            index_2 = None
            try:
                index_1 = [node[2] for node in self.nodes_withoutattacker].index(node_id_to_find_1)
                print(f"The element with node_id {node_id_to_find_1} is at Host {index_1}")
            except ValueError:
                print(f"The node_id {node_id_to_find_1} was not found in self.nodes.")
            try:
                index_2 = [node[2] for node in self.nodes_withoutattacker].index(node_id_to_find_2)
                print(f"The element with node_id {node_id_to_find_2} is at Host {index_2}")
            except ValueError:
                print(f"The node_id {node_id_to_find_2} was not found in self.nodes.")
            
            if node_id_to_find_1 == attacker_node_id: # attacker(1) --> (2)
                h[0].add_edge(attacker, hosts[index_2]) # type: ignore
                print(f"attacker --> host[{index_2}]")
            elif node_id_to_find_2 == attacker_node_id: # (1) --> attacker(2)
                print("wrong arc")
                return
            else:
                # h[0].add_edge(...)
                h[0].add_edge(hosts[index_1], hosts[index_2]) # type: ignore
                print(f"host[{index_1}] --> host[{index_2}]")

        # Now we set the attacker and target
        h[0].source = attacker # type: ignore
        # 找出哪个是target
        
        target_index = None
        for i, node in enumerate(self.nodes_withoutattacker):
            if node[3] == NODE_TARGET:
                target_index = i
                break
        if target_index is not None:
            print(f"target is Host [{target_index}]")
            h[0].target = hosts[target_index] # type: ignore
        else:
            print("no target setted")
            return

        # do some flow up
        h.flowup()

        # Now we will run some metrics
        hm.HarmSummary(h).show()

        # result = hm.HarmSummary(h).show()

        # popup = tk.Toplevel(self.root)
        # popup.title("Pop-up Window")

        # label = tk.Label(popup)
        # label.pack(padx=20, pady=20)

        # # 创建一个多行文本输入框
        # text_input = tk.Text(popup, wrap=tk.WORD, width=60, height=30)
        # text_input.pack(padx=20, pady=20)

        # long_text = """Metrics              Values\n
        # -----------------------  ---------\n
        # Number of hosts                             3\n
        # Risk                                       20\n
        # Cost                                        4\n
        # Mean of attack path lengths                 1.5\n
        # Mode of attack path lengths                 2\n
        # Standard Deviation of attack path lengths   0.707107\n
        # Shortest attack path length                 1\n
        # Return on Attack                            5\n
        # Density                                     0.5\n
        # Probability of attack success               0.6"""
        # text_input.insert(tk.END, long_text)

        # close_button = tk.Button(popup, text="Close", command=popup.destroy)
        # close_button.pack()

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

            self.btn_AT_rootnode = ttk.Button(
                AT_window,
                text='Rootnode',
                style='D.TButton',
                command=self.mode_AT_rootnode
            )
            
            self.btn_AT_vul.place(x=20, y=40, anchor='nw')
            self.btn_AT_arc.place(x=20, y=100, anchor='nw')
            self.btn_AT_AND.place(x=20, y=160, anchor='nw')
            self.btn_AT_OR.place(x=20, y=220, anchor='nw')
            self.btn_AT_rootnode.place(x=20, y=280, anchor='nw')
            self.btn_AT_clear.place(x=20, y=340, anchor='nw')

            # Canvas 画布
            self.AT_canvas = tk.Canvas(
                AT_window,
                width=550,
                height=430,
                bg="white"
            )
            self.AT_canvas.place(x=140, y=10, anchor='nw')
        
            self.AT_canvas.bind("<Button-1>", self.AT_left_click)
            self.AT_canvas.bind("<Button-3>", self.AT_right_click)

            # # 创建右键菜单
            # self.AT_gate_menu = Menu(AT_window, tearoff=0)
            # self.AT_gate_menu.add_command(label="Set as root", command=self.set_root)

    # --------------------------------------------------------------
    def AT_left_click(self, event):
        x, y = event.x, event.y
        # VUL: 添加Vul
        if self.mode == MODE_AT_VUL:
            # 弹出输入信息框，获取用户输入
            # self.vul_info = None
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

            node_id = self.nodes[self.active_node_index][2]
            sub_vul = []
            if_root = GATE_NOT_ROOT
            
            values = x, y, and_gate_id, node_id, sub_vul, if_root
            self.andgates.append(values)

            print(f"add AND gate, id={and_gate_id}")
            print(f"info: {values}")
            
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
            
            node_id = self.nodes[self.active_node_index][2]
            sub_vul = []
            if_root = GATE_NOT_ROOT
            
            values = x, y, or_gate_id, or_gate_half_id, node_id, sub_vul, if_root
            self.orgates.append(values)

            print(f"add OR gate id={or_gate_id}+{or_gate_half_id}")
            print(f"info: {values}")

        # ARC: 添加 ARC
        elif self.mode == MODE_AT_ARC:
            # 1.最近的元素
            closest_element_id = self.AT_canvas.find_closest(x, y) # 最近的
            if closest_element_id:
                element_id = closest_element_id[0]
                closest_element_tags = self.AT_canvas.gettags(element_id)
                element_tags = closest_element_tags[0]
                # 2.保存进 AG_arc_selected2，保存id和tag
                values = element_id, element_tags
                self.AG_arc_selected2.append(values)
                print("select element", values)
                # 3.满了两个 (必须是 vul->门,或者 门->门)
                if len(self.AG_arc_selected2) == 2:
                    element1_id, element1_tag = self.AG_arc_selected2[0]
                    element2_id, element2_tag = self.AG_arc_selected2[1]
                    print("draw between", element1_id, element2_id)
                    # if 'vul_tag' not in element2_tag:
                    # 4.绘制线条
                    gate_line_id = self.draw_arc(element1_id, element2_id, element1_tag, element2_tag)
                    self.AG_arc_selected2 = []

                    node_id = self.nodes[self.active_node_index][2]
                    # gate_lines
                    gate_line_values = gate_line_id, element1_id, element2_id, element1_tag, element2_tag, node_id
                    self.gate_lines.append(gate_line_values)
                    print("Gate_lines: ", self.gate_lines)

                    # self.andgates 添加 sub_vuls
                    if element2_tag == "and_gate_tag":
                        index = None
                        for i, andgate in enumerate(self.andgates):
                            if andgate[2] == element2_id:
                                index = i
                                break
                        if index is not None:
                            self.andgates[index][4].append(element1_id)
                    elif element2_tag == "or_gate_tag":
                        index = None
                        for i, orgate in enumerate(self.orgates):
                            if orgate[2] == element2_id:
                                index = i
                                break
                        if index is not None:
                            self.orgates[index][5].append(element1_id)
                    elif element2_tag == "or_gate_half_tag":
                        index = None
                        for i, orgate in enumerate(self.orgates):
                            if orgate[3] == element2_id:
                                index = i
                                break
                        if index is not None:
                            self.orgates[index][5].append(element1_id)
                    else:
                        print("WRONG gate line")
                    print("- - Append gates - -")
                    print(f"and gates: {self.andgates}")
                    print(f"or gates: {self.orgates}")
                    print("-- -- -- -- -- -- --")

        elif self.mode == MODE_AT_ROOTNODE:
            closest_element_id = None
            closest_element_tags = None
            closest_element_id = self.AT_canvas.find_closest(x, y) # 最近的
            if closest_element_id:
                element_id = closest_element_id[0]
                closest_element_tags = self.AT_canvas.gettags(element_id)
                element_tag = closest_element_tags[0]
                if element_tag in "and_gate_tag":
                    # Find the gate
                    for index, andgate in enumerate(self.andgates):
                        if andgate[2] == element_id:
                            self.andgates[index] = (*self.andgates[index][:5], GATE_IS_ROOT)
                             # set if root
                            print("set the gate to root (info)", self.andgates[index])
                            break
                elif element_tag in "or_gate_tag" or element_tag in "or_gate_half_tag":
                    for index, orgate in enumerate(self.orgates):
                        if orgate[2] == element_id or orgate[3] == element_id:
                            self.orgates[index] = (*self.orgates[index][:6], GATE_IS_ROOT)
                            print("set the gate to root (info)", self.orgates[index])
                            break

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
        gate_line_id = self.AT_canvas.create_line(
            x1_shortened, y1_shortened, x2_shortened, y2_shortened,
            arrow=tk.LAST, width=2, fill="black")
        return gate_line_id

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
            element_tags = self.AT_canvas.gettags(closest_element_id[0])
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
            element_tags = self.AT_canvas.gettags(closest_element_id[0])
            if "and_gate_tag" in element_tags:
                and_id = closest_element_id[0]
            if and_id:
                self.AT_canvas.delete(and_id)
                self.andgates[:] = [andgate for andgate in self.andgates if andgate[2] != and_id]
                print("delete AND ", and_id)
                print("current and gates:", self.andgates)

        # OR: 删除 OR gate
        elif self.mode == MODE_AT_OR:
            or_id = 0
            closest_or_half_id = 0
            closest_element_id = self.AT_canvas.find_closest(x, y) # 最近的
            element_tags = self.AT_canvas.gettags(closest_element_id[0])
            if "or_gate_tag" in element_tags:
                or_id = closest_element_id[0]
            if or_id:
                self.AT_canvas.delete(or_id)
                closest_or_half_id = self.AT_canvas.find_closest(x, y) # 最近的or gate half
                closest_or_half_tags = self.AT_canvas.gettags(closest_or_half_id[0])
                
                or_half_id = None
                if "or_gate_half_tag" in closest_or_half_tags:
                    or_half_id = closest_or_half_id[0]
                if or_half_id:
                    self.AT_canvas.delete(str(or_half_id))

                    self.orgates[:] = [orgate for orgate in self.orgates if orgate[2] != or_id]
                    print("delete OR ", or_id, '+', or_half_id)
                    print("current or gates:", self.orgates)
                
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
        
        vul_id = None
        node_id = None
        if vul_info:
            text = vul_info["Name"] # 创建文本
            vul_id = self.AT_canvas.create_text(
                x, y, text=text, 
                font=("Arial", 12), anchor="nw",
                tags="vul_tag")
            node_id = self.nodes[self.active_node_index][2]

        values = x, y, vul_id, node_id, vul_info # 存进列表
        self.vulnerabilities.append(values)
        print("vul save end:", vul_info)
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
