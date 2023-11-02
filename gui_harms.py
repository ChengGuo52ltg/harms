import tkinter as tk
from tkinter import ttk, messagebox, Menu
from tkinter import simpledialog
from tkinter.scrolledtext import ScrolledText
import io
import contextlib


import harmat as hm
from requests import delete
from tabulate import tabulate
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
VUL_IS_ROOT = 1
VUL_NOT_ROOT = 0

# Position of the window
X_POSITION = 500
Y_POSITION = 300
class GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('Welcome to HARMs!')
        self.root.geometry(f'750x450+{X_POSITION}+{Y_POSITION}')


        # Style setting
        self.style = ttk.Style(self.root)
        self.style.configure('.', font=("Comic Sans MS", 12))
        self.style_active = ttk.Style(self.root)
        self.style_active.configure('A.TButton', background='yellow', padding=(5, 10))
        self.style_default = ttk.Style(self.root)
        self.style_default.configure('D.TButton', background='white', padding=(5, 10))
        
        # track history for undo and redo
        self.history = []  # [(action, values), (action, values)]
        self.history_redo = []

        self.mode = None

        # Menu
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

        # Canvas
        self.canvas = tk.Canvas(
            self.root,
            width=570,
            height=430,
            bg="white"
        )
        self.canvas.place(x=170, y=10, anchor='nw')

        self.nodes = []
        self.lines = []

        # left click, bind
        self.canvas.bind("<Button-1>", self.AG_left_click)
        # right click, bind
        self.canvas.bind("<Button-3>", self.AG_right_click)
    
        # right click, menu
        self.node_menu = Menu(self.root, tearoff=0)
        self.node_menu.add_command(label="Set as attacker", command=self.set_attacker)
        self.node_menu.add_command(label="Set as target", command=self.set_target)
        self.node_menu.add_command(label="Open Lower Layer", command=self.open_attack_tree)
        self.node_menu.add_command(label="Rename", command=self.rename_node)

        # arc
        self.AG_arc_selected2 = []
        self.AT_arc_selected2 = [] # [(id,tags),(id,tags)]

        # ATTACK TREE:
        self.vulnerabilities = []  # list for vulnerabilities
        self.andgates = []
        self.orgates = []
        self.at_lines = [] 
        self.roots = []

        # Buttons
        self.btn_node = ttk.Button(
            self.root,
            text='Node',
            style='D.TButton',
            command=self.mode_AG_node
        )
        
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
        
        self.btn_node.place(x=35, y=40, anchor='nw')
        self.btn_arc.place(x=35, y=100, anchor='nw')
        self.btn_undo.place(x=20, y=200, anchor='nw')
        self.btn_redo.place(x=90, y=200, anchor='nw')
        self.btn_clear.place(x=35, y=260, anchor='nw')
        self.btn_analysis.place(x=35, y=370, anchor='nw')

# --------------------------------------------------------------------------- Modes
    def mode_AG_node(self):
        if self.mode != MODE_AG_NODE: # click this mode
            self.mode = MODE_AG_NODE
            self.btn_node.config(style='A.TButton')
            # recover other buttons
            self.btn_arc.config(style='D.TButton')
        else: # cancel this mode
            self.mode = MODE_NONE
            self.btn_node.config(style='D.TButton')
    
    def mode_AG_arc(self):
        if self.mode != MODE_AG_ARC:
            self.mode = MODE_AG_ARC
            self.btn_arc.config(style='A.TButton')
            self.btn_node.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_arc.config(style='D.TButton')

    def mode_AT_vul(self):
        if self.mode != MODE_AT_VUL:
            self.mode = MODE_AT_VUL
            self.btn_AT_vul.config(style='A.TButton')
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
            self.btn_AT_vul.config(style='D.TButton')
            self.btn_AT_AND.config(style='D.TButton')
            self.btn_AT_OR.config(style='D.TButton')
            self.btn_AT_clear.config(style='D.TButton')
        else: 
            self.mode = MODE_NONE
            self.btn_AT_arc.config(style='D.TButton')

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

            # delete self.nodes with certain vul_id
            self.nodes[:] = [node for node in self.nodes if node[2] != node_id] 
            print("delete node ", node_id)

            return 1
    
    def ag_add_arc(self, x, y):
        closest_node = self.canvas.find_closest(x, y)
        if closest_node:
            node_id = closest_node[0]
            self.AG_arc_selected2.append(node_id)
            print("select node for arc",node_id)
            if len(self.AG_arc_selected2) == 2: # choose two node
                node1_id, node2_id = self.AG_arc_selected2
                line_id = self.draw_arrow_line(node1_id, node2_id)
                # store line
                values = x, y, line_id, node1_id, node2_id
                self.lines.append(values)
                print("print arc", line_id, "from", node1_id, "to", node2_id)
                # clear
                self.AG_arc_selected2 = []

                return 1
            else:
                return 0

    def draw_arrow_line(self, node1_id, node2_id):
        # get node 1 center coordinate
        x1, y1 = self.get_node_center(node1_id)
        # get node 2 center coordinate
        x2, y2 = self.get_node_center(node2_id)

        # adjust the positions of start and end points, move closer to the center point by a certain distance
        line_length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        shorten_distance = 20  # shorten distance
        if line_length > shorten_distance:
            ratio = shorten_distance / line_length
            x1_shortened = x1 + (x2 - x1) * ratio
            y1_shortened = y1 + (y2 - y1) * ratio
            x2_shortened = x2 - (x2 - x1) * ratio
            y2_shortened = y2 - (y2 - y1) * ratio
        else:
            # if too short, do not shorten
            x1_shortened, y1_shortened = x1, y1
            x2_shortened, y2_shortened = x2, y2

        # draw line
        line_id = self.canvas.create_line(
            x1_shortened, y1_shortened, x2_shortened, y2_shortened,
            arrow=tk.LAST, width=2, fill="black", tags="line")
        return line_id

    # get node center coordinate
    def get_node_center(self, node_id):
        x1, y1, x2, y2 = self.canvas.coords(node_id)
        # calculate the center point
        x_center = (x1 + x2) / 2
        y_center = (y1 + y2) / 2
        return x_center, y_center
    
    def ag_remove_arc(self, x, y):
        lines_id = self.canvas.find_withtag("line")

        closest_line_id = None
        closest_distance = float("inf")

        # find closest line
        for line_id in lines_id:
            # get line coordinates
            x1, y1, x2, y2 = self.canvas.coords(line_id)
            # calculate the distance from the point to the line
            distance = ((x2 - x1) * (y1 - y) - (x1 - x) * (y2 - y1)) / ((x2 - x1) ** 2 + (y2 - y1) ** 2)

            # update the closest line
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
            # NODE: add node when left click, delete node when right click
            out = self.add_node(x, y)
            if out == 1:
                # Add the last node to history
                self.history.append(("add_node", self.nodes[-1]))

        elif self.mode == MODE_AG_ARC:
            # ARC: choose nodes to add arc
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
            # NONE: right click to show menu
            closest_node = self.canvas.find_closest(x, y)
            if closest_node:
                node_id = closest_node[0] # get the closest node
                self.node_menu.post(event.x_root, event.y_root)  # show menu
                # find the node in self.nodes
                for i, node in enumerate(self.nodes):
                    if node[2] == node_id: # for each node: (x, y, id, label, name)
                        self.active_node_index = i
                        print('show menu of node: ', node, ' id:', node_id)
                        break
    
    # ---------------------------------------------------------------------------
    def set_attacker(self):
        if hasattr(self, "active_node_index"):
            # set name as attacker
            new_name = "Attacker"
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:3], NODE_ATTACKER, new_name, *self.nodes[self.active_node_index][5:])
            # delete the original name_id, update text
            self.canvas.delete(self.nodes[self.active_node_index][5]) # delete text
            x = self.nodes[self.active_node_index][0]
            y = self.nodes[self.active_node_index][1]
            new_name_id = self.canvas.create_text(x, y + 20, text=new_name, fill="black", anchor="center")
            # replace by new name_id
            self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:5], new_name_id)
            print("attacker: ", self.nodes[self.active_node_index])
            # change color
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
            # change color
            item_id = self.nodes[self.active_node_index][2]
            self.canvas.itemconfig(item_id, fill="light green")
    
    def rename_node(self):
        if hasattr(self, "active_node_index"):
            # set name
            new_name = simpledialog.askstring("Rename", "Enter a new name:")
            if new_name is not None:
                self.nodes[self.active_node_index] = (*self.nodes[self.active_node_index][:3], NODE_HOST, new_name, *self.nodes[self.active_node_index][5:])
                # delete the original name_id, update text
                self.canvas.delete(self.nodes[self.active_node_index][5])
                x = self.nodes[self.active_node_index][0]
                y = self.nodes[self.active_node_index][1]
                new_name_id = self.canvas.create_text(x, y + 20, text=str(new_name), fill="black", anchor="center")
                # replace by new name_id
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
        self.at_lines = []
        self.roots = []
        print("Clear")
    
    def AG_undo(self):
        if self.history:
            # get the previous operation from the history
            action, values = self.history.pop()
            # perform the corresponding undo operation
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
            # get the next operation from the history
            action, values = self.history_redo.pop()
            # perform the corresponding redo operation
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

        self.nodes_withoutattacker = [node for node in self.nodes if node[3] != 1]
        count_expect_attacker = len(self.nodes_withoutattacker)
        hosts = [hm.Host("Host {}".format(i)) for i in range(count_expect_attacker)]
        print(hosts)
        print(self.nodes)
        print(self.nodes_withoutattacker)

        print("all vuls: ", self.vulnerabilities)

        for index, host in enumerate(hosts):
            host.lower_layer = hm.AttackTree()

            # e.g. index=0, what's the node_id under hosts[0] //self.nodes_withoutattacker[0]
            node_id = self.nodes_withoutattacker[index][2]
            print("host's node_id = ", node_id)

            # vuls under certain node_id
            vuls = None
            vuls = [vul for vul in self.vulnerabilities if vul[3] == node_id]
            print("host's vuls = ", vuls)

            # make vuls
            if vuls:
                at_vulnerabilities_list = []
                for vul in vuls:
                    vulnerability = None
                    vul_value = vul[4]
                    print("vul_value = ", vul_value)
                    vulnerability = hm.Vulnerability(vul_value["Name"], values = {
                    'risk' : vul_value["Risk"],
                    'cost' : vul_value["Cost"],
                    'probability' : vul_value["Probability"],
                    'impact' : vul_value["Impact"]
                    })
                    if vulnerability:
                        at_vulnerabilities_list.append(vulnerability)
                    # check ROOT
                    if vul[5] == GATE_IS_ROOT:
                        host.lower_layer.at_add_node(vulnerability)
                print(at_vulnerabilities_list)
            
                # gates under certain node_id
                and_gates = None
                and_gates = [and_gate for and_gate in self.andgates if and_gate[3] == node_id]
                print("host's and_gates = ", and_gates)
                or_gates = None
                or_gates = [or_gate for or_gate in self.orgates if or_gate[4] == node_id]
                print("host's or_gates = ", or_gates)

                # make gates
                at_and_gate_list = []
                at_or_gate_list = []
                for and_gate in and_gates:
                    at_and_gate = hm.LogicGate(gatetype='and')
                    at_and_gate_list.append(at_and_gate)
                    # ROOTNODE:if gate is root, connect logigate to rootnode, use at_add_node
                    if and_gate[5] == GATE_IS_ROOT:
                        host.lower_layer.at_add_node(at_and_gate)

                for or_gate in or_gates:
                    at_or_gate = hm.LogicGate(gatetype='or')
                    at_or_gate_list.append(at_or_gate)
                    if or_gate[6] == GATE_IS_ROOT:
                        host.lower_layer.at_add_node(at_or_gate)

                for i, and_gate in enumerate(and_gates):
                    for element_id in and_gate[4]:
                        # element_id ---> vuls[?] 
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
                            # gate? element_id ----> and_gate or_gate
                            for y, element_and in enumerate(and_gates):
                                if element_id == element_and[2]:
                                    andgate_index = y
                                    break
                            if andgate_index is not None:
                                host.lower_layer.at_add_node(at_and_gate_list[andgate_index], logic_gate=at_and_gate_list[i])
                                print(f"add sub_and (id){element_id} to and gate (info){and_gate}")
                            else:
                                # or orgate
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

        # default: host[0] is attacker
        # for self.lines
        for line in self.lines:
            print("For arc:", line)

            # self.lines[3][4] is node_id - start, end
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

        # find target
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
        # hm.HarmSummary(h).show()
        summary = hm.HarmSummary(h)
        summary.__init__(h)
        summary.compute(h)
        output_buffer = io.StringIO()
        with contextlib.redirect_stdout(output_buffer):
            summary.show()
    
        output_result = output_buffer.getvalue()

        popup = tk.Toplevel(self.root)
        popup.title("Harm Summary Result")
        popup.geometry(f'500x300+{X_POSITION}+{Y_POSITION}')

        result_text = ScrolledText(popup, wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True)
        if output_result is not None:
            result_text.insert('1.0', output_result)  
        result_text.configure(state='disabled')  # disablt to edit

        close_button = tk.Button(popup, text="Close", command=popup.destroy)
        close_button.pack()

    # --------------------------------- Attack tree - Lower layer ----------

    def open_attack_tree(self):
        if hasattr(self, "active_node_index"):
            global AT_window
            AT_window = tk.Toplevel(self.root)
            title_text = str(self.nodes[self.active_node_index][4])
            node_id = self.nodes[self.active_node_index][2]
            AT_window.title("Attack Tree of " + title_text)
            AT_window.geometry(f'700x450+{X_POSITION}+{Y_POSITION}')

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
                command=self.at_clear
            )

            self.btn_AT_save = ttk.Button(
                AT_window,
                text='Save',
                style='D.TButton',
                command=self.at_save
            )
            
            self.btn_AT_vul.place(x=20, y=40, anchor='nw')
            self.btn_AT_arc.place(x=20, y=100, anchor='nw')
            self.btn_AT_AND.place(x=20, y=160, anchor='nw')
            self.btn_AT_OR.place(x=20, y=220, anchor='nw')
            self.btn_AT_save.place(x=20, y=280, anchor='nw')
            self.btn_AT_clear.place(x=20, y=340, anchor='nw')

            # Canvas
            self.AT_canvas = tk.Canvas(
                AT_window,
                width=550,
                height=430,
                bg="white"
            )
            self.AT_canvas.place(x=140, y=10, anchor='nw')
        
            self.AT_canvas.bind("<Button-1>", self.AT_left_click)
            self.AT_canvas.bind("<Button-3>", self.AT_right_click)

            # Create one ROOTNODE
            x = 280
            y = 30
            root_id = self.AT_canvas.create_oval(x - 10, y - 10, x + 10, y + 10, fill="light blue", tags='root_tag')
            root_label_id = self.AT_canvas.create_text(x, y + 20, text="ROOT: " + title_text, fill="black", anchor="center")
            self.roots.append((x, y, root_id, node_id))
    # --------------------------------------------------------------
    def AT_left_click(self, event):
        x, y = event.x, event.y
        # VUL: add vul when left click, delete vul when right click
        if self.mode == MODE_AT_VUL:
            self.get_vulnerability_info(x,y)
            
        # AND: add and gate
        elif self.mode == MODE_AT_AND:
            radius = 30  # AND GATE 
            start_angle = 0
            end_angle = 180

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
            
        # OR: add or gate
        elif self.mode == MODE_AT_OR:
            radius_1 = 30  # OR GATE 
            radius_2 = 15  

            start_angle = 0
            end_angle = 180

            or_gate_id = self.AT_canvas.create_arc(
                x - radius_1, y - radius_1, x + radius_1, y + radius_1,
                start=start_angle, extent=end_angle,
                outline="black",
                style=tk.ARC,
                tags='or_gate_tag')

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

        # ARC: add ARC
        elif self.mode == MODE_AT_ARC:
            # 1. fine the closest element
            closest_element_id = self.AT_canvas.find_closest(x, y)
            if closest_element_id:
                element_id = closest_element_id[0]
                closest_element_tags = self.AT_canvas.gettags(element_id)
                element_tags = closest_element_tags[0]
                # 2. save the element_id and element_tags
                values = element_id, element_tags
                self.AG_arc_selected2.append(values)
                print("select element", values)
                # 3. if 2 elements are selected, draw arc
                if len(self.AG_arc_selected2) == 2:
                    element1_id, element1_tag = self.AG_arc_selected2[0]
                    element2_id, element2_tag = self.AG_arc_selected2[1]
                    print("draw between", element1_id, element2_id)
                    # if 'vul_tag' not in element2_tag:
                    # 4. draw arc
                    at_line_id = self.draw_arc(element1_id, element2_id, element1_tag, element2_tag)
                    self.AG_arc_selected2 = []

                    node_id = self.nodes[self.active_node_index][2]
                    # gate_lines
                    at_line_values = at_line_id, element1_id, element2_id, element1_tag, element2_tag, node_id
                    self.at_lines.append(at_line_values)
                    print("Gate_lines: ", self.at_lines)

                    if element2_tag == "and_gate_tag":
                        index = None
                        for i, andgate in enumerate(self.andgates):
                            if andgate[3] == node_id and andgate[2] == element2_id:
                                index = i
                                break
                        if index is not None:
                            self.andgates[index][4].append(element1_id)
                    elif element2_tag == "or_gate_tag" or element2_tag == "or_gate_half_tag":
                        index = None
                        for i, orgate in enumerate(self.orgates):
                            if orgate[4] == node_id:
                                if orgate[2] == element2_id or orgate[3] == element2_id:
                                    index = i
                                    break
                        if index is not None:
                            self.orgates[index][5].append(element1_id)
                    
                    # connect to the root
                    elif element2_tag == "root_tag":
                        pass
                    else:
                        print("WRONG AT line")
                    print("- - Append gates - -")
                    print(f"and gates: {self.andgates}")
                    print(f"or gates: {self.orgates}")
                    print("-- -- -- -- -- -- --")

    def draw_arc(self, id_1, id_2, tag_1, tag_2):
        x1, y1 = self.get_element_center(id_1, tag_1)
        x2, y2 = self.get_element_center(id_2, tag_2)
        line_length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        shorten_distance = 30  
        if line_length > shorten_distance:
            ratio = shorten_distance / line_length
            x1_shortened = x1 + (x2 - x1) * ratio
            y1_shortened = y1 + (y2 - y1) * ratio
            x2_shortened = x2 - (x2 - x1) * ratio
            y2_shortened = y2 - (y2 - y1) * ratio
        else:
            x1_shortened, y1_shortened = x1, y1
            x2_shortened, y2_shortened = x2, y2
        gate_line_id = self.AT_canvas.create_line(
            x1_shortened, y1_shortened, x2_shortened, y2_shortened,
            arrow=tk.LAST, width=2, fill="black")
        return gate_line_id

    def get_element_center(self, id, tag):
        if 'vul_tag' in tag:
            x1, y1, x2, y2 = self.AT_canvas.bbox(id)
        else:
            x1, y1, x2, y2 = self.AT_canvas.coords(id)
        x_center = (x1 + x2) / 2
        y_center = (y1 + y2) / 2
        return x_center, y_center

    def AT_right_click(self, event):
        x, y = event.x, event.y

        # VUL: remove Vul
        if self.mode == MODE_AT_VUL:
            vul_id = 0
            closest_element_id = self.AT_canvas.find_closest(x, y) 
            element_tags = self.AT_canvas.gettags(closest_element_id[0])
            if "vul_tag" in element_tags:
                vul_id = closest_element_id[0]
            if vul_id:
                self.AT_canvas.delete(vul_id)
                self.vulnerabilities[:] = [vul for vul in self.vulnerabilities if vul[2] != vul_id]
                print("delete vul ", vul_id, ' from node x ')
        
        # AND: remove AND gate
        elif self.mode == MODE_AT_AND:
            and_id = 0
            closest_element_id = self.AT_canvas.find_closest(x, y)
            element_tags = self.AT_canvas.gettags(closest_element_id[0])
            if "and_gate_tag" in element_tags:
                and_id = closest_element_id[0]
            if and_id:
                self.AT_canvas.delete(and_id)
                self.andgates[:] = [andgate for andgate in self.andgates if andgate[2] != and_id]
                print("delete AND ", and_id)
                print("current and gates:", self.andgates)

        # OR: remove OR gate
        elif self.mode == MODE_AT_OR:
            or_id = 0
            closest_or_half_id = 0
            closest_element_id = self.AT_canvas.find_closest(x, y) 
            element_tags = self.AT_canvas.gettags(closest_element_id[0])
            if "or_gate_tag" in element_tags:
                or_id = closest_element_id[0]
            if or_id:
                self.AT_canvas.delete(or_id)
                closest_or_half_id = self.AT_canvas.find_closest(x, y) 
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
        # new window, get vulnerability info
        global vul_info_window
        vul_info_window = tk.Toplevel(AT_window)
        vul_info_window.title("Edit Vulnerability")
        vul_info_window.geometry(f'300x250+{X_POSITION}+{Y_POSITION}')
        # Labels
        self.lbl_vul_name = ttk.Label(vul_info_window,text='Name:')
        self.lbl_vul_prob = ttk.Label(vul_info_window,text='Probability:')
        self.lbl_vul_cost = ttk.Label(vul_info_window,text='Cost:')
        self.lbl_vul_impt = ttk.Label(vul_info_window,text='Impact:')
        # Entries
        self.entry_name = ttk.Entry(vul_info_window, width=15)
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
        self.btn_vul_save.place(x=30, y=200, anchor='nw')
        self.btn_vul_cancel.place(x=160, y=200, anchor='nw')
        self.lbl_vul_name.place(x=30, y=30, anchor='nw')
        self.lbl_vul_prob.place(x=30, y=70, anchor='nw')
        self.lbl_vul_cost.place(x=30, y=110, anchor='nw')
        self.lbl_vul_impt.place(x=30, y=150, anchor='nw')
        self.entry_name.place(x=140, y=30, anchor='nw')
        self.entry_prob.place(x=140, y=70, anchor='nw')
        self.entry_cost.place(x=140, y=110, anchor='nw')
        self.entry_impt.place(x=140, y=150, anchor='nw')

    def vul_save(self, x, y):
        name = ""
        name = self.entry_name.get()
        prob_input = self.entry_prob.get()
        cost_input = self.entry_cost.get()
        impt_input = self.entry_impt.get()

        risk = float(0)
        prob = float(0)
        cost = float(0)
        impt = float(0)
        try:
            prob = float(prob_input)
            cost = float(cost_input)
            impt = float(impt_input)
            risk = prob * impt
        except ValueError:
            print("invalid")

        vul_info = {"Name": name, "Risk": risk, "Probability": prob, "Cost": cost, "Impact": impt}
        
        vul_info_window.destroy()
        
        vul_id = None
        node_id = None
        if vul_info:
            text = vul_info["Name"] 
            vul_id = self.AT_canvas.create_text(
                x, y, text=text, 
                font=("Arial", 12), anchor="nw",
                tags="vul_tag")
            node_id = self.nodes[self.active_node_index][2]

        if_vul_root = VUL_NOT_ROOT
        values = x, y, vul_id, node_id, vul_info, if_vul_root 
        self.vulnerabilities.append(values)
        print("vul:", values)
        print(self.vulnerabilities)
    
    def vul_cancel(self):
        print(self.vulnerabilities)
        vul_info_window.destroy()

    def at_save(self):
        # Find the at_line to root, save: which vuls are connected to root
        for i, at_line in enumerate(self.at_lines):
            at_lne_id = at_line[0]
            at_line_element1_id = at_line[1]
            at_line_element2_id = at_line[2]
            at_line_element1_tag = at_line[3]
            at_line_element2_tag = at_line[4]
            node_id = self.nodes[self.active_node_index][2]

            if at_line_element2_tag in 'root_tag': 
                # find the vuls connected to this line
                if at_line_element1_tag in "vul_tag":
                    for j, vul in enumerate(self.vulnerabilities):
                        if vul[3] == node_id:
                            if vul[2] == at_line_element1_id:
                                self.vulnerabilities[j] = (*self.vulnerabilities[j][:5], VUL_IS_ROOT)
                                print(f"set vul {vul[2]} to root, (info){self.vulnerabilities[j]}")
                                break
                # find the and gates connected to this line
                elif at_line_element1_tag in 'and_gate_tag':
                    for k, and_gate in enumerate(self.andgates):
                        if and_gate[3] == node_id:
                            if and_gate[2] == at_line_element1_id:
                                self.andgates[k] = (*self.andgates[k][:5], GATE_IS_ROOT)
                                print(f"set and gate {and_gate[2]} to root, (info){and_gate}")
                                break
                # find the or gates connected to this line
                elif at_line_element1_tag in "or_gate_tag" or at_line_element1_tag in "or_gate_half_tag":
                    for l, or_gate in enumerate(self.orgates):
                        if or_gate[4] == node_id:   
                            if or_gate[2] == at_line_element1_id or or_gate[3] == at_line_element1_id:
                                self.orgates[l] = (*self.orgates[l][:6], GATE_IS_ROOT)
                                print(f"set or gate {or_gate[2]} to root, (info){or_gate}")
                                break
            
            # close the window
            AT_window.destroy()
            self.mode = MODE_NONE
    
    def at_clear(self):
        self.AT_canvas.delete("all")


    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    app = GUI()
    app.run()
