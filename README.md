# Graphical User Interface of Harms

This is the GUI of the existing Harmat engine.

Link： https://github.com/whistlebee/harmat

## Installation

Make sure you have followed the steps in the link and set up harmat.

```bash
git clone https://github.com/ChengGuo52ltg/harms
```

## Usage

```bash
cd harms
cd dist
./gui_harms
```

Here is an example of generating analysis.

1) Create nodes & arcs

2) Set attacker & target

![image](https://github.com/ChengGuo52ltg/harms/assets/93461778/3ce9daa1-6dea-470f-9282-6a137126bf52)

3) Open the lower layer of each host (including target)

4) Create vulnerabilities, enter information of them

5) Create gates

6) Draw arcs

7) Connect vulnerability or gate to the root node using arc

8) Save attack tree
![image](https://github.com/ChengGuo52ltg/harms/assets/93461778/8e1e1c09-181e-4697-8cc6-35b1960f2aba)
![image](https://github.com/ChengGuo52ltg/harms/assets/93461778/7bb0584a-85bd-49c4-8ad6-da86a7202d2a)

9) Click ‘Analysis’ to get the report
![image](https://github.com/ChengGuo52ltg/harms/assets/93461778/f2e27a34-96c0-43fe-8f9a-51f4209ee0af)



## variables
Data saved as these variables: 

self.nodes = [(x, y, node_id, label, name, name_id), ()]

self.vulnerabilities = [(x, y, vul_id, node_id, vul_info, if_vul_root), ()]

vul_info = {"Name": name, "Risk": float(risk), "Probability": float(probability), "Cost": float(cost), "Impact": impact}

self.lines = [(x, y, line_id, node1_id, node2_id)] 
node1_id --> node2_id
tags = "line"

self.andgates = [(x, y, and_gate_id, node_id, sub_vuls={vul_id, vul_id, ...}, if_root), ()]
tags = 'and_gate'

self.orgates = [(x, y, or_gate_id, or_gate_half_id, node_id, sub_vuls={vul_id, vul_id, ...}, if_root), ()]
tags = 'or_gate', 'or_half_gate'

self.at_lines = [(at_line_id, element1_id, element2_id, element1_tag, element2_tag, node_id), ()]
vul_id/gate_id --> gate_id

self.roots = [(x, y, root_id, node_id), ()]
tags = 'root_tag'
