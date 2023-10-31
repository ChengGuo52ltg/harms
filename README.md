# Graphical User Interface of Harms
This is the GUI of the exsisting Harmat engine.
Link...


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
