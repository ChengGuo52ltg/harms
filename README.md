# GUI of harms
thesis project

Variables: 

self.nodes = [(x, y, node_id, label, name, name_id), ()]

self.vulnerabilities = [(x, y, vul_id, node_id, vul_info), ()]

vul_info = {"Name": name, "Risk": float(risk), "Probability": float(probability), "Cost": float(cost), "Impact": impact}

self.lines = [(x, y, line_id, node1_id, node2_id)] 
node1_id --> node2_id

self.andgates = [(x, y, and_gate_id, node_id, sub_vuls={vul_id, vul_id, ...}), ()]

self.orgates = [(x, y, or_gate_id, or_gate_half_id, node_id, sub_vuls={vul_id, vul_id, ...}), ()]

self.gate_lines = [(gate_line_id, element1_id, element2_id, element1_tag, element2_tag, node_id), ()]
vul_id/gate_id --> gate_id