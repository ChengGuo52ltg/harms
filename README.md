# harms
thesis project

Variables: 
self.nodes
[(x, y, node_id, label, name, name_id), ()]

self.vulnerabilities
[(x, y, vul_id, node_id, vul_info)]
vul_info
{"Name": name, "Risk": float(risk), "Probability": float(probability), "Cost": float(cost), "Impact": impact}

self.lines
[(x, y, line_id, node1_id, node2_id)]
