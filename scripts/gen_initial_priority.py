#!/usr/bin/env python3
import networkx as nx
import random
from collections import defaultdict
import argparse
import math
import json



parser = argparse.ArgumentParser(description="Target Prioritization for Directed Fuzzer")
parser.add_argument("--disable",choices=["none","num_comm","num_func","cent_f"],default="none",help="disable options for target prioritization")
parser.add_argument("--workdir", help="the directory of temp generated by fuzzer")


args = parser.parse_args()
opt = args.disable
workdir = args.workdir


def normalized(data:dict):
    max_data = max(data.values())
    min_data = min(data.values())
    for _,value in data.items():
        data[_] = (value - min_data) / (max_data - min_data)
    return data

class PriorityCalculator:

    def __init__(self, ftargets_file):
        self.target_nodes = []
        self.node2func = defaultdict(str) # the function of a node in callgraph
        self.func2freq = defaultdict(int) # the frequency of a function flagged
        self.func2comm = defaultdict(int) # the community belongs to the function
        self.func2loc = defaultdict(list) # target locations in a function
        self.func2line = defaultdict(str) # function start location
        self.loc2freq = defaultdict(int) # the function frequency of a target location
        self.loc2num = defaultdict(int) # the number of targets in a community where the target in 
        self.loc2num_f = defaultdict(int) # the number of targets in a function where the target in 
        self.loc2cent_f = defaultdict(int) # the centrality of target location at function level
        #self.loc2cent_b = defaultdict(int) # the centrality of target location at basic block level
        self.loc2func = defaultdict(str) # the function of the target location
        self.loc2priority = defaultdict(int) # the priority of the target function location
        self.target2priority = defaultdict(int) # the target priority is inherented from the function priority
        self.func2targetid = defaultdict(set) # the target id of a target function
        self.target_seq_cg = defaultdict(set) # dominators of a target location at function level
        self.targetid2funcid = defaultdict(int) # mapping from target id to function id 
        self.funcid2targetid = defaultdict(list) # mapping from function id to target id
        self.ftargets_file = ftargets_file
        self.funcid_file  = workdir+"/funcid.csv"
        self.graph = nx.DiGraph()
        
        # init
        self.load_func_targets()
        self.load_callgraph(workdir+"/dot-files/callgraph.dot")
        # 
        self.get_target_nodes()
        self.get_priority()
        self.get_target2function_map(workdir+"/target2function.csv",workdir+"/function2target.json")
        #self.merge_dominators()
        #self.assign_priority_to_dominator()

    def load_callgraph(self, callgraph_file):
        self.graph = nx.nx_pydot.read_dot(callgraph_file)
    
    def get_target2function_map(self,target2func_file,func2target_file):
        # load targets from funcid.csv

        with open(self.funcid_file) as f:
            lines = f.read().split("\n")
            for line in lines:
                if line =="":
                    continue
                funcid,func = line.split(",")

                """
                The size of target2functinon.csv is smaller than ftargets.csv
                is because that some targets are not found in the callgraph 
                due to current poor static analysis method,
                which are filtered by funcid.csv.
                """  
                for targetid in self.func2targetid[func]:
                    self.funcid2targetid[funcid].append(targetid)
                    self.targetid2funcid[targetid] = funcid

        formatted_str = ""
        with open(target2func_file, 'w') as f1:
            for targetid, funcid in self.targetid2funcid.items():
                formatted_str += f"{targetid},{funcid}\n" # formats the string to your desired format
            f1.write(formatted_str)
        formatted_str = ""        
        with open(func2target_file, 'w') as f2:
            f2.write(json.dumps(self.funcid2targetid))
        
        
    def load_func_targets(self):
        # load targets from ftargets.txt
        id = 0
        with open(self.ftargets_file) as f:
            lines = f.read().split("\n")
            for line in lines:
                if line =="":
                    continue
                loc,func = line.split(",")
                self.loc2func[loc] = func
                self.func2loc[func].append(loc)
                self.func2targetid[func].add(id)
                id+=1

        for func,locs in self.func2loc.items():
            self.func2freq[func] = len(locs)

            
    def get_target_nodes(self):
        # get function name
        funcs = set()
        self.target_nodes = []
        for node in self.graph.nodes(data=True):
            if "label" in node[1]:
                func_name = node[1]['label'][2:-2]
                funcs.add((node[0],func_name))
                self.node2func[node[0]] = func_name

        # traverse the function to find target nodes
        for func in funcs:
            if(func[1] in self.func2freq):
                self.target_nodes.append(func[0])

    def get_community(self, algorithm="louvain") :
        comm_node = defaultdict(set) # key:communtiy id , value:function node
        if(algorithm == "louvain"):
            # deprecated : python louvain implementation 
#             communities = community.best_partition(self.graph.to_undirected())
#             community_size = {comm: list(communities.values()).count(comm) for comm in set(communities.values())}
#             for node,comm in communities.items():
#                 comm_node[comm].append(node)
#                 if(self.node2func[node] != ''):
#                     self.func2comm[self.node2func[node]] = comm
#             return comm_node

            communities = nx.community.louvain_communities(self.graph.to_undirected(), seed=123)
            comm_id = 0
            for comm in communities:
                comm_node[comm_id] = comm
                comm_id += 1
            return comm_node
        elif(algorithm == "girvan_newman"):
            comp = community.girvan_newman(self.graph)
            return comm_node

        else:
            return NotImplementedError

    def update_target_comm(self):
        comm_node = self.get_community()
        target_comm = set()
        for comm_id,nodes in comm_node.items():
            for node in nodes:
                if node in self.target_nodes:
                    target_comm.add(comm_id)
        return target_comm

    def get_centrality(self, graph,algorithm="pagerank"):
        if algorithm == "pagerank":
            cent = nx.pagerank(graph)
        elif algorithm == "katz":
            cent = nx.katz_centrality(graph, alpha=0.5, beta=1.0, tol=1e-12)
        else:
            return NotImplementedError
        return cent
    
    def get_necessary_nodes(self,dic, target, start):
        seq = []
        try:
            temp = target
            while temp != start:
                if temp not in seq:
                    seq.insert(0, temp)
                temp = dic[temp]
        except:
            if temp not in seq:
                seq.append(target)
        return seq

    
    def get_dominator_CG(self):
        start_node = None
        target_seq = defaultdict(list)
        for node in self.node2func:
            if(self.node2func[node] == "main"):
                start_node = node
        dic = nx.immediate_dominators(self.graph, start_node)
        for node in self.target_nodes:
            seq = self.get_necessary_nodes(dic,node,start_node)
            target_seq[node] = seq
        return target_seq
    
    def merge_dominators(self):
        for node,seq in self.get_dominator_CG().items():
            for seq_item in seq:
                func = self.node2func[node]
                for loc in self.func2loc[func]:
                    seq_line = self.func2line[self.node2func[seq_item]]
                    self.target_seq_cg[loc].add(seq_line)
        
        for target in self.target_seq:
            seq_cg = self.target_seq_cg[target]
            for seq_cg_item in seq_cg:
                self.target_seq[target].add(seq_cg_item)
                
        #target_seq_cg = [ self.func2line[node2func[func]] for node in self.get_dominator_CG()]
        #print(target_seq_cg)
    
    def get_priority(self) :
        single_community = set()
        func2cent = defaultdict(int)
        func2comm_num = defaultdict(int)

        self.load_func_targets()
        self.get_target_nodes()
        comm_node = self.get_community()
        target_communities = self.update_target_comm()
        
        for comm, nodes in comm_node.items():
            if comm not in target_communities:
                continue
            
            for node in nodes:
                func2comm_num[self.node2func[node]] = len(nodes)

            comm_subgraph = self.graph.subgraph(nodes)
            if len(comm_subgraph.edges()) == 0:
                single_community.add(nodes[0])
                continue

            node_cent = self.get_centrality(comm_subgraph)

            for node, cent in node_cent.items():
                if node not in self.target_nodes:
                    continue
                func2cent[self.node2func[node]] = cent
        
        # get centrality of target location
        # if opt == "cent_b":
        #     # disable bb centrality
        #     for loc in self.loc2func:
        #         self.loc2cent_b[loc] = 0
        # else:
        #     for func,locs in self.func2loc.items():
        #         cent_of_locs = self.get_cent_bb(func)
        #         for loc in locs:
        #             self.loc2cent_b[loc] = cent_of_locs[loc]
            
        #     self.loc2cent_b = normalized(self.loc2cent_b)
                    
        # for loc, func in self.loc2func.items():
        #     if opt == "cent_f":
        #         self.loc2cent_f[loc] = 0
        #     else:
        #         self.loc2cent_f[loc] = func2cent[func] 
                
        #     if opt == "num_comm":
        #         self.loc2num[loc] = 0
        #     else:
        #         self.loc2num[loc] = func2comm_num[func]
        #     if opt == "num_func":
        #         self.loc2num_f[loc] = 0
        #     else:
        #         self.loc2num_f[loc] = self.func2freq[func]

        #     self.loc2priority[func] = \
        #         (1 + math.log(self.loc2num[loc] + 1)) * \
        #         ((self.loc2cent_f[loc] + 1)) * \
        #         ((self.loc2cent_b[loc]+ 1)) * \
        #         (1 + math.log(self.loc2num_f[loc] + 1))
        for loc, func in self.loc2func.items():
            if opt == "cent_f":
                self.loc2cent_f[loc] = 0
            else:
                self.loc2cent_f[loc] = func2cent[func] 
                
            if opt == "num_comm":
                self.loc2num[loc] = 0
            else:
                self.loc2num[loc] = func2comm_num[func]
            if opt == "num_func":
                self.loc2num_f[loc] = 0
            else:
                self.loc2num_f[loc] = self.func2freq[func]
            if func not in self.loc2priority:
                self.loc2priority[func] = \
                    (1 + math.log(self.loc2num[loc] + 1)) * \
                    ((self.loc2cent_f[loc] + 1)) * \
                    (1 + math.log(self.loc2num_f[loc] + 1))
        
        self.loc2priority = normalized(self.loc2priority)
        for func,priority in self.loc2priority.items():
            for target_id in self.func2targetid[func]:
                self.target2priority[target_id] = priority

        # can be optimized , just for debug
        sorted_priority = sorted(self.loc2priority.items(), key=lambda x: x[1], reverse=True)
        return sorted_priority
    
    def get_cent_bb(self,func):
        # read cfg file
        cfg_file = "cfg." + func + ".dot"
        cfg = nx.nx_pydot.read_dot(workdir+"/dot-files/"+cfg_file)
        cent = self.get_centrality(cfg)
        loc2cent = defaultdict(int)
        
        for node in cfg.nodes(data=True):
            if "label" in node[1]:
                loc = node[1]['label'][2:-2]
                # filter target loc
                if loc in self.loc2func:
                    loc2cent[loc] = cent[node[0]]
        return loc2cent
    
    def save_priority(self,priority_map,filename='priority.csv'):
        formatted_str = ""
        with open(filename, 'w') as f:
            for loc, priority in priority_map.items():
                formatted_str += f"{loc},{priority:.2f}\n" # formats the string to your desired format
            f.write(formatted_str)

def main():
    pc = PriorityCalculator(workdir+"/ftarget.csv")
    pc.save_priority(pc.loc2priority,workdir+"/priority.csv")
    pc.save_priority(pc.target2priority,workdir+"/target_priority.csv")

if __name__ == "__main__":
    main()
    
