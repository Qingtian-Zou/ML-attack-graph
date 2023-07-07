# %%
import xml.etree.ElementTree as ET
import os
import re
import json
import argparse

FLAGS=None

# %%
def xml2predicate(txt):
    predicate, txt=txt.split(':',1)
    st_indices = [i for i in range(len(txt)) if txt[i]=='[']
    ed_indices = [i for i in range(len(txt)) if txt[i]==']']
    variables=[txt[st_indices[i]+1:ed_indices[i]] for i in range(len(st_indices))]
    return (predicate, variables)

def predicate_and_vars_to_fact(predicate, vars):
    facts=""
    facts+=predicate
    facts+='('
    facts+=(','.join(vars))
    facts+=')'
    return facts

def check_duplicate_predicate(predicate_declarations, new_predicate):
    duplicated=False
    for predicate in predicate_declarations:
        if new_predicate[0] in predicate:
            if len(new_predicate[1])==predicate.count('_'):
                duplicated=True
    return duplicated

def process_fact(fact_node):
    predicate, variables=xml2predicate(fact_node.text)
    return(predicate+"("+",".join(variables)+").")


# %%
def parse_xml(xmlFile):
    tree=ET.parse(xmlFile)

    root=tree.getroot()

    node_libs={}
    node_rules=[]
    predicate_declarations=[]
    tabling_predicates=[]
    interaction_rules=[]
    relations={}
    relation_id=0
    for root_child in root:
        if root_child.tag=='relation':
            relation=root_child
            relation_dict=dict(relation.items())
            relations[relation_id]={}
            relations[relation_id]['dict']=relation_dict
            relations[relation_id]['nodes']={}
            nodes=relations[relation_id]['nodes']
            for node in relation:
                if node.tag=="pre":
                    if 'conditions' not in nodes.keys():
                        nodes['conditions']=[]
                    nodes['conditions'].append(hash(node.text))
                    node_libs[hash(node.text)]=xml2predicate(node.text)
                elif node.tag=="post":
                    if 'results' not in nodes.keys():
                        nodes['results']=[]
                    nodes['results'].append(relation_id)
                    node_libs[relation_id]=xml2predicate(node.text)
            node_rules.append(nodes)

            lines={"conditions":[], 'results':[]}
            if "conditions" in nodes.keys():
                for y in nodes['conditions']:
                    if not check_duplicate_predicate(predicate_declarations, (node_libs[y][0], ["_"+z for z in node_libs[y][1]])):
                        predicate_declarations.append("primitive("+node_libs[y][0]+"("+", ".join(["_"+z for z in node_libs[y][1]])+")).")
                    lines['conditions'].append(node_libs[y][0]+"("+", ".join([z for z in node_libs[y][1]])+")")
            if "results" in nodes.keys():
                for y in nodes['results']:
                    if not check_duplicate_predicate(predicate_declarations, (node_libs[y][0], ["_"+z for z in node_libs[y][1]])):
                        predicate_declarations.append("derived("+node_libs[y][0]+"("+", ".join(["_"+z for z in node_libs[y][1]])+")).")
                        tabling_predicates.append(":- table "+node_libs[y][0]+"/"+str(len(node_libs[y][1]))+".")
                    lines['results'].append(node_libs[y][0]+"("+", ".join([z for z in node_libs[y][1]])+")")
            for result in lines['results']:
                interaction_rules.append("interaction_rule(\n  ("+result+" :- "+",".join(lines['conditions'])+"),\n  rule_desc(\'\',1)\n).")
            
            relation_id+=1

    return (predicate_declarations,tabling_predicates,interaction_rules)

def merge_logics(attack_logics,ML_logics):
    derives_set=find_derives(attack_logics[0],ML_logics[0])
    predicate_declarations=[]

    for predicate in attack_logics[0]+ML_logics[0]:
        fact=(predicate.split("(")[1],predicate.count("_"))
        if fact in derives_set and "primitive" in predicate:
            continue
        predicate_declarations.append(predicate)
    
    tabling_predicates=attack_logics[1]+ML_logics[1]
    interaction_rules=attack_logics[2]+ML_logics[2]

    file_name=os.path.basename(FLAGS.attack_xml).strip(".xml")+"-"+os.path.basename(FLAGS.ML_xml).strip(".xml")
    fi=open(file_name+".rules.P",'w')

    fi.write("\n".join([
        "/******************************************************/",
        "/****         Predicates Declaration              *****/",
        "/******************************************************/",
        "",
        ""
    ]))
    fi.write("\n".join(predicate_declarations))

    fi.write("\n".join([
        "",
        "",
        "/******************************************************/",
        "/****         Tabling Predicates                  *****/",
        "/*   All derived predicates should be tabled          */",
        "/******************************************************/",
        "",
        ""
    ]))
    fi.write("\n".join(tabling_predicates))

    fi.write("\n".join([
        "",
        "",
        "/******************************************************/",
        "/****         Interaction Rules                   *****/",
        "/******************************************************/",
        "",
        ""
    ]))
    fi.write("\n".join(interaction_rules))

    fi.close()

def find_derives(attack_primitives,ML_primitives):
    derives_set=set()
    for primitives in attack_primitives+ML_primitives:
        if "derived" in primitives:
            fact=(primitives.split("(")[1],primitives.count("_"))
            derives_set.add(fact)
    return derives_set

# %%
if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument(
        '--attack_xml',
        type=str,
        required=True
    )
    parser.add_argument(
        '--ML_xml',
        type=str,
        required=True
    )
    FLAGS, unparsed = parser.parse_known_args()
    attack_logics=parse_xml(FLAGS.attack_xml)
    ML_logics=parse_xml(FLAGS.ML_xml)
    merge_logics(attack_logics,ML_logics)
