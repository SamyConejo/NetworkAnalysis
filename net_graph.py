import collections
import pathlib
import networkx as nx
from matplotlib import pyplot as plt
from ipaddress import IPv4Address, IPv4Network
import who_is


def net_analysis():
    pat = './combinedFiles/'
    directory = pathlib.Path(pat)
    #Especifica el dominio a analizar

    dominios = ['Google']
    classC = IPv4Network(("192.168.0.0", "255.255.0.0"))
    dom_map['127.0.0.1'] = 'Base'

    #Itera cada archivo en el pat
    for file in directory.iterdir():
        absolute = pat + file.name
        target = ''
        b_target = ''
        nodeList.append('127.0.0.1')  #Agrega nodo base a lista de nodos
        last_line = ''
        fist_line = ''
        #Escoger solo dominios especificados para el analisis
        if any(x in absolute for x in dominios):

            with open(absolute,'r') as sample:
                lines = sample.readlines()

                i = 0
                #itera cada linea de cada archivo
                for line in lines:

                    common = line.replace("\n", "")
                    as_list = common.split("\t")
                    as_list = [x.strip(' ') for x in as_list]


                    #almacena la ip objetivo en la lista de nodos
                    if i == 0:
                        if ('*' not in as_list[0]) and (':' not in as_list[0]):
                            target = as_list[0]
                            nodeList.append(target)
                        i = i + 1
                    #Almacena posibles ips LAN en los 3 primeros saltos
                    elif i < 4:
                        if ('*' not in as_list[1]) and (':' not in as_list[1]):
                            #Valida si uno de las 3 ips tiene caracteristicas IP LAN
                            if(IPv4Address(as_list[1].strip()) in classC):
                                lan.append(as_list[1])
                            else:
                            #Crea los edges (caminos) para las ips no filtradas entre los 3 saltos
                                element = as_list[1]
                                data.append(as_list[1])
                                b_target = create_edge(element,target,b_target)
                        i = i + 1
                    else:
                        #valida las ips con los saltos mayores a 3 y crear edges.
                        if ('*' not in as_list[1]) and ('192.168.' not in as_list[1]) and (':' not in as_list[1]):
                            element = as_list[1]
                            data.append(as_list[1])
                            b_target = create_edge(element, target, b_target)
                    sample.close()
    #crea archivo de estadisticas de los archivos analizados
    run_statistics(dominios[0])
    #crea grafo
    create_graph(dominios[0])
    #crea grafo ruta mas frecuente
    mostVisited(dominios[0])

def run_statistics(dominio):

    dic = collections.Counter(data)
    sorted_dic = dic.most_common()
    inputs = open("./results/statistics_"+dominio+".txt", "w")
    inputs.write("Estadisticas\n")
    inputs.write('Dominio: '+dominio+'\n')

    print("Estadisticas")
    print('Target: ' + dominio+ '\nIP Base: 127.0.0.1')

    owner = ''
    geo = ''
    for x in sorted_dic:
        w = who_is.whois_lookup(x[0])

        if(w == 'err'):
            geo = 'Not found'
            owner = 'Not found'
        else:
            if w['nets'][0]['country'] == None:
                geo = 'Not Found'
            else:
                geo = w['nets'][0]['country']
            if w['nets'][0]['description'] == None:
                owner = 'Not Found'
            else:
                owner = w['nets'][0]['description']


        dom_map[str(x[0])] = owner.replace("\n", "")
        print("{:<15} {:<15} {:<15}".format("Ocurrencias:" + str(x[1]), 'ip:' + str(x[0]),
                                            '\tOwner:' + owner.replace("\n", "") + ', Location:' + geo))
        inputs.write("{:<15} {:<15} {:<15}".format("Ocurrencias:" + str(x[1]),'ip:' + str(x[0]),

                                            '\tOwner:' + owner.replace("\n", "") + ', Location:'+geo)+'\n')

    inputs.close()
def create_edge(element,target,b_target):
        #creacion del primer edge desde IP base hasta el la primera conexion
        if element != target and b_target == '':
            edge = ('127.0.0.1', element)
            if not edge in edge_map:
                edge_map[edge] = 0
            nodeList.append(element)
        #valida si la ip actual no es la ip objetivo ni la ip base
        if element != target and b_target != '' and b_target != element:

            edge = (b_target, element)
            if edge in edge_map:
                    edge_map[edge] = edge_map[edge] + 1
            else:
                    edge_map[edge] = 1
            nodeList.append(element)
        #valida si la ip actual es la ip objetivo
        if element == target:
            edge = (b_target, target)
            if edge in edge_map:
                edge_map[edge] = edge_map[edge] + 1
            else:
                edge_map[edge] = 1
            nodeList.append(element)

        b_target = element
        return b_target
def create_graph(dominio):
    # Lista de nodos unica, elimina duplicados
    lista_node = list(set(nodeList))

    # agrega nodos al grafo
    for node in lista_node:
        G.add_node(node)

    # Se agregan todos los edges y nodos al grafo
    for key, value in edge_map.items():
        if value == 0:
            G.add_edge(key[0], key[1], weight=0)
        else:
            G.add_edge(key[0], key[1], weight=value)

    all_weights = []
    # Itera los nodos del grafo para obtener sus pesos
    for (node1, node2, data2) in G.edges(data=True):
        all_weights.append(data2['weight'])

    # Lista de pesos unicos, elimina duplicados
    unique_weights = list(set(all_weights))

    # Layout grafo: circular
    pos = nx.circular_layout(G)
    nx.draw_networkx_nodes(G, pos, node_color='r', node_size=70)

    # Agrega etiquetas a los nodos
    labels = {}
    for node_name in lista_node:
        labels[str(node_name)] = str(node_name)

    # Especicificacion para levantar el nodo
    nx.draw_networkx_labels(G, pos, labels, font_size=10)

    # agrega los pesos a cada edge
    for weight in unique_weights:
        # Lista unica de pesos para cada edge
        weighted_edges = [(node1, node2) for (node1, node2, edge_attr) in G.edges(data=True) if
                          edge_attr['weight'] == weight]
        if weight == 0:
            nx.draw_networkx_edges(G, pos, edgelist=weighted_edges, width=1)
        else:
            nx.draw_networkx_edges(G, pos, edgelist=weighted_edges, width=1/weight)
    plt.axis('off')
    plt.title(dominio + ' Network Graph')
    plt.savefig("./results/network_"+dominio+".png")
    plt.show()
def mostVisited (dominio):

    G_2 = nx.DiGraph()
    #subpath del network_graph, ruta mas frecuente
    longest_path = nx.dag_longest_path(G)
    #Elimina duplicados de los nodos del path mas frecuente
    seen = set()
    seen_add = seen.add
    common_nodes = [x for x in longest_path if not (x in seen or seen_add(x))]
    #Itera la lista de nodos y agrega los edges para cada nodo del subpath
    for x in range(len(common_nodes)-1):
            G_2.add_edge(common_nodes[x]+'\n'+dom_map[common_nodes[x]],common_nodes[x+1]+'\n'+dom_map[common_nodes[x+1]])
    # dibuja el grafo circular
    pos = nx.circular_layout(G_2)
    nx.draw_networkx(G_2, pos, node_color='r', node_size=50, font_size =7)
    plt.axis('off')
    plt.title('Most Common Path')
    plt.savefig("./results/common_" + dominio + ".png")
    plt.show()
    #
    # G_3 = nx.DiGraph()
    # short = nx.single_source_shortest_path(G,'127.0.0.1')
    # print(short)

if __name__ == '__main__':
    data = []
    lan = []
    edge_map = {}
    nodeList = []
    dom_map = {}
    G = nx.DiGraph()
    net_analysis()





