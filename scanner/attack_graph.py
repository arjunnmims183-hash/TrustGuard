class AttackGraph:

    def __init__(self):

        self.nodes = set()

        self.edges = []

    def add_edge(self, src, dst):

        self.nodes.add(src)
        self.nodes.add(dst)

        self.edges.append(
            (src, dst)
        )

        
def build_attack_graph(flows):

    graph = AttackGraph()

    for flow in flows:

        previous = flow["source"]

        for transform in flow["transforms"]:

            graph.add_edge(
                previous,
                transform
            )

            previous = transform

        graph.add_edge(
            previous,
            flow["sink"]
        )

    return graph

def print_graph(graph):

    print("\n===== ATTACK GRAPH =====\n")

    for src, dst in graph.edges:

        print(
            f"{src} --> {dst}"
        )

        