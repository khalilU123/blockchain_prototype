import hashlib
import json
import math
import time


class Node:
    def __init__(self, value):
        self.left = None
        self.right = None
        self.value = value
        self.hash=calculate_hash(value)



    # def get_tree_structure(self):
    #     if self.left is None and self.right is None:
    #         return self.value
    #     left_structure = self.left.get_tree_structure()
    #     right_structure = self.right.get_tree_structure()
    #     return [left_structure, right_structure]



def build_merkle_tree(leaves):
    # construct the bottom layer
    current_layer_nodes = []
    for i in leaves:

        # data_str = json.dumps(i, sort_keys=True)
        # # 应用哈希函数
        # hash_value = hashlib.sha256(data_str.encode()).hexdigest()
        # i['id']=hash_value
        current_layer_nodes.append(Node(i))
    while len(current_layer_nodes) != 1:
        # construct the next layer based on the current layer
        next_layer_nodes = []

        for i in range(0, len(current_layer_nodes), 2):  # [0, 2, 4,…]
            # pick two adjacent child nodes
            node1 = current_layer_nodes[i]
            node2 = current_layer_nodes[i + 1]
            # print(f'left hash: {node1.hash}')
            # print(f'right hash: {node2.hash}')
            # construct a parent node
            concat_hash = node1.hash + node2.hash
            parent = Node(concat_hash)
            parent.left = node1
            parent.right = node2
            # print(f'parent hash: {parent.hash}\n')
            next_layer_nodes.append(parent)
        current_layer_nodes = next_layer_nodes

    return current_layer_nodes[0].hash  # Merkle root


def calculate_hash(value):
    value_str = json.dumps(value, sort_keys=True)
    # 计算哈希值
    hash_value = hashlib.sha256(value_str.encode()).hexdigest()
    return hash_value

def padding(leaves):
    size = len(leaves)
    if size == 0:
        return ['']
    reduced_size = int(math.pow(2, int(math.log2(size))))
    pad_size = 0
    if reduced_size != size or reduced_size == 1:
        pad_size = 2 * reduced_size - size
        print(pad_size)

    for i in range(pad_size):
        leaves.append(leaves[-1])  # append empty dictionary
    return leaves



def main():
    medical_record = {
        'publickey':'',
        'signature':'',
        'id':1,
        'timestamp':time.time(),
        "patientID": "John Doe",
        "doctor": "Dr. Smith",
        "hospital": "ABC Hospital",
        "diagnosis": "Hypertension",
        "medication": [{},{}]}

    leaves = []
    leaves.append(medical_record)
    leaves = padding(leaves)
    print(leaves)  # ['We', 'are', 'PolyU', 'Together', 'We', 'Excel', '', '']
    merkle_root=build_merkle_tree(leaves)
    # print(f'\nmerkle root: {merkle_root}\n')



if __name__ == '__main__':
    main()
