import hashlib
from hashlib import sha256
import json
import time

import redis
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, current_app
import requests
import Merkle_tree

from cryptography.hazmat.primitives import hashes



medical_record = {
        "patientID": "John Doe",
        "doctor": "Dr. Smith",
        "hospital": "ABC Hospital",
        "diagnosis": "Hypertension",
        "medication": [
            {
                "medication_id": "12345",
                "medication_name": "Lisinopril"
            },
            {
                "medication_id": "67890",
                "medication_name": "Metoprolol"
            }
        ]
    }
class Block:



    def __init__(self, index, merkle_hash, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.merkle_hash = merkle_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 1

    def __init__(self):
        self.unconfirmed_transactions = []
        self.confirmed_transactions = []
        self.chain = []
        self.pubkeys = []

    def create_genesis_block(self):
        genesis_block = Block(0, '', [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]



    def add_new_transaction(self, transaction):
        if self.confirm_transaction(transaction):
            transaction_string = json.dumps(transaction)
            r.hset('confirmed_transactions', transaction['id'], transaction_string)
            self.confirmed_transactions.append(transaction)
        print(self.confirmed_transactions[0])
        print(len(self.confirmed_transactions))


    #verify the signature
    def confirm_transaction(self,transaction):
        # signing
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        signature = private_key.sign(transaction['id'].encode(), ec.ECDSA(hashes.SHA256()))
        # verify
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )
        data = transaction['id']
        #check authority
        # if public_key not in self.pubkeys:
        #     return False
        try:
            public_key.verify(signature, data.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False



#check pow work
    @classmethod
    def is_valid_proof(cls, block, block_hash):
        records = Merkle_tree.padding(block.transactions)
        root = Merkle_tree.build_merkle_tree(records)
        if root != block.merkle_hash:
            return False
        # confirm_transactions
        for transaction in block.transactions:
            if not blockchain.confirm_transaction(transaction):
                return False
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())


#check hash and pow when adding a new block
    def add_block(self, block, proof):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not Blockchain.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block)
        # push it to the redis
        block_string = json.dumps(block.__dict__)
        r.hset('chain', block.hash, block_string)
        return True


#pow implementation
    @staticmethod
    def proof_of_work(block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash


#verify the longest chain
    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"
        for block in chain[-3]:
            block_hash = block.hash
            # remove the hash field to recompute the hash again
            # using `compute_hash` method.
            delattr(block, "hash")
            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break
            block.hash, previous_hash = block_hash, block_hash
        return result

    def mine(self):
        confirmed_transactions = r.hgetall('confirmed_transactions')
        #get confirmed transaction from redis
        for key, value in confirmed_transactions.items():
            self.confirmed_transactions.append(json.loads(value))
        if not self.confirmed_transactions:
            return False
        last_block = self.last_block
        records = Merkle_tree.padding(self.confirmed_transactions)
        #generate merkle root
        root = Merkle_tree.build_merkle_tree(records)
        new_block = Block(index=last_block.index + 1,
                          merkle_hash=root,
                          transactions=self.confirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)
        #calculate nonce
        proof = self.proof_of_work(new_block)
        #verify the block and transactions again
        if self.add_block(new_block, proof):
            self.confirmed_transactions = []
            r.delete('confirmed_transactions')
        print('finish')



        return True



app = Flask(__name__)
# the node's copy of blockchain
# the address to other participating members of the network
peers = set()


#send new transaction
@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["patientID", "doctor", "hospital", "diagnosis", "medication"]
    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404
    tx_data['timestamp'] = time.time()
    tx_copy = tx_data
    record_str = json.dumps(tx_copy, sort_keys=True)
    hash_object = hashlib.sha256(record_str.encode())
    hash_value = hash_object.hexdigest()
    tx_data['id'] = hash_value
    blockchain.add_new_transaction(tx_data)
    return "Success", 201



#for other nodes to get chain data
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers),
                       'pubkeys': blockchain.pubkeys})


@app.route('/print_chain', methods=['GET'])
def print_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)

    return json.dumps({"length": len(chain_data),
                       "chain": chain_data
                       })


#start mining
@app.route('/mine', methods=['GET'])
def mine_confirmed_transactions():
    result = blockchain.mine()
    if not result:
        return "No transactions to mine"
    else:
        # Making sure we have the longest chain before announcing to the network
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            # announce the recently mined block to the network
            announce_new_block(blockchain.last_block)
        chain_data = []
        for block in blockchain.chain:
            chain_data.append(block.__dict__)
        print(json.dumps({"length": len(chain_data),
                          "chain": chain_data
                          }))
        print(len(blockchain.chain))
        return "Block #{} is mined.".format(blockchain.last_block.index)



@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400
    peers.add(node_address)
    return get_chain()


#called by other nodes
#verify the received block
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    if block_data['index'] != blockchain.chain[-1].index + 1:
        consensus()
        return "The block was not expected", 400
    block = Block(block_data["index"],
                  block_data['merkle_hash'],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])
    proof = block_data['hash']
    added = blockchain.add_block(block, proof)
    if not added:
        return "The block was discarded by the node", 400
    return "Block added to the chain", 201



#longest chain selection
def consensus():
    global blockchain
    longest_chain = None
    current_len = len(blockchain.chain)
    for node in peers:
        #broad requests
        response = requests.get('{}/chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        #check longest chain validity
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain
    if longest_chain:
        blockchain = longest_chain
        r.delete('chain')
        for block in blockchain:
            block_string = json.dumps(block.__dict__)
            r.hset('chain', block.hash, block_string)
        return True
    return False


def announce_new_block(block):
    for peer in peers:
        url = "{}/add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)





if __name__ == '__main__':

    r = redis.Redis(host='localhost', port=6379, db=0)

    #create block for each request
    blockchain = Blockchain()
    blockchain.create_genesis_block()
    block_data = r.hgetall('chain')

    #load blocks from redis
    for key, value in block_data.items():
        data = json.loads(value)
        block = Block(
            index=data['index'],
            merkle_hash=data['merkle_hash'],
            transactions=data['transactions'],
            timestamp=data['timestamp'],
            previous_hash=data['previous_hash'],
            nonce=data.get('nonce', 0)
        )
        blockchain.chain.append(block)

    #load confirmed transaction from redis
    confirmed_transactions = r.hgetall('confirmed_transactions')
    for key, value in confirmed_transactions.items():
        blockchain.confirmed_transactions.append(json.loads(value))
    peers.add('http://localhost:8000')
    app.run(debug=True, port=8000)
