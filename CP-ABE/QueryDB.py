from pymongo import MongoClient, errors
import datetime
from bson import ObjectId

def connect(database_name):
    try:
        client = MongoClient("mongodb+srv://webappdevclub:yZr44JTBCFRnqH8O@cryptocluster.nwrciji.mongodb.net/?retryWrites=true&w=majority&appName=CryptoCluster", 
                            tls=True, tlsAllowInvalidCertificates=True, serverSelectionTimeoutMS=5000)
        #client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
        client.server_info()
        print("Connect MongoDB Successfully!")
        return client[database_name]
    except errors.ServerSelectionTimeoutError as err:
        print(f"Connect MongoDB Failed: {err}")
        return None

# data = {
#   ct_gym, ct_abe
# }

def UploadData(groupObj, collection, data, f_path, ATTACK):
    f_name = f_path.split('/')[-1]
    name = f_name.split('.')[0]
    extension = f_name.split('.')[1]

    document = {}

    document["createdAt"] = datetime.datetime.now()
    document["name"] = name
    document["extname"] = extension

    key = {}
    for field in ATTACK:
        temp = {}
        for n_field in ATTACK[field]:
            temp[n_field] = groupObj.serialize(ATTACK[field][n_field])
        key[field] = temp
    document["key"] = key

    sym = data['ct_sym']
    cpabe = data['ct_abe']
    nonce = data['ct_nonce']

    ct_abe = {}
    ct_abe['C'] = groupObj.serialize(cpabe['C']) # pairing.Element
    ct_abe['C_tilde'] = groupObj.serialize(cpabe['C_tilde']) # pairing.Element
    ct_abe['Cy'] = {} # dict of pairing.Element
    for field in cpabe['Cy']:
        ct_abe['Cy'][field] = groupObj.serialize(cpabe['Cy'][field])
    ct_abe['Cyp'] = {} # dict of pairing.Element
    for field in cpabe['Cyp']:
        ct_abe['Cyp'][field] = groupObj.serialize(cpabe['Cyp'][field])
    ct_abe['policy'] = cpabe['policy'] # str
    ct_abe['policy'] = cpabe['policy'] # list

    document["ct_sym"] = sym
    document["ct_abe"] = ct_abe
    document["ct_nonce"] = nonce
        
    collection.insert_one(document)

    print("\nUpload successfully!\n")

def LoadEncodedData(collection):
    print()
    documents = collection.find()
    for docu in documents:
        print("ID: ", docu['_id'])
        print(f"Filename: {docu['name']}.{docu['extname']}")
        print("Created At: ", docu['createdAt'])
        print()

def QueryData(groupObj, collection, id):
    document = collection.find_one({'_id': ObjectId(id)})
    if document != None:
        sym = document["ct_sym"]
        cpabe = document["ct_abe"]
        nonce = document["ct_nonce"]

        ct_abe = {}
        ct_abe['C'] = groupObj.deserialize(cpabe['C']) # pairing.Element
        ct_abe['C_tilde'] = groupObj.deserialize(cpabe['C_tilde']) # pairing.Element
        ct_abe['Cy'] = {} # dict of pairing.Element
        for field in cpabe['Cy']:
            ct_abe['Cy'][field] = groupObj.deserialize(cpabe['Cy'][field])
        ct_abe['Cyp'] = {} # dict of pairing.Element
        for field in cpabe['Cyp']:
            ct_abe['Cyp'][field] = groupObj.deserialize(cpabe['Cyp'][field])
        ct_abe['policy'] = cpabe['policy'] # str
        ct_abe['policy'] = cpabe['policy'] # list

        f_name = f"{document['name']}.{document['extname']}"

        ATTACK = {}
        for field in document["key"]:
            temp = {}
            for n_field in document["key"][field]:
                temp[n_field] = groupObj.deserialize(document["key"][field][n_field])
            ATTACK[field] = temp

        return { 'ct_sym':sym, 'ct_abe':ct_abe, 'ct_nonce':nonce }, f_name, ATTACK
    