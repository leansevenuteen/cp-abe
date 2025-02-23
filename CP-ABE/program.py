from charm.toolbox.pairinggroup import PairingGroup
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import SHAKE256
from KeyAgreement import key_agreement_encrypt, key_agreement_decrypt
from Cryptodome.Math._IntegerGMP import IntegerGMP
from charm.toolbox.secretutil import SecretUtil
from QueryDB import connect, UploadData, QueryData, LoadEncodedData
import os
import sys
import pickle
from BSW07_CPABE import CPabe_BSW07

groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)

db = connect("Crypto")

def push_data(Udata):
    access_policy = input("\nAccess policy: ")
    (pk, mk) = cpabe.setup()

    with open("system88/system_private_key.pem", "rt") as f:
        server_pri = ECC.import_key(f.read())

    server_pub = ECC.construct(
        curve=Udata['server_pubkey']['curve'],
        point_x=IntegerGMP(int(Udata['server_pubkey']['point_x'])),
        point_y=IntegerGMP(int(Udata['server_pubkey']['point_y']))
    )

    _prikey = {
        'curve': server_pri._curve.name,
        'point_x': str(server_pri.pointQ.x),
        'point_y': str(server_pri.pointQ.y),
        'd': str(server_pri.d)
    }
    _pubkey = {
        'curve': server_pub._curve.name,
        'point_x': str(server_pub.pointQ.x),
        'point_y': str(server_pub.pointQ.y)
    }

    ATTACK = {
        'pk': pk,
        'mk': mk,
    }

    f_path = input("\nPath to your file: ")
    with open(f_path, 'rb') as file:
        message = file.read()

    ct = cpabe.encrypt(pk, message, access_policy, _prikey, _pubkey)

    collection = db.EncodedData

    UploadData(groupObj, collection, ct, f_path, ATTACK)
    
def load_data(Udata):
    attributes = pickle.loads(Udata['attributes'])
    client_pub = ECC.construct(
        curve=Udata['public_key']['curve'],
        point_x=IntegerGMP(int(Udata['public_key']['point_x'])),
        point_y=IntegerGMP(int(Udata['public_key']['point_y']))
    )

    collection = db.EncodedData

    LoadEncodedData(collection)

    id = input("Document Id: ")
    ciphertext, f_name, ATTACK = QueryData(groupObj, collection, id)
    
    pk = ATTACK['pk']
    mk = ATTACK['mk']

    with open("system88/system_private_key.pem", "rt") as f:
        server_pri = ECC.import_key(f.read())

    sk = cpabe.keygen(pk, mk, attributes)

    nonce = os.urandom(64)

    encrypted_sk = key_agreement_encrypt(groupObj, sk, nonce, server_pri, client_pub)
    print("\nEncrypted Secret Key:\n", encrypted_sk)

    secret_pack = {
        'name': f_name,
        'cipher': ciphertext,
        'nonce': nonce
    }
    
    return secret_pack

def get_data(Udata, client_pri, secret_pack):
    f_name = secret_pack['name']
    cipher = secret_pack['cipher']
    nonce = secret_pack['nonce']

    server_pub = ECC.construct(
        curve=Udata['server_pubkey']['curve'],
        point_x=IntegerGMP(int(Udata['server_pubkey']['point_x'])),
        point_y=IntegerGMP(int(Udata['server_pubkey']['point_y']))
    )

    input_sk = eval(input("\nEnter Encrypted Secret Key:\n"))

    print("\nDecrypt Secret Key\n")
    decrypted_sk = key_agreement_decrypt(groupObj, input_sk, nonce, client_pri, server_pub)

    with open("system88/system_private_key.pem", "rt") as f:
        server_pri = ECC.import_key(f.read())

    _prikey = {
        'curve': server_pri._curve.name,
        'point_x': str(server_pri.pointQ.x),
        'point_y': str(server_pri.pointQ.y),
        'd': str(server_pri.d)
    }
    _pubkey = {
        'curve': server_pub._curve.name,
        'point_x': str(server_pub.pointQ.x),
        'point_y': str(server_pub.pointQ.y)
    }

    decrypted_message = cpabe.decrypt(decrypted_sk, cipher, _prikey, _pubkey)

    if decrypted_message != b'False':
        print("\nYou can access. Please check your folder\n")
        with open(f'decrypted_{f_name}', 'wb') as file:
            file.write(decrypted_message)
    else:
        print("You can't access this document!!\n")

def access_action(Udata):
    attrs = pickle.loads(Udata['attributes'])
    util = SecretUtil(groupObj, verbose=False)
    policy = util.createPolicy("Employee")
    pruned_list = util.prune(policy, attrs)
    return pruned_list

def login():
    phone = input("Enter your phone: ")
    password = input("Enter your password: ")
    collection = db.UsersData
    document = collection.find_one({'phone': phone})
    if document:
        if SHAKE256.new(password.encode('utf-8')).read(32) == document['password']:
            userdata = {
                'attributes': document['attributes'],
                'public_key': document['public_key'],
                'server_pubkey': document['server_pubkey']
            }
            return True, userdata
        else:
            print("Password not match")
    else:
        print("User not exist")
    
    return False, None

def register():
    phone = input("Enter your phone: ")
    username = input("Enter your name: ")
    password = input("Enter your password: ")
    auth_password = input("Confirm your password: ")

    collection = db.UsersData

    check_exists = collection.find_one({'phone': phone})
    if check_exists:
        os.system('clear')
        print("Phone number already exists")
        return False

    if password != auth_password:
        os.system('clear')
        print("Registration failed\nAuthentication password not match")
        return False

    obj = input("\nWho are you?\n1. Banker\n2. Officer\n3. Employee\nI'm a ")

    if obj == '1':
        role = "Banker"
    elif obj == '2':
        role = "Officer"
    elif obj == '3':
        role = "Employee"
    else:
        os.system('clear')
        print("Registration failed\nPlease choose your correct role!\n")
        return False
    
    company = input("\nWhat is your company?\nMy company is ")
    if company == '':
        os.system('clear')
        print("Registration failed\nYour company can't empty!\n")
        return False
    
    position = input("\nWhat is your position?\nI'm ")
    if position == '':
        os.system('clear')
        print("Registration failed\nYour position can't empty!\n")
        return False

    attributes = list(map(str.upper, [phone, username, role, company, position]))
    
    customer_pri = ECC.generate(curve='p256')

    with open("system88/system_public_key.pem", "rt") as f:
        server_pub = ECC.import_key(f.read())

    with open("customer_private_key.pem", "wt") as f:
        f.write(customer_pri.export_key(format='PEM'))

    document = {
        'phone': phone,
        'name': username,
        'password': SHAKE256.new(password.encode('utf-8')).read(32),
        'attributes': pickle.dumps(attributes),
        'public_key': {
            'curve': customer_pri.public_key()._curve.name,
            'point_x': str(customer_pri.public_key().pointQ.x),
            'point_y': str(customer_pri.public_key().pointQ.y)
        },
        'server_pubkey': {
            'curve': server_pub._curve.name,
            'point_x': str(server_pub.pointQ.x),
            'point_y': str(server_pub.pointQ.y)
        }
    }

    collection.insert_one(document)
    os.system('clear')
    print("Registered successfully")

    return True


def run_program(Udata):
    while True:
        if access_action(Udata):
            print("1. Push data\n")
        print("2. Get data\n")
        choice = input("Your choice: ")
        if choice == '1':
            push_data(Udata)
        elif choice == '2':
            accept = input("What actions are allowed using your private key?\n1. Allow\n2. Cancel\n")
            if accept == '1':
                with open("customer_private_key.pem", "rt") as f:
                    customer_pri = ECC.import_key(f.read())
                pack = load_data(Udata)
                get_data(Udata, customer_pri, pack)
            elif accept == '2':
                os.system('clear')
            else:
                print("\nPleases choose again!\n")
        elif choice == 'exit' or choice == 'quit':
            sys.exit(0)
        else:
            print("\nPleases choose again!\n")


if __name__ == "__main__":
    while True:
        print("1. Login\n")
        print("2. Register\n")
        choice = input("Your choice: ")
        if choice == '1':
            sucessLogin, Udata = login()
            if sucessLogin:
                print("Logged in successfully")
                run_program(Udata)
            else:
                print("Login failed")
        elif choice == '2':
            if register():
                sucessLogin, Udata = login()
                if sucessLogin:
                    print("Logged in successfully")
                    run_program(Udata)
                else:
                    print("Login failed")
            else:
                continue
        elif choice == 'exit' or choice == 'quit':
            sys.exit(0)
        else:
            print("\nPleases choose again!\n")