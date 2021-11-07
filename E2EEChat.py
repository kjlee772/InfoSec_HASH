import socket
import threading

import base64
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA

# 서버 연결정보; 자체 서버 실행시 변경 가능
SERVER_HOST = "homework.islab.work"
SERVER_PORT = 8080

connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))

### CBC를 위한 패딩 ###
BS = 16
pad = lambda s: s + ( BS- len(s.encode('utf-8')) % BS) * chr(BS - len(s.encode('utf-8')) % BS)
unpad = lambda s: s[0:-s[-1]]

### 공개키, 개인키 생성
random_seed = Random.new().read
generated_key = RSA.generate(2048, random_seed)

my_pub_key = generated_key.publickey().export_key()
my_pri_key = generated_key.export_key()
recv_pub_key = None

def socket_read():
    while True:
        readbuff = connectSocket.recv(2048)

        if len(readbuff) == 0:
            continue

        recv_payload = readbuff.decode('utf-8')
        parse_payload(recv_payload)

def socket_send():
    while True:
        str = ""
        mode = input("\nCHOOSE MODE(1.CONNECT, 2.DISCONNECT, 3.KEYXCHG, 4.KEYXCHGRST, 5.MSGSEND, 6.chk_key, 7.chk_iv)")

        if mode == "1":     ### 연결하기
            print("3EPROTO CONNECT")
            name = input("Credential: ")
            str = "3EPROTO CONNECT\n"+"Credential:"+name

        elif mode == "2":   ### 연결 끊기
            print("3EPROTO DISCONNECT")
            name = input("Credential: ")
            str = "3EPROTO DISCONNECT\n"+"Credential:"+name

        elif mode == "3":       ### 키 교환
            print("3EPROTO KEYXCHG")
            print("Algo: AES-256-CBC")
            sender = input("From: ")
            receiver = input("To: ")
            print()

            send_key = base64.b64encode(my_pub_key).decode('utf-8')     ### 자신의 공개키를 상대에게 보내기 위해

            print(send_key)

            str = "3EPROTO KEYXCHG\n"+"Algo: AES-256-CBC\n"+"From: "+sender+"\n"+"To: "+receiver+"\n\n"+send_key

        elif mode == "4":       ### 키 변경
            print("3EPROTO KEYXCHGRST")
            print("Algo: AES-256-CBC")
            sender = input("From: ")
            receiver = input("To: ")
            print()

            send_key = base64.b64encode(my_pub_key).decode('utf-8')

            print(send_key)

            str = "3EPROTO KEYXCHG\n"+"Algo: AES-256-CBC\n"+"From: "+sender+"\n"+"To: "+receiver+"\n\n"+send_key

        elif mode == "5":       ### 메세지 송신     (상대방의 공개키로 암호화된 세션키/IV, 세션키로 암호화된 메시지를 전송해야한다.)
            print("3EPROTO MSGSEND")
            sender = input("From: ")
            receiver = input("To: ")
            nonce = input("Nonce: ")
            print()
            input_message = input()         ### 사용자에게 메세지를 입력받는다.

            session_key = Random.new().read(32)     ### 세션키 만들기
            iv = Random.new().read(16)              ### IV 만들기
            encrypt_message = encrypt_str(input_message, session_key, iv)   ### 세션키로 암호화된 메시지
            
            key = RSA.importKey(recv_pub_key)
            cipher = PKCS1_OAEP.new(key)
            enc_session_key = cipher.encrypt(session_key)       ### 상대방의 공개키로 세션키 암호화하기
            send_enc_session_key = base64.b64encode(enc_session_key).decode('utf-8')
            enc_iv = cipher.encrypt(iv)                         ### 상대방의 공개키로 IV 암호화하기
            send_enc_iv = base64.b64encode(enc_iv).decode('utf-8')

            # print(encrypt_message)
            
            str = "3EPROTO MSGSEND\n"+"From: "+sender+"\n"+"To: "+receiver+"\n"+"Nonce: "+nonce+"\n\n"+encrypt_message+"\n"+send_enc_session_key+"\n"+send_enc_iv
            ### 세션키로 암호화된 메시지, 상대방의 공개키로 암호화된 세션키와 IV가 전송된다.

        
        send_bytes = str.encode('utf-8')
        connectSocket.send(send_bytes)

def parse_payload(payload):
    # 수신된 페이로드를 여기서 처리; 필요할 경우 추가 함수 정의 가능
    print('\n')
    print(payload)
    
    str_list = payload.split("\n")
    global recv_pub_key
    if "KEYXCHG" in str_list[0]:        ### 키 교환이 요청됐을 경우
        recv_pub_key = base64.b64decode(str_list[6])

    elif "MSGRECV" in str_list[0]:      ### 메세지를 받았을 경우
        recv_message = str_list[5]
        recv_enc_session_key = base64.b64decode(str_list[6])
        recv_enc_iv = base64.b64decode(str_list[7])
        
        key = RSA.importKey(my_pri_key)
        cipher = PKCS1_OAEP.new(key)
        dec_session_key = cipher.decrypt(recv_enc_session_key)      ### 자신의 개인키로 세션키 복호화
        dec_iv = cipher.decrypt(recv_enc_iv)
        dec_message = decrypt_str(recv_message, dec_session_key)    ## 복호화된 세션키로 메시지 복호화
        print(dec_message)

    pass

### 암호화 / 복호화 함수 ###
def encrypt(raw, key, iv):
    raw = pad(raw)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv+cipher.encrypt(raw.encode('utf-8')))
def encrypt_str(raw, key, iv):
    return encrypt(raw, key, iv).decode('utf-8')

def decrypt(enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))
def decrypt_str(enc, key):
    if type(enc) == str:
        enc = str.encode(enc)
    return decrypt(enc, key).decode('utf-8')


reading_thread = threading.Thread(target=socket_read)
sending_thread = threading.Thread(target=socket_send)

reading_thread.start()
sending_thread.start()

reading_thread.join()
sending_thread.join()