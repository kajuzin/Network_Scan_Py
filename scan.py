import urllib.request
import json
import time
import requests
import socket
import ipaddress
import csv
from scapy.all import ARP, Ether, srp


def get_first_valid_ip(ip_address, subnet_mask):
    """
    Obtém o primeiro endereço IP válido da rede a partir de um endereço IP e uma máscara de sub-rede.
    """
    network = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)
    for ip in network.hosts():
        if str(ip) != str(ip_address):
            return str(ip)
    return None



# Cria uma lista vazia para armazenar as informações dos dispositivos
print("Programa executando...")

devices = []

# Obter o nome de host do sistema
host_name = socket.gethostname()
# Obter o endereço IP local
print("Dados da Rede Local!")
print("")

ip_address_local = socket.gethostbyname(host_name)
print("Meu endereço IP local é:", ip_address_local)
subnet_mask = "255.255.255.0"
ip_address = ipaddress.IPv4Address(ip_address_local)
network = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)
ip_address_subnesk = str(network.network_address)
print("Endereço da sub-rede:", ip_address_subnesk)
first_valid_ip = get_first_valid_ip(str(network.network_address), subnet_mask)
if first_valid_ip:
    print("Primeiro endereço IP válido da rede:", first_valid_ip)
    ip_scan = first_valid_ip+"/24"
else:
    print("Não foi possível encontrar um endereço IP válido na rede.")


# Obter o endereço de IP Público
response = requests.get('https://api.ipify.org')
ip_address = response.text
print("Meu endereço IP Publíco é:", ip_address)

# Cria um pacote ARP para escanear a rede
arp = ARP(pdst=ip_scan)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

# Envia o pacote ARP e aguarda as respostas
result = srp(packet, timeout=10, verbose=0)[0]

for sent, received in result:
    devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    mac_address = str(received.hwsrc)
    url = "https://api.macvendors.com/"+mac_address
    try:
        response = urllib.request.urlopen(url).read().decode()
        if response:
            modelo = response
        else:
            modelo = "Not Found"
        time.sleep(2)

    except urllib.error.HTTPError as e:
             if e.code == 404:   
                print("Erro 404: Endereço MAC não encontrado na API")
                modelo = "Not Found"
             else:    
                 print("Erro ao buscar informações na API: ", e)
                 modelo = "Not Found"  
    time.sleep(2)
   
    with open('devices.txt', 'a') as f:
        f.write(f"IP: {received.psrc}  \tMAC:  {received.hwsrc}  \tModelo: {modelo}\n")          

print("Programa finalizado...")
