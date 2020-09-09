import scapy.all as scapy
import requests
import json

ips = []


def mostra_ip(x):
    global ips

    ip = x.payload.dst

    if not ip in ips:
        ips.append(ip)

        if not '192.168' in ip:

            try:
                dados = requests.get(f'http://ip-api.com/json/{ip}')
            except:
                return 0

            if dados.status_code == 200:
                resp = json.loads(dados.text)

                if resp["status"] == 'success':
                    return f"ip: {ip} | city: {resp['city']} | estado: {resp['regionName']} | uf: {resp['region']} | pais: {resp['country']} | org: {resp['org']}"
                else:
                    return f"ip: {ip} | Request error {resp['status']}"

            else:
                return f"ip: {ip} | Erro {dados.status_code}"


a = scapy.sniff(iface='Wi-Fi', prn=mostra_ip, filter="udp")
