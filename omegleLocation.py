from tabulate import tabulate
import scapy.all as scapy
import requests
import json

ips = []


def mostra_ip(x):
    global ips, ip

    try:
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

                        table = [
                            ["Ip:", resp['query']],
                            ["City:", resp['city']],
                            ["State:", resp['regionName']],
                            ["Region:", resp['region']],
                            ["Country:", resp['country']],
                            ["Postcode:", resp['zip']],
                            ["Org:", resp['org']]
                        ]
                        print()
                        print(tabulate(table))

                    else:
                        return f"ip: {ip} | Request error {resp['status']}"

                else:
                    return f"ip: {ip} | Error {dados.status_code}"
    except:
        pass


ip = input('Enter your IP [Press Enter for ALL]: ')

query = ''
if ip:
    query = f' src {ip}'

a = scapy.sniff(iface='Wi-Fi', prn=mostra_ip, filter=f"udp{query}")
