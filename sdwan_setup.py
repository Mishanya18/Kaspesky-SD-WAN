import requests
import json
import sys
import subprocess
from pathlib import Path
import shutil
import getpass
from requests_toolbelt import MultipartEncoder
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

ip = "192.168.200.100" # IP оркестратора, доступный для контроллера
ip_ext = "192.168.200.100" # IP оркестратора, доступный для CPE
stand_dir = "/home/user/installation/knaas-installer_2.25.03.release.10.cis.amd64_en-US_ru-RU" # Директория, содержащая дректорию ssl
pnfs_dir = "/home/user/installation/knaas-installer_2.25.03.release.10.cis.amd64_en-US_ru-RU/pnfs/pnf_sdwan_ctl" # Директория, содержащая образы pnf
cpes_mac_list = ["52540092C58A","5254009EA50D"] # Список мак адресов CPE для добавления в оркестратор
zabbix_proxy_host = "192.168.200.100" # IP адрес прокси, который будет отдаваться CPE
pnf_mgmt_ip = "192.168.200.100" # IP контроллера для коннекта к нему оркестратора
pnf_ext_ip = "192.168.200.100" # IP контроллера для коннекта к нему CPE
tenant_name = "Tenant1" # Имя создаваемого тенанта
pnf_name = "PNF for Tenant1" # Имя pnf для тенанта
dcName = "Tenant1DC" # Имя датацентра
mgmt_net_cidr = "10.11.1.0/24" # CIDR менеджмент сети
mgmt_net_start = "10.11.1.1" # первый IP для выдачи на CPE из менеджмент сети
mgmt_net_end = "10.11.1.254" # последний IP для выдачи на CPE из менеджмент сети

username = input("Введите логин пользователя оркестратора: ")
password = getpass.getpass(f"Введите пароль для пользователя {username}: ")
zabbix_passwd = getpass.getpass(f"Введите пароль для пользователя Admin в Zabbix: ")

sess = requests.Session()
sess.verify = False

try:
    response=sess.get('https://'+ ip +'/api/core/users/current')
    response=sess.post(('https://'+ ip +'/api/authentication'), data={'j_username': username, 'j_password': password},headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    if response.status_code != 200:
        if response.status_code == 403 and response.json()[0]['code'] == "required_2fa_code":
            secFA_code = getpass.getpass(f"Введите код двухфакторной аутентификации: ")
            response=sess.post(('https://'+ ip +'/api/authentication'), data={'j_username': username, 'j_password': password, 'code': secFA_code},headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
            if response.status_code != 200:
                print("Неудачная аутентификация")
                print(f"Неудачная аутентификация. Error: {response}")
                sys.exit(1)
        else:
            print(f"Неудачная аутентификация. Error: {response}")
            sys.exit(1)
except Exception as e:
    print(f"Неудачная аутентификация. Error: {e}")
    sys.exit(1)

sess.get('https://'+ ip +'/api/core/settings/defpage')
sess.headers.update({'Accept': 'application/json','content-type': 'application/json','X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})

# Add Domain
domain = {"name": "Domain"}
try:
    response=sess.post(('https://'+ ip +'/api/core/domains'), data=json.dumps(domain),headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    dmnID = response.json()['id']
except:
    try:
        if response.json()[0]['code'] == "domain_already_exists":
            response=sess.get('https://'+ ip +'/api/core/domains',headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
            dmnID = response.json()['content'][0]['id']
            if response.json()['content'][0]['datacenters']:
                dcID = response.json()['content'][0]['datacenters'][0]['id']
    except Exception as e:
        print("Не удалось добавить Domain", e)
        print(response.content)

# Create Data Center
if 'dcID' not in locals():
    dataCenter = {"name": dcName, "vnfmUrl": "https://vnfm-proxy:86"}
    try:
        response=sess.post(('https://'+ ip +'/api/core/dc?dmnID=' + dmnID), data=json.dumps(dataCenter),headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
        dcID = response.json()['id']
    except Exception as e:
        print("Не удалось добавить Data Center", e)
        print(response.content)

# Create mgmt subnet
subnet = {
  "ipVersion": "V4",
  "type": "MANAGEMENT",
  "datacenterId": dcID,
  "domainId": dmnID,
  "name": "Management",
  "cidr": mgmt_net_cidr,
  "ranges": [
    {
      "lowIp": mgmt_net_start,
      "highIp": mgmt_net_end
    }
  ]
}
try:
    response=sess.post(('https://'+ ip +'/api/nfv/subnet'), data=json.dumps(subnet),headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
except Exception as e:
    if response.json()[0]['code'] == "vnf_subnet_name_exists":
        pass
    else:
        print("Не удалось добавить Management Subnet", e)

# Add Monitoring
zabbix = {
  "type": "ZABBIX",
  "url": "https://zbx-www:8443/api_jsonrpc.php",
  "login": "Admin",
  "password": zabbix_passwd,
  "token": "NTBiMi0zMzRlLTQ3NzYtYWE1My0xMzhlOThjMzE5OWE=",
  "nfGroup": "VNFGROUP",
  "cpeGroup": "CPEGROUP",
  "grouping": "GROUP",
  "triggersSyncPeriod": "600"
}
try:
    response=sess.put(('https://'+ ip +'/api/nfv/zabbix/settings'), data=json.dumps(zabbix),headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
except Exception as e:
    print("Не удалось добавить Zabbix Server", e)


# Add zabbix proxy
zabbix_proxy = {
  "host": zabbix_proxy_host,
  "name": "zabbix-proxy"
}
try:
    response=sess.put(('https://'+ ip +'/api/nfv/zabbix-proxy?dcId='+ dcID), data=json.dumps(zabbix_proxy),headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
except Exception as e:
    print("Не удалось добавить Zabbix Proxy", e)

# Create Tenant
tenant = {
  "name": tenant_name,
  "description": "",
  "groups": [],
  "limits": {
    "cpuCores": -1,
    "memoryInGb": -1,
    "storageInGb": -1
  }
}
try:
    response=sess.get('https://'+ ip +'/api/core/tenants',headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    if len(response.json()['content']):
      tenantID = response.json()['content'][0]['id']
    else:
      response=sess.post(('https://'+ ip +'/api/core/tenants'), data=json.dumps(tenant),headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
      tenantID = response.json()['id']
except Exception as e:
    if response.json()[0]['code'] == "tenant_name_already_exists":
        pass
    else:
        print("Не удалось добавить тенанта", e)

# Upload Certificate
cert_file = stand_dir + '/ssl/ca/certificate.pem'

cert_file_data = MultipartEncoder(
    fields={
        'file': (cert_file, open(cert_file, 'rb'), 'application/x-gzip'),
    }
)

try:
    response=sess.post(('https://'+ ip +'/api/nfv/sdwan/certificate/upload'), data=cert_file_data, headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN'], 'Content-Type': cert_file_data.content_type})
except Exception as e:
    print("Не удалось загрузить Сертификат", e)

# Edit PNF
src = Path(pnfs_dir+"/src/pnfd.xml")
dst = Path(pnfs_dir+"/src/pnfd_template.xml")

if not dst.exists():
    shutil.copy2(src, dst) 

with open(pnfs_dir+"/src/pnfd_template.xml", 'r', encoding='utf-8') as file:
    content = file.read()

new_content = content.replace("SD-WAN CTL PNF", pnf_name)

with open(pnfs_dir+"/src/pnfd.xml", 'w', encoding='utf-8') as file:
    file.write(new_content)

# Create PNF
try:
    result = subprocess.run(
        "make",
        cwd=pnfs_dir,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
except subprocess.CalledProcessError as e:
    print("Ошибка при выполнении make:")
    print(e.stderr)
    sys.exit(1)

# Upload PNF
file_name = str(next(Path(pnfs_dir+"/build").glob("pnf_sdwan_ctl*.tar.gz"), None))

if file_name is not None:
    multipart_data = MultipartEncoder(
        fields={
            'multipartFile': (file_name, open(file_name, 'rb'), 'application/x-gzip'),
            'hash': ''
        }
    )

    try:
        response=sess.post(('https://'+ ip +'/api/nfv/pnf/upload'), data=multipart_data, headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN'], 'Content-Type': multipart_data.content_type})
        pnfID = response.json()['id']
    except Exception as e:
        print("Не удалось добавить PNF", e)
else:
    print("Файл не найден.")

# Set DataCenter for PNF
try:
    response=sess.put(('https://'+ ip +'/api/nfv/pnf/' + pnfID + '/dc/' + dcID), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
except Exception as e:
    print("Не удалось добавить DC для PNF", e)

# Set and test PNF Connection
connection = {
  "flavourName": "Standard",
  "pnfId": pnfID,
  "ip": pnf_mgmt_ip,
  "vduName": "ctl"
}
try:
    response=sess.post(('https://'+ ip +'/api/nfv/pnf/available'), data=json.dumps(connection), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    if response.json()['isAvailable']:
        pass
    else:
        print("PNF не доступна по Mgmt IP!")
except Exception as e:
    print("Ошибка проверки доступности PNF", e)

# Save PNF
pnf = {
  "connectionDetails": [
    {
      "connections": [],
      "flavour": "Standard",
      "managementNetworks": [
        {
          "vduName": "ctl",
          "ip": pnf_mgmt_ip
        }
      ]
    }
  ],
  "backupConfigurations": []
}
try:
    response=sess.put(('https://'+ ip +'/api/nfv/pnf/' + pnfID + '/settings'), data=json.dumps(pnf), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
except Exception as e:
    print("Не удалось сохранить PNF", e)

# Create PNF Template
with open(stand_dir + '/ssl/ca/certificate.pem') as cert_file:
    cert = cert_file.read()

pnf_template = {
  "services": [],
  "unis": [],
  "vnfs": [],
  "pnfs": [
    {
      "id": "123123",
      "alias": pnf_name,
      "existed": False,
      "flavour": "Standard",
      "pnfdId": pnfID,
      "coords": {
        "x": 700,
        "y": 300
      },
      "connections": [],
      "managementNetworks": [],
      "backupConfigurations": [],
      "userConfiguration": {
        "variables": {
          "cacert": cert,
          "orc_ip": ip,
          "orc_port": "443",
          "orc_proto": "https",
          "ctl1_ip": pnf_mgmt_ip,
          "ctl1_port": "6653",
          "ctl1_external_ip": pnf_ext_ip
        }
      }
    }
  ],
  "vms": [],
  "id": "?",
  "sharedNetworkServices": [],
  "routers": [],
  "name": tenant_name + "SD-WAN Template"
}
try:
    response=sess.post(('https://'+ ip +'/api/nfv/nst'), data=json.dumps(pnf_template), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    nstID = response.json()['id']
except Exception as e:
    print("Не удалось добавить PNF Template", e)

# Allow Tenant to use PNF Template
try:
    response=sess.put(('https://'+ ip +'/api/core/tenants/' + tenantID + '/catalog/NST/' + nstID), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
except Exception as e:
    print("Не удалось добавить PNF Template к Tenant", e)

# Save NS in Tenant
tenant_ns = {
  "id": "321",
  "vnfs": [],
  "pnfs": [
    {
      "id": "123",
      "alias": pnf_name,
      "pnfdId": pnfID,
      "flavour": "Standard",
      "order": 0,
      "coords": {
        "x": 700,
        "y": 300
      },
      "userConfiguration": {
        "variables": {
          "ctl1_ip": pnf_mgmt_ip,
          "cacert": cert,
          "orc_port": "443",
          "ctl1_port": "6653",
          "orc_ip": ip,
          "orc_proto": "https",
          "ctl1_external_ip": pnf_ext_ip
        }
      },
      "existed": False
    }
  ],
  "vms": [],
  "unis": [],
  "services": [],
  "sharedNetworkServices": [],
  "routers": [],
  "name": tenant_name + "SD-WAN NS"
}
try:
    response=sess.post(('https://'+ ip +'/api/nfv/ns'), data=json.dumps(tenant_ns), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN'], "X-Override-Tenant-ID": tenantID})
    tenant_nsID = response.json()['id']
except Exception as e:
    print("Не удалось добавить NS для тенанта", e)

# Deploy Tenant's ns
try:
    response=sess.put(('https://'+ ip +'/api/nfv/ns/' + tenant_nsID + '/deploy'), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN'], "X-Override-Tenant-ID": tenantID})
except Exception as e:
    print("Не удалось задеплоить сетевой сервис тенанта", e)

# Get default wan fw zone
try:
    response = sess.get((f'https://{ip}/api/nfv/sdwan/cpe/zone?name=wan&page=0&size=1&sort=%5B%22string%22%5D'), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    fwzoneid = response.json()['content'][0]['id']
except Exception as e:
    print(f"Не удалось найти default wan fw zone. Error: {e}")

#Create CPE Template
cpeTemplate = {
  "linksEncrypted": False,
  "bfdSettings": {
    "enabled": False,
    "peers": [],
    "overridden": False
  },
  "multicast": {
    "globals": {
      "enabled": False,
      "overridden": False
    },
    "multicastInterfaces": {
      "entries": [],
      "overridden": False
    }
  },
  "id": "CPE_Template_ID",
  "name": "vCPE",
  "type": "CPE",
  "configurationSettings": {
    "managementPort": 22,
    "defaultLogin": "root"
  },
  "sdnServices": [],
  "multipathing": {
    "enableMultiWeight": True,
    "maxPathNum": 8,
    "maxSpfPathNum": 2,
    "pathCostVariance": 10
  },
  "sdWanSettings": {
    "globals": {
      "protocol": "HTTPS",
      "server": ip_ext,
      "port": 443,
      "backup": False,
      "ofTransport": "SSL",
      "rebootOnFail": False,
      "rebootTimeout": 86400,
      "updateIntervalSec": 30,
      "urlZtpTemplate": "http://127.0.0.1/cgi-bin/config?payload={config}",
      "overridden": False,
      "interactiveModeTimeout": 180,
      "interactiveModeUpdateIntervalSec": 3,
      "priorityInterface": {
        "preemption": False
      }
    },
    "interfaces": [
      {
        "alias": "sdwan0",
        "isDisabled": False,
        "trackIps": [
          "8.8.8.8"
        ],
        "trackFragIps": [
          "1.1.1.1"
        ],
        "type": "WAN",
        "ofPortNumber": 4800,
        "reliability": 1,
        "count": 2,
        "timeout": 2000,
        "interval": 2,
        "down": 3,
        "up": 2,
        "netperf": False,
        "maxRate": 1000,
        "cos": [
          {
            "queue": "sdwan0_q0_be",
            "index": 8,
            "qtag": "0",
            "minRate": 10,
            "maxRate": 100,
            "name": "be"
          },
          {
            "queue": "sdwan0_q1_bn",
            "index": 7,
            "qtag": "1",
            "minRate": 10,
            "maxRate": 100,
            "name": "bn"
          },
          {
            "queue": "sdwan0_q2_bc",
            "index": 6,
            "qtag": "2",
            "minRate": 10,
            "maxRate": 100,
            "name": "bc"
          },
          {
            "queue": "sdwan0_q3_vid",
            "index": 5,
            "qtag": "3",
            "minRate": 10,
            "maxRate": 100,
            "name": "vid"
          },
          {
            "queue": "sdwan0_q4_conf",
            "index": 4,
            "qtag": "4",
            "minRate": 10,
            "maxRate": 100,
            "name": "conf"
          },
          {
            "queue": "sdwan0_q5_sig",
            "index": 3,
            "qtag": "5",
            "minRate": 10,
            "maxRate": 100,
            "name": "sig"
          },
          {
            "queue": "sdwan0_q6_rt",
            "index": 2,
            "qtag": "6",
            "minRate": 10,
            "maxRate": 50,
            "name": "rt"
          },
          {
            "queue": "sdwan0_q7_nc",
            "index": 1,
            "qtag": "7",
            "minRate": 30,
            "maxRate": 100,
            "name": "nc"
          }
        ],
        "publicAddress": {
          "type": "DISABLED"
        },
        "controllers": []
      },
      {
        "alias": "sdwan1",
        "isDisabled": False,
        "trackIps": [
          "8.8.8.8"
        ],
        "trackFragIps": [
          "1.1.1.1"
        ],
        "type": "WAN",
        "ofPortNumber": 4801,
        "reliability": 1,
        "count": 2,
        "timeout": 2000,
        "interval": 2,
        "down": 3,
        "up": 2,
        "netperf": False,
        "maxRate": 1000,
        "cos": [
          {
            "queue": "sdwan1_q0_be",
            "index": 8,
            "qtag": "0",
            "minRate": 10,
            "maxRate": 100,
            "name": "be"
          },
          {
            "queue": "sdwan1_q1_bn",
            "index": 7,
            "qtag": "1",
            "minRate": 10,
            "maxRate": 100,
            "name": "bn"
          },
          {
            "queue": "sdwan1_q2_bc",
            "index": 6,
            "qtag": "2",
            "minRate": 10,
            "maxRate": 100,
            "name": "bc"
          },
          {
            "queue": "sdwan1_q3_vid",
            "index": 5,
            "qtag": "3",
            "minRate": 10,
            "maxRate": 100,
            "name": "vid"
          },
          {
            "queue": "sdwan1_q4_conf",
            "index": 4,
            "qtag": "4",
            "minRate": 10,
            "maxRate": 100,
            "name": "conf"
          },
          {
            "queue": "sdwan1_q5_sig",
            "index": 3,
            "qtag": "5",
            "minRate": 10,
            "maxRate": 100,
            "name": "sig"
          },
          {
            "queue": "sdwan1_q6_rt",
            "index": 2,
            "qtag": "6",
            "minRate": 10,
            "maxRate": 50,
            "name": "rt"
          },
          {
            "queue": "sdwan1_q7_nc",
            "index": 1,
            "qtag": "7",
            "minRate": 30,
            "maxRate": 100,
            "name": "nc"
          }
        ],
        "publicAddress": {
          "type": "DISABLED"
        },
        "controllers": []
      },
      {
        "alias": "overlay",
        "isDisabled": False,
        "trackIps": [],
        "trackFragIps": [],
        "type": "LAN",
        "ofPortNumber": 2,
        "netperf": False,
        "maxRate": 1000,
        "cos": [
          {
            "queue": "l_q0",
            "name": "be",
            "index": 0,
            "priority": 7,
            "minRate": 10,
            "maxRate": 100
          },
          {
            "queue": "l_q1",
            "name": "bn",
            "index": 1,
            "priority": 6,
            "minRate": 10,
            "maxRate": 100
          },
          {
            "queue": "l_q2",
            "name": "bc",
            "index": 2,
            "priority": 5,
            "minRate": 10,
            "maxRate": 100
          },
          {
            "queue": "l_q3",
            "name": "vid",
            "index": 3,
            "priority": 4,
            "minRate": 10,
            "maxRate": 100
          },
          {
            "queue": "l_q4",
            "name": "conf",
            "index": 4,
            "priority": 3,
            "minRate": 10,
            "maxRate": 100
          },
          {
            "queue": "l_q5",
            "name": "sig",
            "index": 5,
            "priority": 2,
            "minRate": 10,
            "maxRate": 100
          },
          {
            "queue": "l_q6",
            "name": "rt",
            "index": 6,
            "priority": 1,
            "minRate": 10,
            "maxRate": 50
          },
          {
            "queue": "l_q7",
            "name": "nc",
            "index": 7,
            "priority": 0,
            "minRate": 30,
            "maxRate": 100
          }
        ],
        "controllers": []
      },
      {
        "alias": "mgmt",
        "isDisabled": False,
        "trackIps": [],
        "trackFragIps": [],
        "type": "MANAGEMENT",
        "ofPortNumber": 1,
        "netperf": False,
        "cos": [],
        "controllers": []
      }
    ]
  },
  "topology": {
    "role": "CPE",
    "tags": [],
    "overridden": False
  },
  "networkSettings": {
    "isEnabled": True,
    "interfaces": [
      {
        "protocol": "DHCP",
        "isDisabled": False,
        "alias": "sdwan0",
        "l2Mode": False,
        "interfaceName": "eth0",
        "firewallZone": {
          "id": fwzoneid,
          "used": True,
          "system": True,
          "createdBy": "Admin",
          "createdDate": "2024-10-24T07:55:26.476Z",
          "name": "wan",
          "input": "REJECT",
          "output": "ACCEPT",
          "forward": "REJECT",
          "mtuFix": True,
          "dropsLogging": False,
          "networks": []
        },
        "isDefaultRoute": True,
        "dns": [
          "8.8.8.8"
        ],
        "isAuto": True,
        "isForceLink": False,
        "ip6classes": [],
        "modes": [],
        "overridden": False
      },
      {
        "protocol": "DHCP",
        "isDisabled": False,
        "alias": "sdwan1",
        "l2Mode": False,
        "interfaceName": "eth1",
        "firewallZone": {
          "id": fwzoneid,
          "used": True,
          "system": True,
          "createdBy": "Admin",
          "createdDate": "2024-10-24T07:55:26.476Z",
          "name": "wan",
          "input": "REJECT",
          "output": "ACCEPT",
          "forward": "REJECT",
          "mtuFix": True,
          "dropsLogging": False,
          "networks": []
        },
        "isDefaultRoute": True,
        "dns": [
          "8.8.8.8"
        ],
        "isAuto": True,
        "isForceLink": False,
        "ip6classes": [],
        "modes": [],
        "overridden": False
      }
    ]
  },
    "syslogSettings": {
      "logSizeKb": 64,
      "protocol": "UDP"
    },
    "ntpSettings": {
      "enabled": True,
      "servers": [
        "pool pool.ntp.org"
      ]
    },
    "topology": {
      "role": "CPE"
    },
    "vrrp": {
      "vrrpInstances": {
        "enabled": False,
        "entries": []
      },
      "vrrpGroups": []
    },
    "networkSettings": {
      "isEnabled": True,
      "interfaces": []
    },
    "staticRoutes": {
      "entries": []
    },
    "bgpSettings": {
      "entries": []
    },
    "routingFilters": {
      "prefixList": {
        "entries": []
      },
      "routeMap": {
        "entries": []
      },
      "accessList": {
        "entries": []
      }
    },
    "bfdSettings": {
      "enabled": False,
      "peers": []
    },
    "configurationSettings": {
      "defaultLogin": "root",
      "managementPort": 22
    },
    "sdnServices": [],
    "ospf": {
      "globals": {
        "enabled": False,
        "abrType": "IBM"
      }
    },
    "multicast": {
      "globals": {
        "enabled": False,
        "overridden": False
      },
      "multicastInterfaces": {
        "entries": []
      }
    },
    "cfm": {
      "enabled": False,
      "interval": "1s"
    },
    "monitoringConfiguration": {
      "monitoringType": "AGENT",
      "zabbixTemplate": "Linux by Zabbix agent active"
    },
    "pbr": {
      "entries": []
    }
  }
try:
    response=sess.post(('https://'+ ip +'/api/nfv/sdwan/cpe/template'), data=json.dumps(cpeTemplate), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    cpeTemplateID = response.json()['id']
except Exception as e:
    print("Не удалось добавить CPE Template", e)

# Whait for sdwan instance
try:
    print("Ждём создания SD-WAN Instance и перехода его в статус OK")
    while True:
      response=sess.get('https://'+ ip +'/api/nfv/sdwan/inventory',headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
      if response.content != b'[]':
        if response.json()[0]['status'] == 'OK':
          break
except Exception as e:
    print("Не удалось найти SD-WAN Instance", e)

# Get default Firewall template
try:
    response=sess.get('https://'+ ip +'/api/nfv/sdwan/cpe/firewallTemplate/default',headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    dfwID = response.json()['id']
except Exception as e:
    print("Не удалось найти Default CPE Firewall Template", e)

# Get default Net Flow Template
try:
    response=sess.get('https://'+ ip +'/api/nfv/sdwan/netflow/default',headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
    dnfID = response.json()['id']
except Exception as e:
    print("Не удалось найти Default NetFlow template", e)

# Create CPE
if cpes_mac_list:
  i = 1
  cpes_ids = []
  for mac in cpes_mac_list:
    cpe = {
      "name": "vCPE-" + str(i),
      "dpid": "8000" + mac.replace(':', ''),
      "authenticationMethod": "KEY",
      "templateId": cpeTemplateID,
      "tenantId": tenantID,
      "sdWanNetworkServiceRecordPoolId": "null",
      "isActivated": True,
      "firewallTemplate": {
        "id": dfwID,
        "name": "Default firewall template"
      },
      "netFlowTemplate": {
        "id": dnfID,
        "name": "Default NetFlow template"
      }
    }
    try:
        response=sess.post(('https://'+ ip +'/api/nfv/sdwan/cpe/inventory'), data=json.dumps(cpe), headers={'X-CSRF-TOKEN': sess.cookies['CSRF-TOKEN']})
        cpes_ids.append(response.json()['id'])
        i += 1
    except Exception as e:
        print("Не удалось создать CPE", e)
