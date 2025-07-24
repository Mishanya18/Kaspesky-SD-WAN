import random
import string
import time
import sys
from zabbix_utils import ZabbixAPI

ZABBIX_AUTH = {
    "url": "https://"+ sys.argv[1] +":85",
    "user": "Admin",
    "password": "zabbix",
    "validate_certs": False
}

# Функция для проверки доступности веб-интерфейса Zabbix
def wait_for_zabbix(ZABBIX_AUTH, timeout=300, interval=5):
    start_time = time.time()
    while True:
        try:
            zabbix_api = ZabbixAPI(**ZABBIX_AUTH)
            if zabbix_api.version:
                zabbix_api.logout()
                break
        except:
            print("Веб-интерфейс Zabbix недоступен.")
        
        if time.time() - start_time > timeout:
            print("Превышено время ожидания доступности Zabbix.")
            raise Exception("Zabbix не доступен.")
        
        print(f"Ожидание доступности Zabbix... (ждем {interval} секунд)")
        time.sleep(interval)

# Ожидание доступности веб-интерфейса Zabbix
wait_for_zabbix(ZABBIX_AUTH)

zabbix_api = ZabbixAPI(**ZABBIX_AUTH)

proxy_name = 'zabbix-proxy'
proxy_ip = '10.11.11.129'

try:
    proxy_response = zabbix_api.proxy.create({
        'host': proxy_name,
        'status': 5,
        'proxy_address': proxy_ip,
        'tls_connect': 1,
        'tls_accept': 4
    })
except Exception as e:
    print("Ошибка добавления прокси:", e)

try:
    update_user_response = zabbix_api.user.update({
        'userid': zabbix_api.user.get({'filter': {'alias': ZABBIX_AUTH["user"]}})[0]['userid'],
        'passwd': sys.argv[2]
    })
    print("Пароль пользователя Admin изменен")
except Exception as e:
    print("Ошибка изменения пароля:", e)

zabbix_api.logout()
