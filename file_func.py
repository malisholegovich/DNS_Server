import csv
import time

data_to_write = [
    ['domain', 'ip', 'expire_at'],
]


def write_in_cache(mass):
    with open('dns_cache.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(data_to_write + mass)


def get_dns_cache():
    cache_dict = {}
    try:
        with open('dns_cache.csv', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                expire_time = float(row['expire_at'])

                if expire_time > time.time():
                    cache_dict[row['domain']] = {
                        'ip': row['ip'],
                        'expire_at': expire_time
                    }

    except FileNotFoundError:
        pass

    return cache_dict
