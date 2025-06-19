import stealth_requests
from ipwhois import IPWhois
from fake_useragent import UserAgent

ua = UserAgent()
headers = {'User-Agent': ua.random}


def format_ip_info(ip):
    url = f'https://ipapi.co/{ip}/json/'
    try:
        info = stealth_requests.get(url, headers).json()
        if 'error' in info:
            return f"Error: {info['reason']}"

        keys_order = [
            'ip',
            'city',
            'region',
            'country_name',
            'postal',
            'latitude',
            'longitude',
            'timezone',
            'org',
            'asn'
        ]

        output_lines = []
        for key in keys_order:
            value = info.get(key, 'N/A')
            output_lines.append(f"{key.replace('_', ' ').title()}: {value}")

        return '\n'.join(output_lines)

    except Exception as e:
        return f"An error occurred while fetching IP info: {str(e)}"


def format_whois_info(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()

        whois_info = {
            'ASN': results.get('asn', 'N/A'),
            'Organization': results.get('asn_description', 'N/A'),
            'Network Name': results.get('network', {}).get('name', 'N/A'),
            'Country': results.get('network', {}).get('country', 'N/A'),
            'CIDR': results.get('network', {}).get('cidr', 'N/A'),
            'Start Address': results.get('network', {}).get('start_address', 'N/A'),
            'End Address': results.get('network', {}).get('end_address', 'N/A'),
        }

        return whois_info

    except Exception as e:
        return f"An error occurred while fetching WHOIS info: {str(e)}"


if __name__ == "__main__":
    ip = input("Enter IP Address: ")
    formatted_info = format_ip_info(ip)
    whois_info = format_whois_info(ip)

    print(formatted_info)

    for key, value in whois_info.items():
        print(f"{key}: {value}")
