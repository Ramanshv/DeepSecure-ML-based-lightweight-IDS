import socket
import time
import threading

def syn_flood():
    print("🚀 Triggering SYN/CONN Flood...")
    print("Spawning 150 concurrent connection attempts to trigger Rule Engine...")
    def hammer():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("10.35.56.52", 8888))
            s.close()
        except Exception:
            pass

    threads = []
    for _ in range(150):
        t = threading.Thread(target=hammer)
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()
    print("✅ Flood complete. Check dashboard for SYN/CONN HIGH alerts!")

def r2l_bruteforce():
    print("🚀 Triggering R2L (Remote-to-Local) Pattern...")
    print("Simulating a slow FTP/SSH brute force (high RST/Failed login count)...")
    
    # R2L is often characterized by repeated failed connection attempts 
    # to sensitive ports (21 FTP, 22 SSH) over a slightly longer duration.
    for i in range(15):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            # Connecting to closed ports deliberately causes RST (Connection Refused), 
            # which maps to `num_failed_logins` in the KDD Flow Extractor!
            s.connect(("10.35.56.52", 21)) 
            s.close()
        except:
            pass
        time.sleep(0.3)  # Slow enough to avoid DoS threshold, high enough to trigger anomaly target!
        
    print("✅ R2L simulation complete. Check dashboard for R2L ML Output!")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 simulate_attacks.py [syn | r2l]")
    elif sys.argv[1] == "syn":
        syn_flood()
    elif sys.argv[1] == "r2l":
        r2l_bruteforce()
