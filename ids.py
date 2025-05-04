def rabin_karp(text, pattern, q=101):
    d = 256
    M = len(pattern)
    N = len(text)
    p = 0
    t = 0
    h = 1

    for i in range(M - 1):
        h = (h * d) % q

    for i in range(M):
        p = (d * p + ord(pattern[i])) % q
        t = (d * t + ord(text[i])) % q

    for i in range(N - M + 1):
        if p == t:
            if text[i:i + M] == pattern:
                return True
        if i < N - M:
            t = (d * (t - ord(text[i]) * h) + ord(text[i + M])) % q
            if t < 0:
                t += q
    return False

def load_signatures(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def scan_log_file(log_path, signatures):
    with open(log_path, 'r') as file:
        lines = file.readlines()
        for line_number, line in enumerate(lines, start=1):
            for sig in signatures:
                if rabin_karp(line.lower(), sig.lower()):
                    print(f"[ALERT] Threat Detected: '{sig}' in Line {line_number}")
                    break

if __name__ == "__main__":
    signatures = load_signatures("signatures.txt")
    scan_log_file("sample_log.txt", signatures)
