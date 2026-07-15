import math

def analyze_password(password, guesses_per_second):
    if not password:
        return "Please enter a password."

    # 1. Determine the character pool size (R)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    # Check for symbols (non-alphanumeric)
    has_special = any(not c.isalnum() for c in password)

    pool_size = 0
    detected_sets = []

    if has_lower:
        pool_size += 26
        detected_sets.append("Lowercase (a-z)")
    if has_upper:
        pool_size += 26
        detected_sets.append("Uppercase (A-Z)")
    if has_digit:
        pool_size += 10
        detected_sets.append("Numbers (0-9)")
    if has_special:
        pool_size += 32  # Standard US keyboard special characters
        detected_sets.append("Special Characters (~!@...) ")

    length = len(password)
    
    # 2. Calculate Entropy: L * log2(R)
    # If pool size is 0 (empty password or strange characters), entropy is 0
    entropy = length * math.log2(pool_size) if pool_size > 0 else 0
    
    # 3. Total possible combinations: R^L
    combinations = pool_size ** length

    # 4. Average cracking time (finding it halfway on average)
    # Time in seconds = (Combinations / 2) / Guesses_Per_Second
    if guesses_per_second <= 0:
        guesses_per_second = 1
    
    avg_seconds = (combinations / 2) / guesses_per_second

    # Convert seconds to a readable string
    time_string = format_time(avg_seconds)

    # 5. Determine security strength
    if entropy < 40:
        strength = "Weak (Easily cracked)"
    elif entropy < 60:
        strength = "Moderate (Acceptable for low-security)"
    elif entropy < 80:
        strength = "Strong (Secure against most attacks)"
    else:
        strength = "Overkill (Excellent security)"

    # Print results
    print(f"--- Analysis for: '{password}' ---")
    print(f"Length (L):          {length} characters")
    print(f"Pool Size (R):       {pool_size} ({', '.join(detected_sets)})")
    print(f"Entropy:             {entropy:.2f} bits")
    print(f"Total Combinations:  {combinations:,}")
    print(f"Security Rating:     {strength}")
    print(f"Est. Crack Time:     {time_string} (at {guesses_per_second:,} guesses/sec)")
    print("-" * 40)


def format_time(seconds):
    """Converts seconds into a human-readable scale."""
    minute = 60
    hour = 3600
    day = 86400
    year = 31536000
    age_of_universe = 13.8e9 * year  # ~13.8 Billion Years

    if seconds < 0.001:
        return "Instantly"
    elif seconds < minute:
        return f"{seconds:.2f} seconds"
    elif seconds < hour:
        return f"{seconds / minute:.2f} minutes"
    elif seconds < day:
        return f"{seconds / hour:.2f} hours"
    elif seconds < year:
        return f"{seconds / day:.2f} days"
    elif seconds < (year * 1000):
        return f"{seconds / year:.2f} years"
    elif seconds < age_of_universe:
        return f"{seconds / (year * 1000):,.2f} millennia"
    else:
        return f"{seconds / age_of_universe:,.2f} lifetimes of the universe"


# --- DEMO SCENARIOS ---
if __name__ == "__main__":
    # Scenario A: Fast Online Attack (e.g., trying to brute force an SSH server at 100 guesses/sec)
    print("SCENARIO A: Online Network Attack (100 att/sec)")
    analyze_password("secret12", guesses_per_second=100)
    
    # Scenario B: Offline GPU Attack (e.g., hash cracking at 1,000,000,000 guesses/sec)
    print("\nSCENARIO B: Offline GPU Crack (1 Billion att/sec)")
    analyze_password("correcthorse", guesses_per_second=1000000000)