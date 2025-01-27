def encode(x: float, sig: int, X_bit: int) -> int: #prende in input un float e un numero di cifre significative (sig).
    x = float(f"{x:.{sig}f}") #restituisce il float x con sig cifre significative.
#possibilità di vettorializzazione.
    enc = int(x*10**sig)
    if enc.bit_length() > X_bit:
        raise Exception(f"vector {x} is too large for {X_bit} bits")
    return enc

def decode(enc: int, sig: int) -> float: #prende in input un float e un numero di cifre significative (sig).
    return enc / 10**sig #restituisce il float decodificato.

def encode_vector(x: list[float], sig: int, X_bit: int) -> list[int]: #prende in input una lista di float e un numero di cifre significative (sig).
    return [encode(v, sig, X_bit) for v in x] #restituisce una lista di interi