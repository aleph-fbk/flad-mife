import numpy as np


def encode(x: float, sig: int, X_bit: int) -> int: #prende in input un float e un numero di cifre significative (sig).
    x = float(f"{x:.{sig}f}") #restituisce il float x con sig cifre significative.
#possibilità di vettorializzazione.
    enc = int(x*10**sig)
    if enc.bit_length() > X_bit:
        raise Exception(f"{x} is too large for {X_bit} bits")
    return enc

def decode(enc: int, sig: int) -> float: #prende in input un int e un numero di cifre significative (sig).
    return enc / 10**sig #restituisce il float decodificato.

def encode_vector(x, sig: int, X_bit: int): #prende in input una lista di float e un numero di cifre significative (sig).
    return [[encode(v, sig, X_bit)] for v in x] #restituisce una lista di liste di interi

def decode_vector(x, sig: int): #prende in input una lista di int e un numero di cifre significative (sig).
    return [decode(v, sig) for v in x] #restituisce una lista di liste di float


def flatten_keras_weights(model):
    # Extract all weights (including biases) from the Keras model
    all_weights = model.get_weights()
    
    # Flatten each weight array and concatenate into a single 1D array
    flat_weights = np.concatenate([w.flatten() for w in all_weights])
    return flat_weights


def set_flat_weights(model, flat_weights):
    # Initialize position index for slicing
    pos = 0
    flat_weights = np.array(flat_weights)
    # Get the shapes of the original weights
    original_shapes = [w.shape for w in model.get_weights()]
    
    # Create reshaped weights from the flat array
    new_weights = []
    for shape in original_shapes:
        size = np.prod(shape)  # Total number of elements for this weight matrix
        # Reshape and slice the flat weights to the correct shape
        new_weights.append(flat_weights[pos:pos + size].reshape(shape))
        pos += size

    # Set the weights back in the model
    model.set_weights(new_weights)
