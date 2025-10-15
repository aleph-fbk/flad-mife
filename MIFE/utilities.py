import numpy as np
from functools import partial
from multiprocessing import Process, Manager, Pool

def split_list(lst, n):
    chunk_size = len(lst) // n
    return [lst[i:i + chunk_size] for i in range(0, chunk_size * n, chunk_size)] + [lst[chunk_size * n:]]

def split_list_decrypt(lst,n):
    n_clients = len(lst)
    n_weights = len(lst[0])
    chunk_size =  n_weights// n
    residual_weights = n_weights%n
    return [[[lst[i][j+t] for i in range(n_clients)] for t in range(chunk_size)] for j in range(0, chunk_size * n, chunk_size)] + [[[lst[i][chunk_size * n+t] for i in range(n_clients)] for t in range(residual_weights)]]

def encode(x: float, sig: int, X_bit: int) -> int: #take as input a float and a number of significant digits (sig).
    x = float(f"{x:.{sig}f}") #returns the float x with sig significant digits.
    enc = int(x*10**sig)
    if enc.bit_length() > X_bit:
        raise Exception(f"{x} is too large for {X_bit} bits")
    return enc

def decode(enc: int, sig: int) -> float: #take as input an int and a number of significant digits (sig).
    return enc / 10**sig #returns the float corresponding to the int enc with sig significant digits.

def encode_vector(x, sig: int, X_bit: int): #take as input a list of floats and a number of significant digits (sig).
    return [[encode(v, sig, X_bit)] for v in x] #returns a list of lists of ints

def decode_vector(x, sig: int): #take as input a list of lists of ints and a number of significant digits (sig).
    return [decode(v, sig) for v in x] # returns a list of lists of floats


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


def encrypt_vector(v, mife, key):
    return [mife.encrypt(v[i], key=key) for i in range(len(v))]


def process_chunk(chunk, f): # each worker process a chunk of the weights
        return [f(x) for x in chunk]

def parallel_encrypt_vector_compact(v, max_workers, mife, key):
  
    chunks = split_list(v, max_workers)

    encrypt_with_key = partial(mife.encrypt, key=key)
    process_chunk_with_fun = partial(process_chunk,f=encrypt_with_key)
    # Build the worker pool and map the function to the chunks
    with Pool(max_workers) as pool:
        results = pool.map(process_chunk_with_fun, chunks)

    # Join the results from all workers
    return [item for sublist in results for item in sublist]



def parallel_encrypt_vector(v, max_workers, mife, key):
    def worker(shared_dict, f, chunk_size): # each worker encrypts a chunk of the weights
        for i in range(chunk_size):
            shared_dict[i] = f(shared_dict[i])

    n_elem = len(v)
    dicts = []

    encrypt_with_key = partial(mife.encrypt, key=key)

    chunk_size = n_elem//max_workers 
    final_pos = (n_elem//max_workers)*max_workers
    residual_size = n_elem%max_workers

    #dicts = {i:Manager().dict()  for i in range(max_workers+1)} # we generate a dictionary for each worker
    dicts = {i:Manager().list() for i in range(max_workers+1)}
    # dicts = {i:{}  for i in range(max_workers+1)}

    # for i in range(max_workers):
    #     for j in range(chunk_size):
    #         dicts[i][j] = v[i*chunk_size+j]

    # for i in range(residual_size):
    #     dicts[max_workers][i] = v[i+final_pos]

    for i in range(max_workers):
        for j in range(chunk_size):
            dicts[i].append(v[i*chunk_size+j])

    for i in range(residual_size):
        dicts[max_workers].append(v[i+final_pos])
    


    processes = []
    for i in range(max_workers):
        p = Process(target=worker, args=(dicts[i], encrypt_with_key, chunk_size))
        p.start()
        processes.append(p)

    p = Process(target=worker, args=(dicts[max_workers], encrypt_with_key, residual_size))
    p.start()
    processes.append(p)

    for p in processes:
        p.join()
        p.close()    

    return dicts
    

def decrypt_vector(v, mife, pp, sk):
    number_of_clients = len(v)
    number_of_dicts = len(v[0])
    number_of_weight = 0
    aggregated_list = []

    for dict_pos in range(number_of_dicts):
        dict_size = len(v[0][dict_pos])
        number_of_weight += dict_size
        aggregated_list.extend([mife.decrypt(pp=pp, c=[v[cl][dict_pos][i] for cl in range(number_of_clients)], sk=sk) for i in range(dict_size)])

    return aggregated_list


def parallel_decrypt_vector_compact(v,mife,pp,sk,max_workers):

    chunks = split_list_decrypt(v, max_workers)
    decrypt = partial(mife.decrypt, pp=pp, sk=sk)
    process_chunk_with_fun = partial(process_chunk,f=decrypt)
    with Pool(max_workers) as pool:
        results = pool.map(process_chunk_with_fun, chunks)

    return [item for sublist in results for item in sublist]
    

def parallel_decrypt_vector(v,mife,pp,sk,max_workers):
    
    def worker(shared_dict, f, chunk_size):
        num_dicts = len(shared_dict)
        for i in range(chunk_size):
            shared_dict[0][i] = f([shared_dict[j][i] for j in range(num_dicts)])

    number_of_clients = len(v)
    number_of_weight = 0
    aggregated_list = []

    decrypt = partial(mife.decrypt, pp=pp, sk=sk)

    processes = []
    for dict_pos in range(max_workers + 1):
        dict_size = len(v[0][dict_pos])
        number_of_weight += dict_size

        p = Process(target=worker, args=([v[cl][dict_pos] for cl in range(number_of_clients)], decrypt, dict_size))
        # p.daemon = True
        p.start()
        processes.append(p)
        # aggregated_weights_list.extend([mife.decrypt(pp=server['pp'], c=[encrypted_model_set[i][dict_pos][j] for i in range(number_of_clients)], sk=server['sky']) for j in range(dict_size)])
    
    for p in processes:
        p.join()
        p.kill()

    for dict_pos in range(max_workers + 1):
        dict_size = len(v[0][dict_pos])
        aggregated_list.extend([v[0][dict_pos][j] for j in range(dict_size)])
    
    return aggregated_list
    
    
