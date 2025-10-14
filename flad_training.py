# Copyright (c) 2023 @ FBK - Fondazione Bruno Kessler
# Author: Roberto Doriguzzi-Corin
# Project: FLAD, Adaptive Federated Learning for DDoS Attack Detection
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ann_models import *
from MIFE.utilities import *
from flad_main import X_BIT, NUM_DECIMAL
import time
import math
import csv
from sklearn.metrics import f1_score
import random
import gc
import shutil


# MAX_WORKERS = 31 # number of parallel workers

# General hyperparameters
EXPERIMENTS = 10

# FL hyper-parameters 
PATIENCE = 25
CLIENT_FRACTION = 0.8 # Fraction of clients selected at each round for FedAvg-based approaches

def trainClientModel(model, epochs, X_train, Y_train,X_val, Y_val, steps_per_epoch=None):

    if steps_per_epoch != None and steps_per_epoch > 0:
        batch_size = max(int(round(len(Y_train) / steps_per_epoch)),1) # min batch size set to 1

    print("Batch size: " + str(batch_size))
    tp0 = time.time()
    history = model.fit(x=X_train, y=Y_train, validation_data=(X_val, Y_val), epochs=epochs, batch_size=batch_size,
                        verbose=2, callbacks=[])
    tp1 = time.time()

    loss_train = history.history['loss'][-1]
    loss_val = history.history['val_loss'][-1]

    return model, loss_train, loss_val, tp1-tp0

# Federated training procedure
def  FederatedTrain(clients, model_type, outdir, time_window, max_flow_len, dataset_name, mife_elements_for_server, epochs='auto', steps='auto', training_mode = 'flad', weighted=False,optimizer='SGD',nr_experiments=EXPERIMENTS):
    
    round_fieldnames = ['Model', 'Round', 'AvgF1']
    tuning_fieldnames = ['Model', 'Epochs', 'Steps', 'Mode', 'Weighted', 'Experiment', 'ClientsOrder','Round', 'TotalClientRounds', 'F1','Time(sec)','AggregationTime(sec)']
    for client in clients:
        round_fieldnames.append(client['name'] + '(f1)')
        round_fieldnames.append(client['name']+ '(loss)')
        tuning_fieldnames.append(client['name'] + '(EncryptionTime(sec))')
        tuning_fieldnames.append(client['name'] + '(f1)')
        tuning_fieldnames.append(client['name'] + '(rounds)')

    hyperparamters_tuning_file = open(outdir + '/federated-tuning.csv', 'w', newline='')

    tuning_writer = csv.DictWriter(hyperparamters_tuning_file, fieldnames=tuning_fieldnames)
    tuning_writer.writeheader()
    hyperparamters_tuning_file.flush()

    # we start all the experiments with the same server, which means same initial model and random weights
    server = init_server(model_type, dataset_name, clients[0]['input_shape'], max_flow_len, mife_elements_for_server)
    if server == None:
        exit(-1)
    model_name = server['model'].name

    # we keep client_indeces for compatibility with the full experiments
    client_indeces = list(range(0, len(clients)))

    training_filename = model_name + '-epochs-' + str(epochs) + "-steps-" + str(steps) + "-trainingclients-" + str(training_mode) + "-weighted-" + str(weighted)
    training_file = open(outdir + '/' + training_filename  + '.csv','w', newline='')
    writer = csv.DictWriter(training_file, fieldnames=round_fieldnames)
    writer.writeheader()

    # initialising clients before starting a new round of training
    server['best_model'] = clone_model(server['model'])
    total_rounds = 0

    # in this configuration we use a static subset of  all clients
    client_subset = clients
    stop_counter = 0
    max_f1 = 0
    f1_val = 1
    stop = False

    # assign mife obj

    mife_obj = mife_elements_for_server['mife']

    while True:  # training epochs
        total_rounds += 1

        # here we set clients' epochs and steps/epoch
        update_client_training_parameters_local(client_subset, 'epochs', epochs, f1_val, MAX_EPOCHS, MIN_EPOCHS)
        update_client_training_parameters_local(client_subset, 'steps_per_epoch', steps, f1_val, MAX_STEPS, MIN_STEPS)

        training_time = 0
        
        encrypted_model_set = {}

        for index,client in enumerate(client_subset):
            # "Send" the global model to the client
            print("Training client in folder: ", client['folder'])
            client['model'] = clone_model(server['model'])
            client['model'].set_weights(server['model'].get_weights())
            compileModel(client['model'], optimizer,'binary_crossentropy')

            # If the client is selected, perform the local training
            if client['update'] == True:
                client['model'], client['loss_train'], client['loss_val'], client['round_time'] = trainClientModel(
                    client['model'], 
                    client['epochs'],
                    client['training'][0],
                    client['training'][1],
                    client['validation'][0],
                    client['validation'][1],
                    steps_per_epoch=client['steps_per_epoch'])
                client['rounds'] +=1
                if client['round_time'] > training_time:
                    training_time = client['round_time']

            print('\nEncrypting model...')
            encrypted_model_set[index], client['encryption_time'] = encrypt_model(client['model'], mife_obj, client['pk'], mife_elements_for_server['max_workers'], parall_flag=True)


            
        print("==============================================")
        print("Aggregating models...")
        t0 = time.time()
        server['model'], server['aggregation_time'] = aggregation_encrypted_weighted_sum(server, encrypted_model_set, mife_obj, mife_elements_for_server['max_workers'], weighted)
        t1 = time.time()
        print('Aggregation time: %.2f s' % (t1-t0))  
        print("==============================================")
         
        
            
        print("\n################ Round: " + '{:05d}'.format(total_rounds) + " ################")

        f1_val = select_clients(server, client_subset, mife_obj, training_mode=training_mode)
        print("==============================================")
        print('Average F1 Score: ', str(f1_val))
        #print('Std_dev F1 Score: ', str(f1_std_val))

        # f1 score on the validation set. We put "*" when the f1 reaches or overcome the max_f1
        row = {'Model': model_name if f1_val < max_f1 else "*"+model_name, 'Round': int(total_rounds),
            'AvgF1': '{:06.5f}'.format(f1_val)}
        for client in client_subset:
            row[client['name'] + '(f1)'] = '{:06.5f}'.format(client['f1_val'])
            row[client['name'] + '(loss)'] = '{:06.5f}'.format(client['loss_val'])
        writer.writerow(row)
        training_file.flush()

        if f1_val > max_f1:
            max_f1 = f1_val
            server['best_model'] = clone_model(server['model'])
            server['best_model'].set_weights(server['model'].get_weights())
            print("New Max F1 Score: " + str(max_f1))
            stop_counter = 0
        else:
            stop_counter += 1
            print("Stop counter: " + str(stop_counter))

        print('Current Max F1 Score: ' + str(max_f1))
        print("##############################################\n")

        total_client_rounds = 0
        for client in clients:
            total_client_rounds += client['rounds']

        f1_val = assess_encrypted_server_model(server, 'best_model', client_subset,mife_obj,update_clients=True,print_f1=False)
        row = {'Model': model_name, 'Epochs': epochs, 'Steps': steps,
                'Mode': training_mode, 'Weighted': weighted, 'Experiment': 0,
                'ClientsOrder': ' '.join(str(c) for c in client_indeces), 'Round': int(total_rounds),
                'TotalClientRounds': int(total_client_rounds), 'F1': '{:06.5f}'.format(f1_val), 'Time(sec)': '{:06.2f}'.format(training_time), 'AggregationTime(sec)': '{:06.2f}'.format(server['aggregation_time'])}
        for client in clients:
            row[client['name']+'(EncryptionTime(sec))'] = '{:06.2f}'.format(client['encryption_time'])
            row[client['name'] + '(f1)'] = '{:06.5f}'.format(client['f1_val_best'])
            row[client['name'] + '(rounds)'] = int(client['rounds'])
        
        tuning_writer.writerow(row)
        hyperparamters_tuning_file.flush()

        # early stopping procedure
        stop = True if stop_counter > PATIENCE else False

        if stop == True:
            # once we have trained with all the clients, we save the best model and we compute the f1_val
            # with the best model obtained with all the clients. We also close the training stats file and
            # we save the final results obtained with a given set of hyper-parameters
            best_model_file_name = str(time_window) + 't-' + str(max_flow_len) + 'n-' + model_name + '-global-model.h5'
            server['best_model'].save(outdir + '/' + best_model_file_name)
            break

    training_file.close()
    shutil.move(outdir + '/' + training_filename  + '.csv', outdir + '/' + training_filename  + '-rounds-' + str(total_rounds) + '.csv') #here we add the total training rounds to the filename

    hyperparamters_tuning_file.close()

# We evaluate the aggregated model on the clients validation sets
# in a real scenario, the server would send back the aggregated model to the clients, which evaluate it on their local validation data
# as a final step, the clients would send the resulting f1 score to the server for analysis (such as the weighted avaerage below)
def select_clients(server, clients, mife, training_mode):

    # this function simulates the second round of comunication,
    # needed to compute the average score
    average_f1 = assess_encrypted_server_model(server, 'model', clients, mife, update_clients=True, print_f1=True)

    # selection of clients to train in the next round for fedavg and flddos
    random_clients_list = random.sample(clients,int(len(clients)*CLIENT_FRACTION))

    for client in clients:
        if training_mode == "flad" and client['f1_val'] <= average_f1:
            client['update']= True
        elif training_mode != "flad" and client in random_clients_list:
            client['update'] = True
        else:
            client['update'] = False
        
    return average_f1

def encrypt_model(model, mife, key, max_workers, parall_flag = True):

    weights = flatten_keras_weights(model)
    encoded_weights = encode_vector(weights,X_bit=X_BIT,sig=NUM_DECIMAL) # encoding the weights into X_BIT long integers
    t0 = time.time()    
    encrypted_vector = parallel_encrypt_vector_compact(v=encoded_weights,mife=mife,key=key,max_workers=max_workers)
    t1 = time.time()    
    print('Encryption time: %.2f s\n' % (t1-t0))  
    return encrypted_vector, t1-t0
        

def assess_encrypted_server_model(server, parameter, clients, mife, update_clients=False, print_f1=False):
    f1_val_list = []
    for client in clients:
        X_val, Y_val = client['validation']
        Y_pred = np.squeeze(server[parameter].predict(X_val, batch_size=2048) > 0.5)
        client_f1 = f1_score(Y_val, Y_pred)

        f1_val_list.append(mife.encrypt([encode(client_f1,NUM_DECIMAL,X_BIT)], client['pk']))
        if update_clients == True:
            if parameter == 'model':
                client['f1_val'] = f1_score(Y_val, Y_pred)
            else:
                client['f1_val_best'] = f1_score(Y_val, Y_pred)
        if print_f1 == True:
            print(client['name'] + ": " + str(client['f1_val']))

    K.clear_session()
    gc.collect()

    if len(clients) > 0:
        average_f1 = mife.decrypt(pp=server['pp'], c=f1_val_list, sk=server['sky'])
        average_f1 = decode(average_f1,NUM_DECIMAL)
        average_f1 /= len(clients)
        #std_dev_f1 = np.std(f1_val_list)
    else:
        average_f1 = 0
        #std_dev_f1 = 0

    return average_f1


# check the global model on the clients' validation sets
def assess_server_model(server_model, clients,update_clients=False, print_f1=False):
    f1_val_list = []
    for client in clients:
        X_val, Y_val = client['validation']
        Y_pred = np.squeeze(server_model.predict(X_val, batch_size=2048) > 0.5)
        client_f1 = f1_score(Y_val, Y_pred)

        f1_val_list.append(client_f1)
        if update_clients == True:
            client['f1_val'] = f1_score(Y_val, Y_pred)
        if print_f1 == True:
            print(client['name'] + ": " + str(client['f1_val']))

    K.clear_session()
    gc.collect()

    #TODO: to compute the mean we have to perform a round of MIFE on the f1 encrypted list
    if len(clients) > 0:
        average_f1 = np.average(f1_val_list)
        #std_dev_f1 = np.std(f1_val_list)
    else:
        average_f1 = 0
        #std_dev_f1 = 0

    return average_f1

# check the BEST global model on the clients' validation sets
def assess_best_model(server_model, clients,update_clients=False, print_f1=False):
    f1_val_list = []
    for client in clients:
        X_val, Y_val = client['validation']
        Y_pred = np.squeeze(server_model.predict(X_val, batch_size=2048) > 0.5)
        client_f1 = f1_score(Y_val, Y_pred)
        f1_val_list.append(client_f1)
        if update_clients == True:
            client['f1_val_best'] = f1_score(Y_val, Y_pred)
        if print_f1 == True:
            print(client['name'] + ": " + str(client['f1_val_best']))

    K.clear_session()
    gc.collect()


    if len(clients) > 0:
        average_f1 = np.average(f1_val_list)
        #std_dev_f1 = np.std(f1_val_list)
    else:
        average_f1 = 0
        #std_dev_f1 = 0

    return average_f1

# We dynamically assign the number of training steps/epochs (called 'parameter') to each client for the next training round
# The result is based on the f1 score on the local validation set obtained by each client and communicated to
# the server along with the model update
def update_client_training_parameters(clients, parameter, value, max_value, min_value):

    f1_list = []
    update_clients = []

    # here we select the clients that must be updated
    for client in clients:
        if client['update'] ==True:
            update_clients.append(client)


    if value == 'auto': # dynamic parameter based on f1_val
        # the resulting parameters depend on the current f1 values of the clients that will
        # be updated. Such a list of clients is determined in method average_f1_val
        for client in update_clients:
            f1_list.append(client['f1_val'])

        if len(set(f1_list)) > 1:
            min_f1_value = min(f1_list)
            max_value = max(min_value+1, math.ceil(max_value*(1-min_f1_value))) # min acceptable value for is min_value+1
            value_list = max_value + min_value - scale_linear_bycolumn(f1_list, np.min(f1_list), np.max(f1_list), high=float(max_value), low=min_value)

        elif len(set(f1_list)) == 1: # if there a single f1 value,  scale_linear_bycolumn does not work
            value_list = [max_value] * len(update_clients)
        else:
            return 0

        for client in update_clients:
            client[parameter] = int(value_list[update_clients.index(client)])
            #print ("Client: " + client['name'] + " F1: " + str(client['f1_val']) + " Parameter(" + parameter + "): "  + str(client[parameter]))


    else: # static parameter
        for client in update_clients:
            client[parameter] = value

    return len(update_clients)


def update_client_training_parameters_local(clients, parameter, value, mean_value, max_value, min_value):

    update_clients = []

    # here we select the clients that must be updated
    for client in clients:
        if client['update'] ==True:
            update_clients.append(client)

    for client in update_clients:
        sigma = abs(mean_value-client['f1_val'])/mean_value
        print(f'client {client["name"]} ha f1 {client["f1_val"]} e sigma {sigma}')

        #FIXME: we should use a more sophisticated scaling function
        client[parameter] = round(min_value + (max_value-min_value)*sigma) + 1

    return len(update_clients)

    
# FedAvg, with the additional option for averaging without weighting with the number of local samples
def aggregation_weighted_sum(server, clients,weighted=True):
    total = 0

    aggregated_model = clone_model(server['model'])
    aggregated_weights = aggregated_model.get_weights()
    aggregated_weights_list = []

    for weights in aggregated_weights:
        aggregated_weights_list.append(np.zeros(weights.shape))

    weights_list_size = len(aggregated_weights_list)

    for client in clients:
        if weighted == True:
            avg_weight = client['samples']
        else:
            avg_weight = 1
        total += avg_weight
        client_model = client['model']

        client_weights = client_model.get_weights()
        for weight_index in range(weights_list_size):
            aggregated_weights_list[weight_index] += client_weights[weight_index] * avg_weight

    aggregated_weights_list[:] = [(aggregated_weights_list[i] / total) for i in
                             range(len(aggregated_weights_list))]
    aggregated_model.set_weights(aggregated_weights_list)

    return aggregated_model


def aggregation_encrypted_weighted_sum(server, encrypted_model_set, mife, max_workers, weighted=False):
    
    aggregated_model = clone_model(server['model'])
    number_of_clients = len(encrypted_model_set)

    t0 = time.time()
    aggregated_weights_list = parallel_decrypt_vector_compact(v=encrypted_model_set,mife=mife,pp=server['pp'],sk=server['sky'],max_workers=max_workers)
    t1 = time.time()

    aggregated_weights_list = decode_vector(aggregated_weights_list,NUM_DECIMAL)
    number_of_weight = len(aggregated_weights_list)
    
    aggregated_weights_list = [aggregated_weights_list[i]/number_of_clients for i in range(number_of_weight)]

    set_flat_weights(aggregated_model,aggregated_weights_list)
    # aggregated_model.set_weights(aggregated_weights_list)

    return aggregated_model, t1-t0

