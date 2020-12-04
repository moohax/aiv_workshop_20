import sys

if sys.version_info.major != 3:
    print("[!] Python 3 is required")
    sys.exit(1)

import os
import re
import csv
import uuid
import numpy
import base64
import pickle
import argparse

from hashlib import md5
from subprocess import Popen, PIPE
from collections import namedtuple

from tqdm import tqdm
from tensorflow.keras.layers import Dense
from tensorflow.keras.models import Sequential
from tensorflow.keras.models import load_model
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.preprocessing.text import Tokenizer
from sklearn.model_selection import train_test_split

import tensorflow.keras.backend as K

K.set_epsilon(1e-4) 
K.set_floatx('float16')

def collect_output(scripts_to_scan):

    labeled_data = [] # Storage for all the entries
    
    ScoredObject = namedtuple('Scored', 'name, path, hash, content, label')

    re_score = re.compile(r'Scan result is \d+. IsMalware: \d+') # regex to gather the score

    for path in os.walk(scripts_to_scan): # Create the dataset 

        if path[2]:
            for script in path[2]:

                # Get script path
                temp_path = (f'{path[0]}\\{script}')
                
                # Scan the content of the file
                process = Popen(['AmsiStream.exe', f'{temp_path}'], stdout=PIPE)
                (output, err) = process.communicate()
                exit_code = process.wait()
                
                if not output:
                    continue
                    
                # Collect the result
                try:
                    result = re.findall(re_score, output.decode())[0]

                except Exception as e:
                    print(f'[!] Error: {e} ({temp_path})')
                    continue
                
                # Get content of file
                with open(temp_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                # Encode script for storage    
                b64encoded = base64.b64encode(content.encode()).decode()

                # Hash the content the look for duplicates later
                hashed = md5(content.encode()).hexdigest()
                
                # Create the entry
                scored_entry = ScoredObject(name=script, path=temp_path, hash=hashed, content=b64encoded, label=result)

                # Add it to the list
                labeled_data.append(scored_entry)

    return labeled_data

def write_output(labeled_data, output_path):

    with open(output_path, 'w', encoding='utf-8', newline='') as df:
        writer = csv.writer(df)
        writer.writerow(('name', 'hash', 'label', 'content'))
        writer.writerows([(entry.name, entry.hash, entry.label, entry.content) for entry in labeled_data]) # temp_path is part of the struct but ignored here

    return True

def preprocess_data(training_data, max_scripts):

    scripts = {
        'malicious': [], 
        'clean':[]
        }

    punc_re = re.compile(r'[,;@#?!&$"(){}<>\'\[\]\\\\]+\ *') # could filter any number of ways. Choose your own adventure

    tokenizer = Tokenizer()
    
    ScoredObject = namedtuple('Scored', 'text, score, hash')

    print('[+] Processing training data...')

    for line in tqdm(training_data):

        raw_data = line.split(',')

        try:
            decoded_data = base64.b64decode(raw_data[3].encode()).decode().lower()

        except Exception as e:
            #print(f'{e} for {raw_data[:2]}')
            continue
        
        if '.ps1' not in raw_data[0]:
            continue
        
        stripped_data = re.sub(punc_re, ' ', decoded_data)
        split_data = stripped_data.split()
        uniq_data = list(set(split_data))

        # add some additional filtering
        filtered_data = []
        for token in uniq_data:
            if '\x00' in token:
                continue

            if 'tvqqaa' in token:
                continue

            if len(token) >= 64:
                continue

            if len(token) <=1:
                continue

            if 'ÿþ' in token:
                continue

            else:
                filtered_data.append(token)

        # Create the training struct while we're here.
        script_content = ' '.join(filtered_data)

        if 'IsMalware: 0' in raw_data[2]:
            temp = ScoredObject(text=script_content, score=0, hash=raw_data[1]) # add the label
            scripts['clean'].append(temp)

        if 'IsMalware: 1' in raw_data[2]:
            temp = ScoredObject(text=script_content, score=1, hash=raw_data[1]) # add the label
            scripts['malicious'].append(temp)
    
    print('[+] Creating vocab...')
    all_data = scripts['clean'][:max_scripts] + scripts['malicious']
    text = [entry.text for entry in all_data]
    
    tokenizer.fit_on_texts(text)

    # create training matrix
    print('[+] Creating training matrix...')
    text_matrix = tokenizer.texts_to_matrix(text, mode='binary')

    # create score matrix
    print('[+] Creating score matrix...')
    score_matrix = numpy.array([entry.score for entry in all_data])

    return text_matrix, score_matrix, tokenizer


def build_model(activation, input_dim, epochs, loss, layer_size, output_dim):

    model = Sequential()
    model.add(Dense(layer_size, activation=activation, input_dim=input_dim))
    model.add(Dense(layer_size, activation=activation))
    model.add(Dense(output_dim, activation=activation))
    model.compile(loss=loss, optimizer='adam', metrics=['acc'])

    return model

def gather_insights(model, tokenizer, text_matrix):

    insights = {}

    for sample in tqdm(text_matrix):
        base_prediction = model.predict(numpy.array([sample]))[0][0]

        for i,word_is_set in enumerate(sample):
            if i is 0 or not word_is_set: continue # first index is reserved
            
            word = tokenizer.index_word[i]
            alt_sample = numpy.copy(sample)
            alt_sample[i] = 0
            new_prediction = model.predict(numpy.array([alt_sample]))[0][0]            

            if word not in insights:
                insights[word] = [0, 0]

            insights[word][0] += 1
            insights[word][1] += (base_prediction - new_prediction)

    insights = dict([(k, i[1] / i[0]) for k,i in insights.items()])

    return sorted(insights.items(), key=lambda x: x[1], reverse=True) 

def main(args):
    
    if args.mode == 'collect':

        # Gather a labeled dataset
        labeled_data = collect_output(args.dir)

        # Write the dataset to a file for processing later
        write_output(labeled_data, f'{args.output}_data.csv')

        print(f'[+] Successfully wrote data to {args.output}.csv!')
        print('[+] Done!')

    if args.mode == 'train':

        # Set some model parameters
        activation = 'sigmoid'
        epochs = 10
        batch_size = 16
        loss = 'mse'
        layer_size = 64 
        output_dim = 1
        
        try:
            output_file = f'{args.output}_data.csv'
            with open(output_file, 'r', encoding='utf-8') as f:
                training_data = f.readlines()[1:] # skip the headers

        except Exception as err:
            print(f'[!] There was an error opening {output_file}: {err}')
            sys.exit(1)

        # Preprocess the data
        text_matrix, score_matrix, tokenizer = preprocess_data(training_data, args.max_scripts)
        score_matrix.reshape(-1, 1)

        # Build a model
        model = build_model(activation, text_matrix.shape[1], epochs, loss, layer_size, output_dim)

        # Split the data
        x_train, x_test, y_train, y_test = train_test_split(text_matrix, score_matrix, test_size=0.2)

        # Train the model
        early_stop = EarlyStopping(monitor='loss', mode='min', verbose=1)
        history = model.fit(x_train, y_train, epochs=epochs, batch_size=batch_size, callbacks=[early_stop])

        # Evaluate the model
        mse, acc = model.evaluate(x_test, y_test)
        print(f'[+] Mean square error: {mse}')
        print(f'[+] Accuracy: {acc}')

        # Save the model
        
        model_file = f'./{args.output}_model.h5'
        model.save(model_file)
        print(f'[+] Saved model to {model_file}')

        vocab_file = f'{args.output}.vocab'
        with open(vocab_file, 'wb') as h:
            pickle.dump(tokenizer, h, protocol=pickle.HIGHEST_PROTOCOL)
        
        print(f'[+] Saved vocab to {vocab_file}')
        print('[+] Done!')

    if args.mode == 'insight':

        model_path = f'{args.output}_model.h5'
        model = load_model(model_path)

        with open(f'{args.output}.vocab', 'rb') as h:
            tokenizer = pickle.load(h)

        try:
            output_file = f'{args.output}_data.csv'
            with open(output_file, 'r', encoding='utf-8') as f:
                training_data = f.readlines()[1:] # skip the headers

        except Exception as err:
            print(f'[!] There was an error opening {output_file}: {err}')
            sys.exit(1)
        
        text_matrix, score_matrix, _ = preprocess_data(training_data, args.max_scripts)

        insights = gather_insights(model, tokenizer, text_matrix)

        insights_path = f'{args.output}_insights.csv'
        with open(insights_path, 'w', newline='') as f:
            writer = csv.writer(f, delimiter=',')

            for token in insights:
                writer.writerow(token)

        print(f'[+] Wrote insights to {insights_path}')
        print('[+] Done!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Playing with Windows Defenders ML Model', formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
    parser.add_argument('-d','--dir', help='Directory of scripts to scan with AmsiStream.exe', default='./data/Github')
    parser.add_argument('-o', '--output', help='Specify an outfile if collecting scores from Defender', default='Defender')
    parser.add_argument('-t', '--model', help='Trained model to load to process insights')
    parser.add_argument('-a', '--amsi', help='Path to AmsiStream.exe', default='./AmsiStream.exe')
    parser.add_argument('-x', '--max_scripts', help='max scripts to parse - helps with memory issues', default='150000', type=int)
    parser.add_argument('-m', '--mode', choices=['collect', 'train', 'insight'], help='Collect data, train a model, or gather insights')
    args = parser.parse_args()
    main(args)
