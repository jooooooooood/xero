# -*- coding: utf-8 -*-
from datetime import datetime

import os
import base64
import hashlib
from functools import wraps
from io import BytesIO
from logging.config import dictConfig
import re

from flask import Flask, url_for, render_template, session, redirect, json, send_file
from flask_oauthlib.contrib.client import OAuth, OAuth2Application
from flask_session import Session
import requests
from xero_python.accounting import AccountingApi, ContactPerson, Contact, Contacts
from xero_python.api_client import ApiClient, serialize
from xero_python.api_client.configuration import Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.exceptions import AccountingBadRequestException
from xero_python.identity import IdentityApi
from xero_python.utils import getvalue
from xero_python.accounting import LineItem, Account, BankTransaction, BankTransactions

import logging_settings
from utils import jsonify, serialize_model

import dateutil
from decimal import Decimal
from dateutil.parser import parse as date_parse


CLIENT_ID = '7A62E45022044D3A8DE844CB91AC88CC'
CLIENT_SECRET = 'qVEhGH8r1pkYZi6lML-tWF6PRRFe9eZI570q_Uzcis0RGUVz'
REDIRECT_URI = 'http://localhost:5000/callback'
AUTHORIZATION_URL = 'https://login.xero.com/identity/connect/authorize'
TOKEN_URL = 'https://identity.xero.com/connect/token'
BASE_URL = 'https://api.xero.com/api.xro/2.0/'


def accounting_get_bank_transactions(access_token, tenant_id):
    url = BASE_URL + 'BankTransactions'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Xero-tenant-id': tenant_id
    }
    params = {
        'if-modified-since': '2024-01-01T12:17:43.202-08:00',
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        response_data = response.json()
        
        # Write the response to a file
        with open('response.json', 'w') as file:
            json.dump(response_data, file, indent=4)
        
        print("Response written to response.json")
        return response_data
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def accounting_get_journals(access_token, tenant_id, offset=0, uncategorized_journals=None):
    if uncategorized_journals is None:
        uncategorized_journals = []

    url = BASE_URL + 'Journals'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Xero-tenant-id': tenant_id
    }
    params = {
        'offset': offset
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        journals_response = response.json()
        print(f"Offset: {offset}")

        # Assuming the journals are in a 'Journals' key in the response
        journals = journals_response.get('Journals', [])

        # Read existing data from the file
        try:
            with open('journals.json', 'r') as file:
                existing_journals = json.load(file)
        except FileNotFoundError:
            existing_journals = []

        # Append new journals to the existing data
        existing_journals.extend(journals)

        # Save the updated journal entries to the file
        with open('journals.json', 'w') as file:
            json.dump(existing_journals, file, indent=4)

        # Check for uncategorized journals
        for journal in journals:
            # Check if any journal line in the current journal has 'account_name' == 'Uncategorized Expense'
            if any(line['AccountName'] in ['Uncategorized Expense', 'Uncategorized Income'] for line in journal['JournalLines']):
                uncategorized_journals.append(journal)

        # Check if more journals exist (assuming a page size of 100)
        if len(journals) == 100:
            # Fetch the next page of journals
            return accounting_get_journals(access_token, tenant_id, offset=offset + 100, uncategorized_journals=uncategorized_journals)
        else:
            return uncategorized_journals
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
def get_matched_transactions(access_token, tenant_id):
    # Fetch bank transactions
    bank_transactions_response = accounting_get_bank_transactions(access_token, tenant_id)
    if 'error' in bank_transactions_response:
        return jsonify(bank_transactions_response), 400

    bank_transactions = bank_transactions_response['BankTransactions']

    # Fetch journals
    journals_response = accounting_get_journals(access_token, tenant_id)
    if 'error' in journals_response:
        return jsonify(journals_response), 400

    # Match transactions
    matches = match_transactions(bank_transactions, journals_response)

    return jsonify(matches)

def match_transactions(bank_transactions, journals):
    matches = []
    print(journals)

    for journal in journals:
        journal_date = journal['JournalDate']
        for journal_line in journal['JournalLines']:
            gross_amount = abs(Decimal(journal_line['GrossAmount']))
            description = journal_line['Description']
            
            for transaction in bank_transactions:
                # print(transaction)
                transaction_date = transaction['Date']
                # print(convert_unix_time(transaction_date))
                # print(convert_unix_time(journal_date))
                # if (journal_date == transaction_date):
                #     print("Match")
                # print(Decimal(transaction['Total']))
                # print(gross_amount)
                # print('\n')
                if (
                    Decimal(transaction['Total']) == gross_amount and
                    transaction_date == journal_date and transaction['IsReconciled'] == False
                ):
                    matches.append({
                        'date': convert_unix_time(transaction['Date']),
                        'description': description,
                        'gross_amount': str(gross_amount),
                        'bank_transaction_id': transaction['BankTransactionID'],
                        'contact_id': transaction['Contact']['ContactID'],
                        'account_id': transaction['BankAccount']['AccountID']
                    })
    with open('matches.json', 'w') as file:
        json.dump(matches, file, indent=4)                
    return matches

def accounting_update_bank_transaction(tenant_id, bank_transaction_id, contact_id, account_id, amount, category):
    xero_tenant_id = tenant_id
    bank_transaction_id = bank_transaction_id

    contact = Contact(
        contact_id = contact_id)

    line_item = LineItem(
        quantity = 1.0,
        unit_amount = amount,
        account_code = category)
    
    line_items = []    
    line_items.append(line_item)

    bank_account = Account(
        account_id = account_id)

    bank_transaction = BankTransaction(
        reference = "",
        type = "",
        contact = contact,
        line_items = line_items,
        bank_account = bank_account)

    bankTransactions = BankTransactions( 
        bank_transactions = [bank_transaction])
    
    try:
        update_bank_transaction(xero_tenant_id, bank_transaction_id, bankTransactions)
    except AccountingBadRequestException as e:
        print("Exception when calling AccountingApi->updateBankTransaction: %s\n" % e)

def accounting_create_bank_transactions(access_token, tenant_id):
    url = 'https://api.xero.com/api.xro/2.0/BankTransactions'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Xero-tenant-id': tenant_id,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Define the contact
    contact = {
        "name": "test"
    }

    # Define the line item
    line_item = {
        "description": "test",
        "quantity": 1.0,
        "unit_amount": 400.0,
        "account_code": "000",
        "line_amount": 400.0
    }
    
    # Define the bank account
    bank_account = {
        "account_id": "69c850b6-7d21-4ee3-a598-7d5c365dba24"
    }

    # Create the bank transaction
    bank_transaction = {
    "Type": "SPEND",
    "Contact": {
        "name": "Test"
    },
    "LineItems": [{
        "Description": "Test",
        "UnitAmount": "400.00",
        "AccountCode": "8888",
        "TaxType": "NONE",
    }],
    "BankAccount": {
        "AccountID": "69c850b6-7d21-4ee3-a598-7d5c365dba24"
    }
}
    
    # Send the POST request
    response = requests.post(url, headers=headers, json=bank_transaction)

    # Check the response
    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
def generate_code_verifier():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    return verifier

def generate_code_challenge(verifier):
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
    return challenge

def get_authorization_url(verifier, challenge):
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email accounting.transactions accounting.attachments accounting.settings accounting.contacts',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    request_url = requests.Request('GET', AUTHORIZATION_URL, params=params).prepare().url
    return request_url

def get_access_token(authorization_code, code_verifier):
    # Create the authorization header
    auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

    # Prepare the data for the POST request
    data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,  # PKCE flow requires client_id in the body
        'code_verifier': code_verifier
    }

    headers = {
        'Authorization': f"Basic {auth_header}",
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Make the POST request to get the access token
    response = requests.post(TOKEN_URL, data=data, headers=headers)
    
    # Check if the response is successful
    if response.status_code != 200:
        raise Exception(f"Error fetching access token: {response.text}")

    return response.json()

def refresh_access_token(refresh_token):
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    }
    response = requests.post(TOKEN_URL, data=data)
    print(response.json())
    return response.json()

def get_tenants(access_token):
    url = 'https://identity.xero.com/api.xro/2.0/Connections'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
    }
    response = requests.get(url, headers=headers)

    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def get_chart_of_accounts(access_token, tenant_id):
    url = 'https://api.xero.com/api.xro/2.0/Accounts'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Xero-Tenant-Id': tenant_id,
        'Accept': 'application/json',
    }
    response = requests.get(url, headers=headers)

    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def convert_unix_time(date_str):
    match = re.search(r'/Date\((\d+)\+\d+\)/', date_str)
    if match:
        timestamp = int(match.group(1)) / 1000  # Convert milliseconds to seconds
        date_time = datetime.utcfromtimestamp(timestamp)  # Convert to datetime object
        return date_time.strftime('%Y-%m-%d %H:%M:%S')  # Format to readable string
    return date_str

if __name__ == '__main__':
    # code_verifier = generate_code_verifier()
    # code_challenge = generate_code_challenge(code_verifier)
    
    # # Get the authorization URL
    # auth_url = get_authorization_url(code_verifier, code_challenge)
    # print("Go to the following URL to authorize the application:")
    # print(auth_url)
    
    # # After the user authorizes the app, they will be redirected to the redirect URI with a code
    # authorization_code = input("Enter the authorization code: ")
    
    # # Exchange the authorization code for an access token
    # token_data = get_access_token(authorization_code, code_verifier)
    # print(token_data)
    # access_token = token_data['access_token']
    # refresh_token = token_data['refresh_token']
    
    # print("Access Token:", access_token)
    # print("Refresh Token:", refresh_token)
    access_token = refresh_access_token('CaUjXTscoHv8MSi5SJ9oszndYpl-aRekwemEieJYTEM')['access_token']
    accounting_create_bank_transactions(access_token=access_token, tenant_id='c0395c8a-b2e1-4c3c-b697-7e4094d9ad9b')
    # print(get_chart_of_accounts(access_token=access_token, tenant_id='c0395c8a-b2e1-4c3c-b697-7e4094d9ad9b'))
    # get_matched_transactions(access_token=access_token, tenant_id='c0395c8a-b2e1-4c3c-b697-7e4094d9ad9b')
