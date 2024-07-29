# -*- coding: utf-8 -*-
from datetime import datetime

import os
import base64
import hashlib
from functools import wraps
from io import BytesIO
from logging.config import dictConfig

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

TODO: "I can pull charts of accounts from each client which will serve as the category list when I make their google sheet. Transaction Type column in Sheet will be the bankTransaction description. Need to figure out how to store pending transactions so when customer clarifies category I can update proper bank transaction. Maybe store bank transactionId in the sheet?"



def accounting_get_bank_transactions(access_token, tenant_id):
    url = BASE_URL + 'BankTransactions'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Xero-tenant-id': tenant_id
    }
    params = {
        'if-modified-since': '2024-02-06T12:17:43.202-08:00',
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Function to get journals
def accounting_get_journals(access_token, tenant_id):
    url = BASE_URL + 'Journals'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Xero-tenant-id': tenant_id
    }
    params = {
        'if-modified-since': '2024-02-06T12:17:43.202-08:00'
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        journals = response.json()
        uncategorized_journals = []

        # Assuming 'journals' is a list of journal entries structured as in the provided data excerpt
        for journal in journals.get('Journals', []):
            # Check if any journal line in the current journal has 'account_name' == 'Uncategorized Expense'
            if any(line['AccountName'] == 'Uncategorized Expense' for line in journal['JournalLines']):
                uncategorized_journals.append(journal)
        
        # Return the list of uncategorized journals
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

    for journal in journals:
        journal_date = journal['JournalDate']
        for journal_line in journal['JournalLines']:
            if journal_line['AccountName'] == 'Uncategorized Expense':  # Identify uncategorized expenses
                gross_amount = abs(Decimal(journal_line['GrossAmount']))
                description = journal_line['Description']
                
                for transaction in bank_transactions:
                    # print(transaction)
                    transaction_date = transaction['Date']
                    # print(journal_date)
                    # print(transaction_date)
                    # if (journal_date == transaction_date):
                    #     print("Match")
                    # print(Decimal(transaction['Total']))
                    # print(gross_amount)
                    # print('\n')
                    if (
                        Decimal(transaction['Total']) == gross_amount and
                        transaction_date == journal_date
                    ):
                        matches.append({
                            'date': journal['JournalDate'],
                            'description': description,
                            'gross_amount': str(gross_amount),
                            'bank_transaction_id': transaction['BankTransactionID'],
                            'contact_id': transaction['Contact']['ContactID'],
                            'account_id': transaction['BankAccount']['AccountID']
                        })
    print(matches)                    
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
        api_instance.update_bank_transaction(xero_tenant_id, bank_transaction_id, bankTransactions)
    except AccountingBadRequestException as e:
        print("Exception when calling AccountingApi->updateBankTransaction: %s\n" % e)

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
        'scope': 'openid profile email accounting.transactions accounting.attachments',
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
    access_token = refresh_access_token('IKVVV0yvuiTp4_S50AbIfm-WEZ4STPm0Msf__T35VuM')['access_token']
    print(get_chart_of_accounts(access_token=access_token, tenant_id='c0395c8a-b2e1-4c3c-b697-7e4094d9ad9b'))
    get_matched_transactions(access_token=access_token, tenant_id='c0395c8a-b2e1-4c3c-b697-7e4094d9ad9b')
