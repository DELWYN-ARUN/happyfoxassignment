import base64
import os
import json
import datetime
import re
import pymysql

from google.auth.transport.requests import Request as google_requests, Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow


def get_database_connection():
    """Establish a connection to the MySQL database."""
    connection = pymysql.connect(
        host='127.0.0.1',
        user='root',
        password='root',
        database='local'
    )
    return connection


SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# this Initializes the Google API client and authenticates with the Gmail
creds = None
if os.path.exists('token.json'):
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
    with open('token.json', 'w') as token:
        token.write(creds.to_json())


CLIENT_SECRET_FILE = 'client_secret.json'
TOKEN_FILE = 'token.json'

# this is the specified rules stored in rules.json
RULES_FILE = 'rules.json'


def authenticate():
    """this Authenticate to the Gmail API."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(google_requests())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
    return creds


def fetch_emails(service):
    """this Fetch emails from the Inbox using Gmail API."""
    results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])

    emails = []
    if messages:
        for message in messages:
            email = service.users().messages().get(userId='me', id=message['threadId']).execute()
            emails.append(email)

    return emails


def store_emails(emails, service):
    """this Store emails in the MySQL database."""
    conn = get_database_connection()
    cursor = conn.cursor()

    for email in emails:
        email_id = email['id']

        # this line insert the email into the table
        insert_query = "INSERT INTO emails (id, body, date,sender,is_read,subject) VALUES (%s, %s, %s,%s,%s,%s) ON DUPLICATE KEY UPDATE id = %s"

        body = get_message_body(email)
        date = get_header_value(email, 'Date')
        sender = get_header_value(email, 'From')
        if '<' in sender:
            sender = sender.split(">")[0].strip()
            sender = sender.split("<")[1].strip()
        subject = get_header_value(email, 'Subject')
        isRead = 1 if "UNREAD" in email.get("labelIds") else 0
        cursor.execute(insert_query, (email_id, body, date, sender, isRead, subject, email_id))

    conn.commit()
    cursor.close()
    conn.close()


def get_header_value(msg, header_name):
    """this gets the value of a header field from the email message."""
    headers = msg['payload']['headers']
    for header in headers:
        if header['name'] == header_name:
            if header_name == 'Date':

                date_value = header['value']
                match = re.search(r'(\d{1,2}\s\w+\s\d{4})\s(\d{2}:\d{2}:\d{2})', date_value)
                if match:
                    date_string = match.group(1) + ' ' + match.group(2)
                    parsed_date = datetime.datetime.strptime(date_string, "%d %b %Y %H:%M:%S")
                    formatted_date = parsed_date.strftime("%Y-%m-%d %H:%M:%S")
                    return formatted_date
            else:
                return header['value']
    return ""


def get_message_body(msg):
    """ this gets the body of the email message."""
    payload = msg.get('payload', {})
    parts = payload.get('parts', [])

    for part in parts:
        if part.get('mimeType') == 'text/plain':
            data = part.get('body', {}).get('data')
            if data:
                return base64.urlsafe_b64decode(data).decode('utf-8')

    # this line checks If no plain text parts are found and also check if the payload itself contains the message body
    if payload.get('mimeType') == 'text/plain':
        data = payload.get('body', {}).get('data')
        if data:
            return base64.urlsafe_b64decode(data).decode('utf-8')

    return


def mark_email_as_read(email_id, service):

    service.users().messages().modify(userId='me', id=email_id, body={'removeLabelIds': ['UNREAD']}).execute()


def mark_email_as_unread(email_id, service):

    service.users().messages().modify(userId='me', id=email_id, body={'addLabelIds': ['UNREAD']}).execute()


def move_email_to_folder(email_id, folder, service):

    label = service.users().labels().list(userId='me').execute()
    label_id = None
    for lbl in label['labels']:
        if lbl['name'] == folder:
            label_id = lbl['id']
            break

    if label_id is None:
        print(f"Label '{folder}' not found.")
        return


    try:
        service.users().messages().modify(
            userId='me',
            id=email_id,
            body={'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}
        ).execute()
        print(f"Email moved to '{folder}' successfully.")
    except Exception as e:
        print(f"Error moving email: {str(e)}")


def process_emails(service):

    with open(RULES_FILE) as file:
        rules = json.load(file)

    emails = fetch_emails(service)

    for email in emails:
        for rule in rules:
            conditions = rule['conditions']
            actions = rule['actions']
            predicate = rule['predicate']

            if predicate == 'All' and all(check_condition(email, condition) for condition in conditions):
                perform_actions(email, actions, service)
                break
            elif predicate == 'Any' and any(check_condition(email, condition) for condition in conditions):
                perform_actions(email, actions, service)
                break


def check_condition(email, condition):

    field = condition['field']
    predicate = condition['predicate']
    value = condition['value']

    if field == 'From':
        field_value = get_header_value(email, 'From')
    elif field == 'Subject':
        field_value = get_header_value(email, 'Subject')
    elif field == 'Message':
        field_value = get_message_body(email)
    elif field == 'Received Date/Time':
        field_value = get_header_value(email, 'Date')
    else:
        return False


    if predicate == 'Contains':
        return value in field_value
    elif predicate == 'Does not contain':
        return value not in field_value
    elif predicate == 'Equals':
        return value == field_value
    elif predicate == 'Does not equal':
        return value != field_value
    elif predicate == 'Less than':
        try:
            value = int(value)
            field_value_date = datetime.datetime.strptime(field_value, "%Y-%m-%d %H:%M:%S")
            return field_value_date < datetime.datetime.now() - datetime.timedelta(days=value)
        except ValueError:
            return False
    elif predicate == 'Greater than':
        try:
            value = int(value)
            field_value_date = datetime.datetime.strptime(field_value, "%Y-%m-%d %H:%M:%S")
            return field_value_date > datetime.datetime.now() + datetime.timedelta(days=value)
        except ValueError:
            return False
    else:
        return False


def perform_actions(email, actions, service):

    for action in actions:
        if action == 'Mark as read':
            mark_email_as_read(email['id'], service)
        elif action == 'Mark as unread':
            mark_email_as_unread(email['id'], service)
        elif action.startswith('Move Message'):
            folder = action.split(': ')[-1]
            move_email_to_folder(email['id'], folder, service)



if __name__ == '__main__':

    creds = authenticate()


    service = build('gmail', 'v1', credentials=creds)


    emails = fetch_emails(service)


    store_emails(emails, service)


    process_emails(service)


