from flask import Flask, jsonify, request
from OpenSSL import crypto
from endesive import pdf
import boto3
import os
import requests
from datetime import datetime

s3 = boto3.client('s3')
bucket_name = "cyclic-cute-school-uniform-boa-us-east-1"

app = Flask(__name__)

folder = '/tmp'

def set_current_date_time():
    current_datetime = datetime.now()
    current_date_time = current_datetime.strftime("%Y%m%d_%H%M%S")
    return current_date_time

def download_file(url, local_path):
    response = requests.get(url)
    with open(local_path, 'wb') as file:
        file.write(response.content)

def load_certificate_and_key(pfx_path, password):
    with open(pfx_path, "rb") as f:
        pfx_data = f.read()
    pfx = crypto.load_pkcs12(pfx_data, password)
    certificate = pfx.get_certificate()
    private_key = pfx.get_privatekey()
    return certificate, private_key

def sign_pdf(input_pdf_path, output_pdf_path, private_key, certificate):
    dct = {
        "aligned": 0,
        "sigflagsft": 1,
        "sigpage": 0,
        "sigbutton": True,
        "sigfield": "Signature1",
        "auto_sigfield": True,
        "sigandcertify": True,
        "contact": "email@example.com",
        "location": "Localização",
        "signingdate": "2020.02.20",
        "reason": "Razão da assinatura",
        "password": "1234",
    }
    datau = open(input_pdf_path, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
                         private_key.to_cryptography_key(),
                         certificate.to_cryptography(),
                         [],
                         "sha256"
                         )
    with open(output_pdf_path, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)

@app.route('/sign', methods=['POST'])
def sign_pdf_endpoint():
    try:
        data = request.get_json()
        pfx_file_url = data.get('pfx_file_url')
        pfx_password = data.get('pfx_password')
        pdf_url = data.get('pdf_url')

        current_date_time = set_current_date_time()
        local_pdf_file = f'/tmp/pdf_{current_date_time}.pdf'
        pfx_path = f'/tmp/pfx_{current_date_time}.pfx'

        os.makedirs(folder, exist_ok=True)

        download_file(pfx_file_url, pfx_path)
        download_file(pdf_url, local_pdf_file)
        certificate, private_key = load_certificate_and_key(pfx_path, pfx_password)

        sign_pdf(local_pdf_file, local_pdf_file, private_key, certificate)

        with open(local_pdf_file, 'rb') as f:
            s3.put_object(Body=f.read(), Bucket=bucket_name, Key=local_pdf_file)

        url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': bucket_name,
                'Key': local_pdf_file
            }
        )

        return jsonify({'message': 'PDF signed successfully!', 'url': url}), 200
    except Exception as e:
        app.logger.error(f'Error: {e}')
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=True)
