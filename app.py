# from flask import Flask, request, redirect, session, render_template, url_for, make_response
# from flask_cors import CORS
# from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, saml
# from saml2.config import Config as Saml2Config
# from saml2.client import Saml2Client
# from saml2.saml import NameID
# import logging
# import secrets
# import base64
# import zlib
# import xmltodict
# import json
# from urllib.parse import urlparse, parse_qs, quote
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import serialization
# from lxml import etree

# app = Flask(__name__)
# app.secret_key = secrets.token_hex(16)
# CORS(app)

# logging.basicConfig(level=logging.INFO)

# # Load configuration
# with open('config.json') as config_file:
#     config_data = json.load(config_file)

# # Temporary storage for SAML data
# saml_storage = {
#     'saml_request_id': '',
#     'saml_request': '',
#     'decoded_saml_request': ''
# }

# def saml_client():
#     config = Saml2Config()
#     config.load({
#         'entityid': config_data['entityid'],
#         'service': {
#             'sp': {
#                 'name': 'SAML SP',
#                 'endpoints': {
#                     'assertion_consumer_service': [
#                         (config_data['acs_url'], BINDING_HTTP_POST),
#                     ],
#                     'single_logout_service': [
#                         (config_data['sp_slo_url'], BINDING_HTTP_REDIRECT),
#                         (config_data['sp_slo_url'], BINDING_HTTP_POST),
#                     ],
#                 },
#                 'required_attributes': config_data['required_attributes'],
#                 'optional_attributes': config_data['optional_attributes'],
#                 'authn_requests_signed': config_data['authn_requests_signed'],
#                 'want_assertions_signed': config_data['want_assertions_signed'],
#                 'want_response_signed': config_data['want_response_signed'],
#                 'return_addresses': [
#                     config_data['sp_slo_url'],
#                     config_data['idp_slo_url']
#                 ],
#             },
#         },
#         'metadata': {
#             'local': [config_data['idp_metadata_file']],
#         },
#         'key_file': config_data['key_file'],
#         'cert_file': config_data['cert_file'],
#         'allow_unknown_attributes': config_data['allow_unknown_attributes'],
#         'debug': config_data['debug'],
#     })
#     return Saml2Client(config)


# def pretty_print_xml(xml_string):
#     try:
#         xml_dict = xmltodict.parse(xml_string)
#         return xmltodict.unparse(xml_dict, pretty=True)
#     except Exception as e:
#         logging.error(f"Error parsing XML: {e}")
#         return xml_string

# def sign_logout_request(logout_request, key_file):
#     with open(key_file, 'rb') as key_file_data:
#         private_key = serialization.load_pem_private_key(
#             key_file_data.read(),
#             password=None
#         )

#     # Parse the XML
#     root = etree.fromstring(logout_request.encode('utf-8'))

#     # Generate a digest of the entire XML string
#     digest = hashes.Hash(hashes.SHA1())
#     digest.update(logout_request.encode('utf-8'))
#     digest_value = digest.finalize()

#     # Sign the digest
#     signature = private_key.sign(
#         digest_value,
#         padding.PKCS1v15(),
#         hashes.SHA1()
#     )

#     # Create the Signature element
#     signature_value = base64.b64encode(signature).decode('utf-8')
#     signature_element = etree.Element('{http://www.w3.org/2000/09/xmldsig#}SignatureValue')
#     signature_element.text = signature_value

#     # Append the Signature element to the XML
#     root.append(signature_element)

#     # Convert the XML back to a string
#     signed_xml_string = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding='UTF-8').decode('utf-8')

#     return signed_xml_string

# @app.route('/')
# def index():
#     saml_request = saml_storage['saml_request']
#     decoded_saml_request = saml_storage['decoded_saml_request']
#     return render_template('index.html', saml_request=saml_request, decoded_saml_request=decoded_saml_request)

# @app.route('/generate_saml_request', methods=['POST'])
# def generate_saml_request():
#     client = saml_client()
#     reqid, info = client.prepare_for_authenticate()
#     location_header = dict(info['headers'])['Location']
#     parsed_url = urlparse(location_header)
#     saml_request = parse_qs(parsed_url.query)['SAMLRequest'][0]

#     # Decode and decompress SAML Request
#     decoded_saml_request = base64.b64decode(saml_request)
#     decompressed_saml_request = zlib.decompress(decoded_saml_request, -15).decode('utf-8')
#     pretty_saml_request = pretty_print_xml(decompressed_saml_request)

#     # Store in temporary storage
#     saml_storage['saml_request_id'] = reqid
#     saml_storage['saml_request'] = saml_request
#     saml_storage['decoded_saml_request'] = pretty_saml_request

#     return redirect('/')

# @app.route('/sso', methods=['POST'])
# def sso():
#     saml_request = request.form['saml_request']
#     encoded_saml_request = quote(saml_request)  # Ensure the SAML request is URL encoded
#     redirect_url = f"{config_data['redirect_url']}?SAMLRequest={encoded_saml_request}"
#     return redirect(redirect_url)

# @app.route('/acs', methods=['POST'])
# def acs():
#     client = saml_client()
#     saml_response = request.form['SAMLResponse']
#     try:
#         outstanding = {saml_storage['saml_request_id']: 'example'}
#         authn_response = client.parse_authn_request_response(
#             saml_response, BINDING_HTTP_POST, outstanding=outstanding
#         )
#         session['user_info'] = authn_response.get_identity()

#         # Extract session_index from AuthnStatement
#         session_index = None
#         for statement in authn_response.assertion.authn_statement:
#             session_index = statement.session_index
#             if session_index:
#                 break

#         if not session_index:
#             raise ValueError("No session index found in AuthnStatement")

#         # Store name_id and session_index as strings
#         session['name_id'] = str(authn_response.name_id)
#         session['session_index'] = session_index

#         # Decode SAML Response
#         decoded_saml_response = base64.b64decode(saml_response).decode('utf-8')
#         pretty_saml_response = pretty_print_xml(decoded_saml_response)

#         logging.info("User successfully logged in")

#         return render_template('response.html', saml_response=saml_response, pretty_saml_response=pretty_saml_response, user_info=session['user_info'])
#     except Exception as e:
#         logging.error(f"Error processing SAML response: {e}")
#         return f"Error processing SAML response: {e}", 500

# @app.route('/logout', methods=['POST'])
# def logout():
#     client = saml_client()
#     session_index = session.get('session_index')
#     name_id_str = session.get('name_id')

#     if 'entityid' not in config_data:
#         logging.error("Missing 'entityid' in configuration data")
#         return redirect(url_for('index'))

#     issuer_entity_id = config_data['entityid']

#     if session_index and name_id_str:
#         logging.info(f"Initiating logout for session_index: {session_index}, name_id: {name_id_str}")
#         try:
#             name_id = NameID(text=name_id_str, format=saml.NAMEID_FORMAT_EMAILADDRESS)

#             # Prepare the logout request
#             logout_request_id, logout_request = client.create_logout_request(
#                 name_id=name_id,
#                 session_indexes=[session_index],
#                 destination=config_data['idp_slo_url'],
#                 issuer_entity_id=issuer_entity_id
#             )

#             logout_request_str = str(logout_request)
#             logging.info(f"Logout request before signing: {logout_request_str}")

#             # Sign the logout request using cryptography
#             signed_logout_request_str = sign_logout_request(logout_request_str, client.config.key_file)
#             logging.info(f"Signed LogoutRequest: {signed_logout_request_str}")

#             # Encode the SAML request (deflate + base64)
#             deflated_logout_request = zlib.compress(signed_logout_request_str.encode('utf-8'))[2:-4]
#             saml_request_encoded = base64.b64encode(deflated_logout_request).decode('utf-8')
#             logging.info(f"Deflated LogoutRequest: {deflated_logout_request}")
#             logging.info(f"Base64 Encoded SAMLRequest: {saml_request_encoded}")

#             # Ensure the SAML request is URL encoded
#             encoded_saml_request = quote(saml_request_encoded)
#             logging.info(f"URL Encoded SAMLRequest: {encoded_saml_request}")

#             # Formulate the logout URL
#             logout_url = f"{config_data['idp_slo_url']}?SAMLRequest={encoded_saml_request}"

#             # Clear the session and SAML storage
#             session.clear()
#             clear_saml_storage()

#             # Clear cookies
#             response = make_response(redirect(logout_url))
#             response.set_cookie('session', '', expires=0)
#             for key in request.cookies.keys():
#                 response.set_cookie(key, '', expires=0)

#             logging.info("User successfully logged out")
#             return response
#         except Exception as e:
#             logging.error(f"Error creating logout request: {e}")
#             logging.error(f"Error details: {e.__class__.__name__}, {str(e)}")
#             return f"Error creating logout request: {e}", 500

#     # In case of missing session data, clear and redirect
#     session.clear()
#     clear_saml_storage()

#     # Clear cookies
#     response = make_response(redirect(url_for('index')))
#     response.set_cookie('session', '', expires=0)
#     for key in request.cookies.keys():
#         response.set_cookie(key, '', expires=0)

#     logging.info("Session and cookies cleared, redirected to index")
#     return response

# @app.route('/slo', methods=['POST'])
# def slo():
#     response = request.form.get('SAMLResponse')
#     if response:
#         try:
#             client = saml_client()
#             logout_response = client.parse_logout_request_response(
#                 response, BINDING_HTTP_POST
#             )
#             if logout_response:
#                 # Clear the session and redirect to index
#                 session.clear()
#                 clear_saml_storage()
#                 logging.info("Single logout successful, session cleared")
#                 return redirect(url_for('index'))
#         except Exception as e:
#             logging.error(f"Error processing SLO response: {e}")
#             return f"Error processing SLO response: {e}", 500

#     logging.error("Invalid SLO response")
#     return "Invalid SLO response", 400

# def clear_saml_storage():
#     saml_storage['saml_request_id'] = ''
#     saml_storage['saml_request'] = ''
#     saml_storage['decoded_saml_request'] = ''

# if __name__ == '__main__':
#     app.run(debug=True)


from flask import Flask, request, redirect, session, render_template, url_for, make_response
from flask_cors import CORS
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, saml
from saml2.config import Config as Saml2Config
from saml2.client import Saml2Client
from saml2.saml import NameID
import logging
import secrets
import base64
import zlib
import xmltodict
import json
from urllib.parse import urlparse, parse_qs, quote
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from lxml import etree

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

logging.basicConfig(level=logging.INFO)

# Load configuration
with open('config.json') as config_file:
    config_data = json.load(config_file)

# Temporary storage for SAML data
saml_storage = {
    'saml_request_id': '',
    'saml_request': '',
    'decoded_saml_request': ''
}

def saml_client():
    config = Saml2Config()
    config.load({
        'entityid': config_data['entityid'],
        'service': {
            'sp': {
                'name': 'SAML SP',
                'endpoints': {
                    'assertion_consumer_service': [
                        (config_data['acs_url'], BINDING_HTTP_POST),
                    ],
                    'single_logout_service': [
                        (config_data['sp_slo_url'], BINDING_HTTP_REDIRECT),
                        (config_data['sp_slo_url'], BINDING_HTTP_POST),
                    ],
                },
                'required_attributes': config_data['required_attributes'],
                'optional_attributes': config_data['optional_attributes'],
                'authn_requests_signed': config_data['authn_requests_signed'],
                'want_assertions_signed': config_data['want_assertions_signed'],
                'want_response_signed': config_data['want_response_signed'],
                'return_addresses': [
                    config_data['sp_slo_url'],
                    config_data['idp_slo_url']
                ],
            },
        },
        'metadata': {
            'local': [config_data['idp_metadata_file']],
        },
        'key_file': config_data['key_file'],
        'cert_file': config_data['cert_file'],
        'allow_unknown_attributes': config_data['allow_unknown_attributes'],
        'debug': config_data['debug'],
    })
    return Saml2Client(config)

def pretty_print_xml(xml_string):
    try:
        xml_dict = xmltodict.parse(xml_string)
        return xmltodict.unparse(xml_dict, pretty=True)
    except Exception as e:
        logging.error(f"Error parsing XML: {e}")
        return xml_string

def sign_logout_request(logout_request, key_file):
    with open(key_file, 'rb') as key_file_data:
        private_key = serialization.load_pem_private_key(key_file_data.read(), password=None)

    # Parse the XML
    root = etree.fromstring(logout_request.encode('utf-8'))

    # Generate a digest of the entire XML string
    digest = hashes.Hash(hashes.SHA1())
    digest.update(logout_request.encode('utf-8'))
    digest_value = digest.finalize()

    # Sign the digest
    signature = private_key.sign(digest_value, padding.PKCS1v15(), hashes.SHA1())

    # Create the Signature element
    signature_value = base64.b64encode(signature).decode('utf-8')
    signature_element = etree.Element('{http://www.w3.org/2000/09/xmldsig#}SignatureValue')
    signature_element.text = signature_value

    # Append the Signature element to the XML
    root.append(signature_element)

    # Convert the XML back to a string
    signed_xml_string = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding='UTF-8').decode('utf-8')

    return signed_xml_string

@app.route('/')
def index():
    saml_request = saml_storage['saml_request']
    decoded_saml_request = saml_storage['decoded_saml_request']
    return render_template('index.html', saml_request=saml_request, decoded_saml_request=decoded_saml_request)

@app.route('/generate_saml_request', methods=['POST'])
def generate_saml_request():
    client = saml_client()
    reqid, info = client.prepare_for_authenticate()
    location_header = dict(info['headers'])['Location']
    parsed_url = urlparse(location_header)
    saml_request = parse_qs(parsed_url.query)['SAMLRequest'][0]

    # Decode and decompress SAML Request
    decoded_saml_request = base64.b64decode(saml_request)
    decompressed_saml_request = zlib.decompress(decoded_saml_request, -15).decode('utf-8')
    pretty_saml_request = pretty_print_xml(decompressed_saml_request)

    # Store in temporary storage
    saml_storage['saml_request_id'] = reqid
    saml_storage['saml_request'] = saml_request
    saml_storage['decoded_saml_request'] = pretty_saml_request

    return redirect('/')

@app.route('/sso', methods=['POST'])
def sso():
    saml_request = request.form['saml_request']
    encoded_saml_request = quote(saml_request)  # Ensure the SAML request is URL encoded
    redirect_url = f"{config_data['redirect_url']}?SAMLRequest={encoded_saml_request}"
    return redirect(redirect_url)

@app.route('/acs', methods=['POST'])
def acs():
    client = saml_client()
    saml_response = request.form['SAMLResponse']
    try:
        outstanding = {saml_storage['saml_request_id']: 'example'}
        authn_response = client.parse_authn_request_response(
            saml_response, BINDING_HTTP_POST, outstanding=outstanding
        )
        session['user_info'] = authn_response.get_identity()

        # Extract session_index from AuthnStatement
        session_index = None
        for statement in authn_response.assertion.authn_statement:
            session_index = statement.session_index
            if session_index:
                break

        if not session_index:
            raise ValueError("No session index found in AuthnStatement")

        # Store name_id and session_index as strings
        session['name_id'] = str(authn_response.name_id)
        session['session_index'] = session_index

        # Decode SAML Response
        decoded_saml_response = base64.b64decode(saml_response).decode('utf-8')
        pretty_saml_response = pretty_print_xml(decoded_saml_response)

        logging.info("User successfully logged in")

        return render_template('response.html', saml_response=saml_response, pretty_saml_response=pretty_saml_response, user_info=session['user_info'])
    except Exception as e:
        logging.error(f"Error processing SAML response: {e}")
        return f"Error processing SAML response: {e}", 500

@app.route('/logout', methods=['POST'])
def logout():
    client = saml_client()
    session_index = session.get('session_index')
    name_id_str = session.get('name_id')

    if not session_index or not name_id_str:
        session.clear()
        clear_saml_storage()
        return redirect(url_for('index'))

    try:
        name_id = NameID(text=name_id_str, format=saml.NAMEID_FORMAT_EMAILADDRESS)

        # Prepare the logout request
        logout_request_id, logout_request = client.create_logout_request(
            name_id=name_id,
            session_indexes=[session_index],
            destination=config_data['idp_slo_url'],
            issuer_entity_id=config_data['entityid']
        )

        # Sign the logout request
        signed_logout_request_str = sign_logout_request(str(logout_request), client.config.key_file)

        # Encode the SAML request (deflate + base64)
        deflated_logout_request = zlib.compress(signed_logout_request_str.encode('utf-8'))[2:-4]
        saml_request_encoded = base64.b64encode(deflated_logout_request).decode('utf-8')

        # Ensure the SAML request is URL encoded
        encoded_saml_request = quote(saml_request_encoded)

        # Formulate the logout URL
        logout_url = f"{config_data['idp_slo_url']}?SAMLRequest={encoded_saml_request}"

        # Clear the session and SAML storage
        session.clear()
        clear_saml_storage()

        # Clear cookies
        response = make_response(redirect(logout_url))
        response.set_cookie('session', '', expires=0)
        for key in request.cookies.keys():
            response.set_cookie(key, '', expires=0)

        logging.info("User successfully logged out")
        return response
    except Exception as e:
        logging.error(f"Error creating logout request: {e}")
        return f"Error creating logout request: {e}", 500

@app.route('/slo', methods=['POST'])
def slo():
    response = request.form.get('SAMLResponse')
    if not response:
        return "Invalid SLO response", 400

    try:
        client = saml_client()
        logout_response = client.parse_logout_request_response(response, BINDING_HTTP_POST)
        if logout_response:
            # Clear the session and redirect to index
            session.clear()
            clear_saml_storage()
            logging.info("Single logout successful, session cleared")
            return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error processing SLO response: {e}")
        return f"Error processing SLO response: {e}", 500

def clear_saml_storage():
    saml_storage['saml_request_id'] = ''
    saml_storage['saml_request'] = ''
    saml_storage['decoded_saml_request'] = ''

if __name__ == '__main__':
    app.run(debug=True)
