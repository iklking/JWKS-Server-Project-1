#Kaylyn King
#CSCE 3550
#kaylynking@my.unt.edu
#3/2/24
#Project 1
from flask import Flask, jsonify, request
import jwt, base64, secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

#Array to hold keys
keyArray = {}

#generate a rsa key pair
def generate_rsa_key_pair(expiry_duration=1800): #set expiration to 30 min
        #create a random kid
        kid = secrets.token_hex(16)

        #generate a private key via rsa import
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        #assign details (private and public key, expiration) to key pair
        keyArray[kid] = {
                            'private_key': private_key, 
                            'public_key': private_key.public_key(), 
                            'expiry': datetime.utcnow() + timedelta(seconds=expiry_duration)}
        return kid


#encode the 'n', 'e' public key components in base64url for JWK response format
def encode_key_value(key):
    return base64.urlsafe_b64encode(key.to_bytes((key.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")

#create and return JWKS response
@app.route('/.well-known/jwks.json' , methods=['GET'])
def jwks():
        #create JWK for valid keys
        jwk = [{
                    'kty': 'RSA', 
                    'alg': 'RS256',
                    'kid': kid, 
                    'use': 'sig',
                    'n': encode_key_value(keyArray[kid]['public_key'].public_numbers().n),
                    'e': encode_key_value(keyArray[kid]['public_key'].public_numbers().e),
                
                #filter for valid keys
                } for kid in keyArray if keyArray[kid]['expiry'] > datetime.utcnow()]
        
        return jsonify({'keys': jwk})

#filters through keyArray and returns key based on given 'expired' condition 
def get_selected_kid(expired):
        #return first non-expired or expired key depending if expired is set to 'false' or 'true' respectively
        return next((
                        #iterate through keyArray
                        kid for kid in keyArray 

                        #check for not expired keys with expiration = 'false'
                        if (not expired and keyArray[kid]['expiry'] > datetime.utcnow()) 

                        #check for expired keys with expiration = 'true'
                        or (expired and keyArray[kid]['expiry'] < datetime.utcnow())),

                        #return none if keys not found
                        None)

#issues JWTs
@app.route('/auth', methods=['POST'])
def auth():
        #determines if request is for expired keys
        expired = 'expired' in request.args

        #find the key if present in keyArray based on conditions otherwise generate key based on conditions
        temp = get_selected_kid(expired) or generate_rsa_key_pair(-1800 if expired else 1800)

        #create JWT payload with issuance time and expiration time based on conditions
        payload = {
                    'iat': datetime.utcnow(), 
                    'exp': datetime.utcnow() + timedelta(seconds=1800 if not expired else -1800)}
        
        #create JWT with key pair
        token = jwt.encode(payload, 
                           keyArray[temp]['private_key'], 
                           algorithm='RS256', 
                           headers={'kid': temp})
        
        return jsonify({'token':token})

#generate key and run app
if __name__ == '__main__':
        generate_rsa_key_pair()
        app.run(port=8080, debug=True)

