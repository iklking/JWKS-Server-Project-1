#Kaylyn King
#kaylynking@my.unt.edu
#CSCE 3550
#3/2/24
#Test Suite
import unittest
from Project1 import app, keyArray, generate_rsa_key_pair

class JWKSAppTestCase(unittest.TestCase):

    #start up test suite
    def setUp(self):
        app.config['TESTING'] = True
        self.app = app.test_client()

    #test the generating_rsa_key_pair function
    def test_generate_rsa_key_pair(self):
        #generate key pair
        kid = generate_rsa_key_pair()

        #ensures kid is not none
        self.assertIsNotNone(kid)

        #makes sure kid is in keyArray
        self.assertIn(kid, keyArray)

        #get key_info
        key_info = keyArray[kid]

        #makes sure there is info in each parameter
        self.assertIn('private_key', key_info)
        self.assertIn('public_key', key_info)
        self.assertIn('expiry', key_info)

    #test if jwks works
    def test_jwks(self):
        #check if there is a response from jwks
        response = self.app.get('/.well-known/jwks.json')

        #make sure the response code is 200
        self.assertEqual(response.status_code, 200)

    #test if auth works
    def test_auth(self):
        #check if JWTs exist
        response = self.app.post('/auth')

        #make sure response code is 200
        self.assertEqual(response.status_code, 200)

    def test_expired_key(self):
        #generate key pair
        kid = generate_rsa_key_pair()

        #set keys to expired
        expiry = keyArray[kid]['expiry']

        #sets query parameter to 1 hour before expiration
        expired_time = int(expiry.timestamp()) - 3600 
        response = self.app.post(f'/auth?expired={expired_time}')

        #make sure the response code is 200
        self.assertEqual(response.status_code, 200)

#run test suite
if __name__ == '__main__':
    unittest.main()