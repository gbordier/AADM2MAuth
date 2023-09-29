
from flask import Flask, jsonify, request

import json 
from azure_ad_verify_token import verify_jwt


# To run this example, follow the instructions in the project README

## the azure_ad_verify_token module does the key fetching and token validation

# those can be retrieved from https://login.microsoftonline.com/common/discovery/keys
## the "kid"  field from the JWT header must match the "kid" field from the jwks
## sample keys below are from https://login.microsoftonline.com/common/discovery/keys
jwks = {
    "keys":  [
                 {
                     "kty":  "RSA",
                     "use":  "sig",
                     "kid":  "-KI3Q9nNR7bRofxmeZoXqbHZGew",
                     "x5t":  "-KI3Q9nNR7bRofxmeZoXqbHZGew",
                     "n":  "tJL6Wr2JUsxLyNezPQh1J6zn6wSoDAhgRYSDkaMuEHy75VikiB8wg25WuR96gdMpookdlRvh7SnRvtjQN9b5m4zJCMpSRcJ5DuXl4mcd7Cg3Zp1C5-JmMq8J7m7OS9HpUQbA1yhtCHqP7XA4UnQI28J-TnGiAa3viPLlq0663Cq6hQw7jYo5yNjdJcV5-FS-xNV7UHR4zAMRruMUHxte1IZJzbJmxjKoEjJwDTtcd6DkI3yrkmYt8GdQmu0YBHTJSZiz-M10CY3LbvLzf-tbBNKQ_gfnGGKF7MvRCmPA_YF_APynrIG7p4vPDRXhpG3_CIt317NyvGoIwiv0At83kQ",
                     "e":  "AQAB",
                     "x5c":  "MIIDBTCCAe2gAwIBAgIQGQ6YG6NleJxJGDRAwAd/ZTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIyMTAwMjE4MDY0OVoXDTI3MTAwMjE4MDY0OVowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALSS+lq9iVLMS8jXsz0IdSes5+sEqAwIYEWEg5GjLhB8u+VYpIgfMINuVrkfeoHTKaKJHZUb4e0p0b7Y0DfW+ZuMyQjKUkXCeQ7l5eJnHewoN2adQufiZjKvCe5uzkvR6VEGwNcobQh6j+1wOFJ0CNvCfk5xogGt74jy5atOutwquoUMO42KOcjY3SXFefhUvsTVe1B0eMwDEa7jFB8bXtSGSc2yZsYyqBIycA07XHeg5CN8q5JmLfBnUJrtGAR0yUmYs/jNdAmNy27y83/rWwTSkP4H5xhihezL0QpjwP2BfwD8p6yBu6eLzw0V4aRt/wiLd9ezcrxqCMIr9ALfN5ECAwEAAaMhMB8wHQYDVR0OBBYEFJcSH+6Eaqucndn9DDu7Pym7OA8rMA0GCSqGSIb3DQEBCwUAA4IBAQADKkY0PIyslgWGmRDKpp/5PqzzM9+TNDhXzk6pw8aESWoLPJo90RgTJVf8uIj3YSic89m4ftZdmGFXwHcFC91aFe3PiDgCiteDkeH8KrrpZSve1pcM4SNjxwwmIKlJdrbcaJfWRsSoGFjzbFgOecISiVaJ9ZWpb89/+BeAz1Zpmu8DSyY22dG/K6ZDx5qNFg8pehdOUYY24oMamd4J2u2lUgkCKGBZMQgBZFwk+q7H86B/byGuTDEizLjGPTY/sMms1FAX55xBydxrADAer/pKrOF1v7Dq9C1Z9QVcm5D9G4DcenyWUdMyK43NXbVQLPxLOng51KO9icp2j4U7pwHP"
                 },
                 {
                     "kty":  "RSA",
                     "use":  "sig",
                     "kid":  "lHLIu4moKqzPcokwlfCRPHyjl5g",
                     "x5t":  "lHLIu4moKqzPcokwlfCRPHyjl5g",
                     "n":  "xlc-u9LJvOdbwAsgsYZpaJrgmrGHaEkoa_3_7Jvu4-Hb8LNtszrQy5Ik4CXgQ_uiLPt4-ePprX3klFAx91ahfd5LwX6mEQPT8WuHMDunx8MaNQrYNVvnOI1L5NxFBFV_6ghi_0d-cOslErcTMML2lbMCSjQ8jwltxz1Oy-Hd9wdY2pz2YC3WR4tHzAGreWGeOB2Vs2NLGv0U3CGSCMqpM9vxbWLZQPuCNpKF93RkxHj5bLng9U_rM6YScacEnTFlKIOOrk4pcVVdoSNNIK2uNUs1hHS1mBXuQjfceghzj3QQYHfp1Z5qWXPRIw3PDyn_1Sowe5UljLurkpj_8m3KnQ",
                     "e":  "AQAB",
                     "x5c":  "MIIC6TCCAdGgAwIBAgIIT3fcexMa3ggwDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAxMYbG9naW4ubWljcm9zb2Z0b25saW5lLnVzMB4XDTIzMDcxNDAwNDU0NFoXDTI4MDcxNDAwNDU0NFowIzEhMB8GA1UEAxMYbG9naW4ubWljcm9zb2Z0b25saW5lLnVzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxlc+u9LJvOdbwAsgsYZpaJrgmrGHaEkoa/3/7Jvu4+Hb8LNtszrQy5Ik4CXgQ/uiLPt4+ePprX3klFAx91ahfd5LwX6mEQPT8WuHMDunx8MaNQrYNVvnOI1L5NxFBFV/6ghi/0d+cOslErcTMML2lbMCSjQ8jwltxz1Oy+Hd9wdY2pz2YC3WR4tHzAGreWGeOB2Vs2NLGv0U3CGSCMqpM9vxbWLZQPuCNpKF93RkxHj5bLng9U/rM6YScacEnTFlKIOOrk4pcVVdoSNNIK2uNUs1hHS1mBXuQjfceghzj3QQYHfp1Z5qWXPRIw3PDyn/1Sowe5UljLurkpj/8m3KnQIDAQABoyEwHzAdBgNVHQ4EFgQUCSJrrznFYz1BLqd17S8HFjGrAOAwDQYJKoZIhvcNAQELBQADggEBAAQHNudtmYpeh9x5+rGDVy6OYpTnQ2D5+rmgOHM5yRvgEnFBNuZ6bnr3Ap9nb6EM08juYKPaVyhkV+5axMl+dT8KOuCgrfcKvXqzdQ3BgVFkyU9XfajHzq3JALYpNkixCs/BvqRhXx2ecYxFHB2D671cOwhYIaMZdGtbmOOk8puYSgJ9DBqqn3pLksHmxLP656l/U3hPATTCdfDaNcTagIPx+Q2d9RBn8zOIa/p4CLsu3E0aJfDw3ljPD8inLJ2mpKq06TBfd5Rr/auwipb4J8Y/PHhef8b2kOf42fikIKAP538k9lLsXSowyPWn7KZDTEsku7xpyqvKvEiFkmaV+RY="
                 }
             ]
}

# configuration, these can be seen in valid JWTs from Azure B2C:

class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)


def validate_jwt_token(token):

    azure_ad_jwks_uri='https://login.microsoftonline.com/'+TENANT_ID +'/discovery/keys?appid='+ CLIENT_ID
    
    payload = verify_jwt(
        token=token,
        valid_audiences=[SERVER_ID],
        issuer=issuer,
        jwks_uri=azure_ad_jwks_uri,
        verify=True,
    )
    
    return payload


app = Flask(__name__)

## load json file   
with open('./config.json') as f:
    config = json.load(f)
    SERVER_ID = config['SERVER_ID']
    TENANT_ID = config['TENANT_ID']
    CLIENT_ID = config['CLIENT_ID']
        


if (SERVER_ID == '' or CLIENT_ID == '' or TENANT_ID == ''): 
    print("Missing configuration")
    exit(1)        

print("SERVER_ID : " + SERVER_ID)
print("CLIENT_ID : " + CLIENT_ID)
print("TENANT_ID : " + TENANT_ID)


valid_audiences = [SERVER_ID] # id of the application prepared previously
issuer  = 'https://sts.windows.net/'+TENANT_ID+ '/'

## end configuration


@app.route('/hello', methods=['GET'])
def helloworld():
    if(request.method == 'GET'):
        if ('Authorization' in request.headers):
            token = request.headers.get('Authorization').split(" ")[1]
            data = {"API": "Hello World"}
        else:
            data = {"API": "Hello World", "status": "no Authentication please provide a Bearer token in the authorization header"}
            return jsonify(data)
        
        if (token):
#            data['auth'] =token
            
            payload=validate_jwt_token(token)
            validtoken = False
#            data['payload'] = payload
            if (payload): validtoken = True
            if (validtoken and 'roles' in payload):
                data['AppRoles'] = payload['roles']
            else:
                validtoken = False
                data['status'] = "invalid token or missing roles"
                
            if (validtoken and ( 'appidacr' not in payload or  payload['appidacr'] != "2")):
                data['status'] = "valid token but need a certificate credential"
                validtoken = False
            if validtoken: data['status']= "valid token [certclaim ]  " + payload['appidacr']

        return jsonify(data)
  
  
#if __name__ == '__main__':
#    app.run(debug=True)
