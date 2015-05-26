# Orthros Messenger API
This is the backend to the Orthros messenger, it handles everything from public key management to the messaging queue. This all happens over GET and POST requests.

*Note from author; This PHP code may not be the best, but it does work. Much of this may be very hacky and inefficient, but overtime I do hope to improve the code greatly for a solid product. At the moment it's really my first project that relies on a PHP backend so I'm still learning. This documentation will also be greatly expanded overtime as well.*

The public API can be requested at ```https://api.orthros.ninja```. If you wish to use this backend privately, you will need to generate your own RSA keys for server side encryption as well as creating a secure key for AES crypto. The AES IV (initialization vector) can be generated randomly, but at the moment it is statically stored in the ```config.ini```, this can be randomly generated per-message but would need to be stored with the associated message in a secure way, this is currently considered a TODO task.

## Security Features
### One-time use key
Using the *gen_key* function will return a key with a length of 20, this will be used and required by functions that handle user-specific and possibly sensitive information. A copy is encrypted with the users public key, another with the servers public key. Both of these are decrypted and checked against each other to ensure the users identity.

### Server side message encryption
The AES crypto system is used to encrypt the message data for storage on the server, this isn't necessarily needed but adds an extra quick layer of security to sensitive data such as who sent the target message. The key and IV are static at the moment, the IV can (and should?) be dynamic but would require the IV to be stored somewhere on the server and per message which makes it a bit convoluted.

## Functions
To call a function you will need to pass the GET parameter "action" which will specify what function is to be ran **this is a required parameter**, the UUID  parameter must be a valid UUID for the action to be executed **this parameter is also required**.

An example;
```
https://api.orthros.ninja/?action=check&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165
```

All functions will return the same basic formatted response, returned "error" 0 is a successful execution, 1 is unsuccessful (check result for error description);
```json
{
    "result": "some good or bad result",
    "called": "some_action_name",
    "error": 0
}
```

### check
Check if public key exists for provided UUID.

**Required GET params; action, UUID.**
```
https://api.orthros.ninja/?action=check&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165
```
### download
Download public key for receiver.

**Required GET params; action, UUID, receiver**
```
https://api.orthros.ninja/?action=download&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165&receiver=17cc8f0b-ca3c-4801-87c3-80cbc1989b0f
```
### upload
Upload public key for UUID, requires the one-time usage key.

**Required GET params; action, UUID**

**Required POST params; pub, key**
```
https://api.orthros.ninja/?action=upload&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165
```
POST "pub" package
```json
{
  "pub":"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0\nFPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/\n3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB\n-----END PUBLIC KEY-----"
}
```
### send
Send message to receiving UUID, requires generation of a one-time use key.

**Required GET params; action, UUID, receiver**

**Required POST params; msg, key**
```
https://api.orthros.ninja/?action=send&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165&reciever=ac5a421c-0891-4d3e-922c-f3c838d7dceb
```
POST "msg" package
```json
msg = {
    "msg": "KdJDWi286llL8AC7nsYi7qlocVQzykYen9zZKCRzAwvfjLn0 AROJQDd9WTAk6qLwP4lQGLxTXx106IH72EBu7Ajqj bFLZnuciP4tflF4c1tsdQ57MPiEWBWLmxfX/J 2MybljJ O99Idd3FPlwVEoBln1iiKuSgJjZxa2xjKI=",
    "sender": "17cc8f0b-ca3c-4801-87c3-80cbc1989b0f"
},
key = some_long_key
```
### list
List messages in que for UUID to be decrypted with the users private key.

**Required GET params; action, UUID**
```
https://api.orthros.ninja/?action=list&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165
```
### get
Get (encrypted) message in que for message ID.

**Required GET params; action, UUID, msg_id**
```
https://api.orthros.ninja/?action=get&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165&msg_id=1432537385
```
### delete_msg
Delete message in que for message ID, requires generation of a one-time use key.

**Required GET params; action, UUID, msg_id**

**Required POST params; key**
```
https://api.orthros.ninja/?action=delete_msg&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165&msg_id=1432537385
```
### gen_key
Generate a one-time use key.

**Required GET params; action, UUID**

```
https://api.orthros.ninja/?action=gen_key&UUID=EE93B33A-A4AB-428C-ACF7-5081716D4165
```
